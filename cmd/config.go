package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	_ "github.com/joho/godotenv/autoload"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/sch8ill/mclib"
	"github.com/urfave/cli-altsrc/v3"
	"github.com/urfave/cli-altsrc/v3/toml"
	"github.com/urfave/cli/v3"

	"github.com/sch8ill/minescan/proto"
)

const (
	mcPort   uint16 = 25565
	httpPort uint16 = 80
)

var configFile = altsrc.StringSourcer("config.toml")

// config holds a configuration.
type config struct {
	IPRange     string
	File        string
	Exclude     []string
	ExcludeFile string
	Port        uint16
	Proto       proto.Proto

	SrcPort        uint16
	SrcMac, DstMac net.HardwareAddr
	Iface          string

	MCProto    int32
	MCHostname string
	MCHostport int16

	Log4shellHttpHeaders []string
	Log4shellHttpPath    bool
	Log4shellHttpBody    bool
	Log4shellCookieSeed  int

	LdapAddress string
	LdapPath    string

	Debug         bool
	ExportMetrics bool
}

// cmd configures the cli wrapper.
func cmd() *cli.Command {
	return &cli.Command{
		Action: func(c_ context.Context, c *cli.Command) error {
			conf, err := parseConfig(c)
			if err != nil {
				return err
			}

			return start(conf)
		},
		Flags: flags(),
	}
}

func flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "range",
			Aliases: []string{"r"},
			Sources: cli.NewValueSourceChain(toml.TOML("scan.range", configFile)),
		},
		&cli.StringFlag{
			Name:    "file",
			Aliases: []string{"f"},
			Sources: cli.NewValueSourceChain(toml.TOML("scan.file", configFile)),
		},
		&cli.StringSliceFlag{
			Name:    "exclude",
			Sources: cli.NewValueSourceChain(toml.TOML("scan.exclude.list", configFile)),
		},
		&cli.StringFlag{
			Name:    "exclude-file",
			Value:   "exclude.conf",
			Sources: cli.NewValueSourceChain(toml.TOML("scan.exclude.file", configFile)),
		},
		&cli.Uint16Flag{
			Name:    "port",
			Aliases: []string{"p"},
			Sources: cli.NewValueSourceChain(toml.TOML("scan.port", configFile)),
		},
		&cli.StringFlag{
			Name:    "proto",
			Value:   "mc",
			Sources: cli.NewValueSourceChain(toml.TOML("scan.protocol", configFile)),
		},
		&cli.Uint16Flag{
			Name:    "src-port",
			Value:   uint16(rand.Uint32()),
			Sources: cli.NewValueSourceChain(toml.TOML("network.src_port", configFile)),
		},
		&cli.StringFlag{
			Name:    "src-mac",
			Sources: cli.NewValueSourceChain(toml.TOML("network.src_mac", configFile)),
		},
		&cli.StringFlag{
			Name:    "dst-mac",
			Sources: cli.NewValueSourceChain(toml.TOML("network.dst_mac", configFile)),
		},
		&cli.StringFlag{
			Name:    "interface",
			Value:   "eth0",
			Sources: cli.NewValueSourceChain(toml.TOML("network.interface", configFile)),
		},
		&cli.Int32Flag{
			Name:    "mc-proto",
			Value:   mclib.DefaultProtocol,
			Sources: cli.NewValueSourceChain(toml.TOML("minecraft.proto", configFile)),
		},
		&cli.StringFlag{
			Name:    "mc-hostname",
			Sources: cli.NewValueSourceChain(toml.TOML("minecraft.hostname", configFile)),
		},
		&cli.Uint16Flag{
			Name:    "mc-hostport",
			Value:   mcPort,
			Sources: cli.NewValueSourceChain(toml.TOML("minecraft.hostport", configFile)),
		},
		&cli.StringSliceFlag{
			Name:    "log4shell-http-headers",
			Value:   []string{"User-Agent"},
			Sources: cli.NewValueSourceChain(toml.TOML("log4shell.http_headers", configFile)),
		},
		&cli.BoolFlag{
			Name:    "log4shell-http-path",
			Sources: cli.NewValueSourceChain(toml.TOML("log4shell.http_path", configFile)),
		},
		&cli.BoolFlag{
			Name:    "log4shell-http-body",
			Sources: cli.NewValueSourceChain(toml.TOML("log4shell.http_body", configFile)),
		},
		&cli.IntFlag{
			Name:    "log4shell-cookie-seed",
			Sources: cli.NewValueSourceChain(toml.TOML("log4shell.cookie_seed", configFile)),
		},
		&cli.StringFlag{
			Name:    "ldap-address",
			Sources: cli.NewValueSourceChain(toml.TOML("ldap.address", configFile)),
		},
		&cli.StringFlag{
			Name:    "ldap-path",
			Sources: cli.NewValueSourceChain(toml.TOML("ldap.path", configFile)),
		},
		&cli.BoolFlag{
			Name:    "debug",
			Value:   false,
			Aliases: []string{"d"},
			Sources: cli.NewValueSourceChain(toml.TOML("debug", configFile)),
		},
		&cli.BoolFlag{
			Name:    "export-metrics",
			Value:   false,
			Sources: cli.NewValueSourceChain(toml.TOML("metrics.export", configFile)),
		},
	}
}

func parseConfig(c *cli.Command) (*config, error) {
	conf := &config{
		IPRange:     c.String("range"),
		File:        c.String("file"),
		Exclude:     c.StringSlice("exclude"),
		ExcludeFile: c.String("exclude-file"),
		Port:        c.Uint16("port"),

		SrcPort: c.Uint16("src-port"),
		Iface:   c.String("interface"),

		MCProto:    c.Int32("mc-proto"),
		MCHostname: c.String("mc-hostname"),
		MCHostport: c.Int16("mc-hostport"),

		Log4shellHttpHeaders: c.StringSlice("log4shell-http-headers"),
		Log4shellHttpPath:    c.Bool("log4shell-http-path"),
		Log4shellHttpBody:    c.Bool("log4shell-http-body"),
		Log4shellCookieSeed:  c.Int("log4shell-cookie-seed"),

		LdapAddress: c.String("ldap-address"),
		LdapPath:    c.String("ldap-path"),

		Debug:         c.Bool("debug"),
		ExportMetrics: c.Bool("export-metrics"),
	}

	var err error
	conf.Proto, err = proto.ParseProto(c.String("proto"))
	if err != nil {
		return nil, err
	}

	conf.SrcMac, err = net.ParseMAC(c.String("src-mac"))
	if err != nil {
		return nil, fmt.Errorf("parse src mac: %w", err)
	}

	conf.DstMac, err = net.ParseMAC(c.String("dst-mac"))
	if err != nil {
		return nil, fmt.Errorf("parse dst mac: %w", err)
	}

	if !c.IsSet("port") {
		switch conf.Proto {
		case proto.Minecraft:
			conf.Port = mcPort

		case proto.Http:
			conf.Port = httpPort
		}

	}

	return conf, nil
}

func createLogger(conf *config) {
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stdout,
		TimeFormat: time.DateTime,
	}

	level := zerolog.InfoLevel
	if conf.Debug {
		level = zerolog.DebugLevel
	}
	log.Logger = log.Output(consoleWriter).Level(level).With().Timestamp().Logger()
}
