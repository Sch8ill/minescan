package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/sch8ill/minescan/conn"
	"github.com/sch8ill/minescan/metrics"
	"github.com/sch8ill/minescan/proto"
	"github.com/sch8ill/minescan/proto/cookie"
	"github.com/sch8ill/minescan/proto/hello"
	"github.com/sch8ill/minescan/proto/response"
	"github.com/sch8ill/minescan/sender"
	"github.com/sch8ill/minescan/sys"
	"github.com/sch8ill/minescan/target"
)

const interruptDelay = time.Second * 5

func main() {
	if err := cmd().Run(context.Background(), os.Args); err != nil {
		log.Fatal().Err(err).Send()
	}
}

// start configurates, injects dependencies and starts all goroutines.
func start(conf *config) error {
	createLogger(conf)

	targets, err := parseTargets(conf)
	if err != nil {
		return err
	}

	logScanConfig(conf, targets)

	if err := sys.ConfigureFirewall(conf.SrcPort); err != nil {
		return err
	}
	log.Debug().Msg("Firewall configured")

	wg := &sync.WaitGroup{}

	// the response handler is only needed in Minecraft mode
	var responseChan chan *response.Response
	if conf.Proto == proto.Minecraft {
		responseChan = make(chan *response.Response, 1000)
		responseHandler := response.NewMCHandler(responseChan)
		wg.Go(responseHandler.Run)
	}

	srcIP, err := sys.LocalIP()
	if err != nil {
		return err
	}

	etherBuilder := proto.NewEtherBuilder(srcIP, conf.SrcPort, conf.SrcMac, conf.DstMac)
	etherSender, err := sys.NewEtherSender(conf.Iface)
	if err != nil {
		return err
	}

	helloBuilder, err := createHelloBuilder(conf)
	if err != nil {
		return err
	}

	cookieOven := cookie.NewSYNOven()
	packetChan := make(chan []byte, 1000) // TODO: adjust size?
	controlPlane, err := conn.NewControlPlane(conf.SrcPort, conf.Proto, helloBuilder, cookieOven, etherBuilder, packetChan, responseChan)
	if err != nil {
		return err
	}
	wg.Go(controlPlane.Run)

	customSender := sender.NewCustomSender(etherSender, packetChan)
	wg.Go(customSender.Run)

	metrics.M.Start()
	go metrics.M.Reporter()

	sigChan := make(chan os.Signal, 1)
	// the SYN sender will call an OS interrupt once it has finished, leading all goroutines to terminate safely
	synSender, err := sender.NewSYNSender(targets, etherBuilder, etherSender, srcIP, conf.SrcPort, cookieOven, sigChan)
	if err != nil {
		return err
	}
	wg.Go(synSender.Run)

	// block till all goroutines have terminated properly
	terminate(sigChan, wg, synSender, controlPlane)

	if err := sys.RevertFirewall(conf.SrcPort); err != nil {
		return fmt.Errorf("revert firewall changes: %w", err)
	}
	log.Debug().Msg("Firewall changes reverted")

	if conf.ExportMetrics {
		if err := exportMetrics(conf); err != nil {
			return err
		}
	}

	return nil
}

func parseTargets(conf *config) (target.Input, error) {
	excludes, err := target.ReadExcludeFile(conf.ExcludeFile)
	if err != nil {
		log.Warn().Err(err).Msg("read exclude file")
	}
	conf.Exclude = append(conf.Exclude, excludes...)

	if conf.File != "" {
		return target.NewTXTInput(conf.File)
	}

	targets, err := target.NewRangeInput(conf.IPRange, conf.Exclude, conf.Port)
	if err != nil {
		return nil, err
	}

	if targets == nil || targets.Size() == 0 {
		return nil, errors.New("no targets")
	}

	return targets, nil
}

func createHelloBuilder(conf *config) (hello.Builder, error) {
	var helloBuilder hello.Builder
	var err error

	switch conf.Proto {
	case proto.Minecraft:
		helloBuilder, err = hello.NewMCBuilder(conf.MCProto, conf.MCHostname, conf.MCHostport)

	case proto.Http:
		ldapBuilder := hello.NewLDAPBuilder(conf.Log4shellCookieSeed, conf.LdapAddress, conf.LdapPath)
		helloBuilder = hello.NewHTTPBuilder(ldapBuilder, conf.Log4shellHttpHeaders, conf.Log4shellHttpPath, conf.Log4shellHttpBody)
	}

	if err != nil {
		return nil, fmt.Errorf("hello packet: %w", err)
	}
	return helloBuilder, nil
}

// terminate blocks till all goroutines have terminated properly.
func terminate(sigChan chan os.Signal, wg *sync.WaitGroup, synSender *sender.SYNSender, controlPlane *conn.ControlPlane) {
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// might also be called by the SYN sender
	<-sigChan
	synSender.Stop()

	// kill process on second os interrupt
	go func() {
		<-sigChan
		os.Exit(1)
	}()

	log.Info().Msgf("Stopping in %s...", interruptDelay)
	time.Sleep(interruptDelay)

	controlPlane.Stop()
	wg.Wait()
}

func logScanConfig(conf *config, targets target.Input) {
	metrics.M.SetTargets(targets.Size())

	log.Info().Msgf("Scanning %d targets on %d/%s", targets.Size(), conf.Port, conf.Proto.String())
	log.Info().Uint16("port", conf.SrcPort).Msg("Source port")

	// other input types might be unaware of their size
	switch targets := targets.(type) {
	case *target.RangeInput:
		log.Debug().Str("ranges", targets.String()).Send()
	}
}

func exportMetrics(conf *config) error {
	type report struct {
		Config  *config
		Metrics metrics.Bucket
	}

	scanReport := report{
		Config:  conf,
		Metrics: metrics.M.Totals(),
	}

	name := fmt.Sprintf(
		"scan_%s_%d_%s.json",
		conf.Proto.String(),
		conf.Port,
		scanReport.Metrics.Start.Format(time.DateTime),
	)
	log.Info().Msgf("Saving metrics to %s", name)

	f, err := os.Create(name)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "	")
	return encoder.Encode(scanReport)
}
