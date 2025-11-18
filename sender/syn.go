package sender

import (
	"fmt"
	"net"
	"os"

	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"

	"github.com/sch8ill/minescan/metrics"
	"github.com/sch8ill/minescan/proto"
	"github.com/sch8ill/minescan/sys"
	"github.com/sch8ill/minescan/proto/cookie"
	"github.com/sch8ill/minescan/target"
)

// SYNSender spews out SYN packets as fast as possible.
type SYNSender struct {
	sigChan chan os.Signal
	stop    bool

	srcPort uint16
	srcIP   net.IP

	targets    target.Input
	builder    proto.EtherBuilder
	sender     sys.EtherSender
	cookieOven cookie.SYNOven
}

// NewSYNSender creates a new sender for SYN packets.
func NewSYNSender(
	targets target.Input,
	builder proto.EtherBuilder,
	sender sys.EtherSender,
	srcIP net.IP,
	srcPort uint16,
	cookieOven cookie.SYNOven,
	sigChan chan os.Signal,
) (*SYNSender, error) {
	return &SYNSender{
		targets:    targets,
		builder:    builder,
		sender:     sender,
		srcIP:      srcIP,
		srcPort:    srcPort,
		cookieOven: cookieOven,
		sigChan:    sigChan,
	}, nil
}

// Run contains the SYN spewing loop.
func (s *SYNSender) Run() {
	defer log.Debug().Msg("SYN sender stopped")

	for {
		if s.stop {
			break
		}

		addr, done := s.targets.Target()
		if err := s.sendSyn(addr.IP, addr.Port); err != nil {
			log.Warn().Err(err).Str("addr", addr.String()).Msg("failed to send syn")
		}
		metrics.M.SendSYN()

		if done {
			// call the os interrupt listener to gently stop all other goroutines
			s.sigChan <- os.Interrupt
			return
		}
	}
}

func (s *SYNSender) sendSyn(dstIP net.IP, dstPort uint16) error {
	tcpLayer := &layers.TCP{
		Seq: s.cookieOven.Create(dstIP, dstPort),
		SYN: true,
	}

	packet, err := s.builder.CreatePacket(dstIP, dstPort, tcpLayer, nil)
	if err != nil {
		return fmt.Errorf("serialize SYN: %w", err)
	}
	return s.sender.Send(packet)
}

// Stop asynchronously stops the SYN sender on it's next loop.
func (s *SYNSender) Stop() {
	s.stop = true
}
