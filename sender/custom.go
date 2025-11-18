package sender

import (
	"github.com/rs/zerolog/log"

	"github.com/sch8ill/minescan/sys"
)

// CustomSender forwards packets from a given channel to the kernel.
type CustomSender struct {
	sender  sys.EtherSender
	packets chan []byte
}

// NewCustomSender create a new CustomSender for sending custom packets.
func NewCustomSender(sender sys.EtherSender, packets chan []byte) *CustomSender {
	return &CustomSender{
		sender:  sender,
		packets: packets,
	}
}

// Run contains the forwarding loop.
func (s *CustomSender) Run() {
	for {
		packet, ok := <-s.packets
		if !ok {
			log.Debug().Msg("Packet sender stopped")
			return
		}

		if err := s.sender.Send(packet); err != nil {
			log.Warn().Err(err).Msg("send packet")
		}
	}
}
