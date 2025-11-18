package sys

import (
	"fmt"
	"net"
	"syscall"
)

// EtherSender wraps a raw socket and the link layer.
type EtherSender struct {
	sock int
	link *syscall.SockaddrLinklayer
}

// NewEtherSender creates a new wrapper for sending Ethernet frames.
func NewEtherSender(iface string) (EtherSender, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		return EtherSender{}, fmt.Errorf("craete RAW AF_PACKET socket: %w", err)
	}

	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return EtherSender{}, fmt.Errorf("get interface: %w", err)
	}

	link := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  ifi.Index,
	}

	return EtherSender{
		sock: sock,
		link: link,
	}, nil
}

// Send sends an Ethernet frame.
func (s EtherSender) Send(packet []byte) error {
	if err := syscall.Sendto(s.sock, packet, 0, s.link); err != nil {
		return fmt.Errorf("send packet: %w", err)
	}
	return nil
}

// NewRawTCPSock creates a new AF_INET, SOCK_RAW and IPPROTO_TCP socket and returns it's descriptor.
func NewRawTCPSock() (int, error) {
	return syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
}

// Htons converts a uint16 from host- to network byte order.
// from https://github.com/atoonk/go-pktgen/blob/main/pktgen/af_packet.go
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
