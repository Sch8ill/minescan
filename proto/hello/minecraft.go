package hello

import (
	"fmt"
	"net"

	"github.com/sch8ill/mclib"
	"github.com/sch8ill/mclib/packet"
)

// Builder builds the data packets send to the target to trigger a certain reaction.
type Builder interface {
	// Hello creates a hello packet given ip and port.
	Hello(net.IP, uint16) ([]byte, error)
}

// mcBuilder is the pre-build Minecraft packet.
type mcBuilder []byte

// NewMCBuilder creates a new builder for creating Minecraft SLP packets.
func NewMCBuilder(protocol int32, hostname string, hostPort int16) (mcBuilder, error) {
	hello, err := buildMCReq(protocol, hostname, hostPort)
	if err != nil {
		return nil, fmt.Errorf("build MC status request: %w", err)
	}

	return mcBuilder(hello), nil
}

func (m mcBuilder) Hello(ip net.IP, port uint16) ([]byte, error) {
	return m, nil
}

// buildMCReq builds the Minecraft handshake and status request into one packet.
func buildMCReq(protocol int32, hostname string, hostPort int16) ([]byte, error) {
	handshake := packet.NewOutboundPacket(packet.HandshakeID)
	handshake.WriteVarInt(protocol)          // protocol version
	handshake.WriteString(hostname)          // hostname
	handshake.WriteShort(hostPort)           // port
	handshake.WriteVarInt(mclib.StatusState) // next state
	p, err := handshake.Build()
	if err != nil {
		return nil, err
	}

	statusReq := packet.NewOutboundPacket(packet.StatusID)
	req, err := statusReq.Build()
	if err != nil {
		return nil, err
	}

	return append(p, req...), nil
}
