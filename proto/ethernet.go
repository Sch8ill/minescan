package proto

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const tcpWindowSize uint16 = 14600

// EtherBuilder constructs Ethernet frames based on its properties.
type EtherBuilder struct {
	srcIP   net.IP
	srcPort uint16

	ethLayer *layers.Ethernet
}

// NewEtherBuilder creates a new Builder for Ethernet frames.
func NewEtherBuilder(srcIP net.IP, srcPort uint16, srcMac, dstMac net.HardwareAddr) EtherBuilder {
	ethLayer := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	return EtherBuilder{
		srcIP:    srcIP,
		srcPort:  srcPort,
		ethLayer: ethLayer,
	}
}

// CreatePacket builds a new Ethernet frame.
func (b EtherBuilder) CreatePacket(dstIP net.IP, dstPort uint16, tcpLayer *layers.TCP, payload []byte) ([]byte, error) {
	ipLayer := b.newIPLayer(dstIP)

	tcpLayer.Window = tcpWindowSize
	tcpLayer.SrcPort = layers.TCPPort(b.srcPort)
	tcpLayer.DstPort = layers.TCPPort(dstPort)
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buffer, opts, b.ethLayer, ipLayer, tcpLayer, gopacket.Payload(payload))
	if err != nil {
		return nil, fmt.Errorf("serialize layers: %w", err)
	}

	return buffer.Bytes(), nil
}

func (b EtherBuilder) newIPLayer(dstIP net.IP) *layers.IPv4 {
	return &layers.IPv4{
		SrcIP:    b.srcIP,
		DstIP:    dstIP,
		Version:  4,  // IPv4
		IHL:      5,  // internet header length / 32
		TTL:      64, // time to live
		Protocol: layers.IPProtocolTCP,
	}
}
