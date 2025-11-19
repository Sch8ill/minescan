package conn

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"

	"github.com/sch8ill/minescan/conn/addr"
	"github.com/sch8ill/minescan/metrics"
	"github.com/sch8ill/minescan/proto"
	"github.com/sch8ill/minescan/proto/cookie"
	"github.com/sch8ill/minescan/proto/hello"
	"github.com/sch8ill/minescan/proto/response"
	"github.com/sch8ill/minescan/sys"
)

// ControlPlane manages all incoming packets and responds if necessary.
type ControlPlane struct {
	stop bool

	recvSock int
	srcPort  uint16
	proto    proto.Proto

	packetChan   chan []byte
	responseChan chan *response.Response

	cookieOven   cookie.SYNOven
	etherBuilder proto.EtherBuilder
	helloBuilder hello.Builder
	conns        *conns
}

// NewControlPlance creates a new ControlPlane.
func NewControlPlane(
	srcPort uint16,
	proto proto.Proto,
	helloBuilder hello.Builder,
	cookieOven cookie.SYNOven,
	etherBuilder proto.EtherBuilder,
	packetChan chan []byte,
	responseChan chan *response.Response,
) (*ControlPlane, error) {
	recvSock, err := sys.NewRawTCPSock()
	if err != nil {
		return nil, err
	}

	return &ControlPlane{
		recvSock:     recvSock,
		srcPort:      srcPort,
		proto:        proto,
		packetChan:   packetChan,
		responseChan: responseChan,
		cookieOven:   cookieOven,
		etherBuilder: etherBuilder,
		helloBuilder: helloBuilder,
		conns:        newConns(proto),
	}, nil
}

// Run contains the receiving loop.
func (p *ControlPlane) Run() {
	go p.conns.expireConns()

	buf := make([]byte, 4096)
	for {
		openConns := p.conns.openConns()
		metrics.M.OpenConns(p.conns.openConns())

		if p.stop {
			if openConns > 0 {
				continue
			}
			p.terminate()
			break
		}

		if err := p.listen(buf); err != nil {
			log.Warn().Err(err).Send()
		}
	}
}

func (p *ControlPlane) listen(buf []byte) error {
	n, _, err := syscall.Recvfrom(p.recvSock, buf, 0)
	if err != nil {
		return fmt.Errorf("receive packet: %v", err)
	}

	packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.Lazy)
	if err := p.handlePacket(packet); err != nil {
		return err
	}

	return nil
}

func (p *ControlPlane) handlePacket(packet gopacket.Packet) error {
	tcpLayer := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if tcpLayer == nil {
		return nil
	}

	if uint16(tcpLayer.DstPort) != p.srcPort {
		return nil
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// new connection
	if tcpLayer.SYN && tcpLayer.ACK {
		metrics.M.SynAck()
		if err := p.handleSYNACK(ip, tcpLayer); err != nil {
			return fmt.Errorf("handle SYN+ACK: %w", err)
		}
		return nil
	}

	// connection termination
	// may occur before a connection has been set up
	if tcpLayer.RST {
		metrics.M.RST()
		if err := p.handleRST(ip, tcpLayer); err != nil {
			return fmt.Errorf("handle RST: %w", err)
		}
		return nil
	}

	conn, _ := p.conns.state(ip, tcpLayer)
	if conn == nil {
		log.Trace().Err(fmt.Errorf("unexpected packet from %s:%d", ip.SrcIP.String(), tcpLayer.SrcPort)).Send()
		return nil
	}

	// abort connection
	if p.proto == proto.Http {
		if err := p.sendRST(ip.SrcIP, uint16(tcpLayer.SrcPort), tcpLayer.Ack); err != nil {
			return fmt.Errorf("send RST: %w", err)
		}
		p.conns.remove(addr.New(ip.SrcIP, uint16(tcpLayer.SrcPort)).String())
		return nil
	}

	// connection termination
	if tcpLayer.FIN {
		metrics.M.FIN()
		if err := p.handleFIN(ip, tcpLayer); err != nil {
			return fmt.Errorf("handle FIN: %w", err)
		}
		return nil
	}

	// data packet
	// PSH flag does not need to be set for packets containing data
	if tcpLayer.PSH || tcpLayer.ACK {
		metrics.M.ACKRecv()
		if err := p.handleDataPacket(ip, tcpLayer); err != nil {
			return fmt.Errorf("handle PSH/ACK: %w", err)
		}
		return nil
	}

	return nil
}

// handleSYNACK handles new connections
func (p *ControlPlane) handleSYNACK(ip *layers.IPv4, tcp *layers.TCP) error {
	log.Trace().Uint32("seq", tcp.Seq).Uint32("ack", tcp.Ack).Msg("SYN ACK received")
	dstPort := uint16(tcp.SrcPort)

	cookie := tcp.Ack - 1
	if !p.cookieOven.Match(ip.SrcIP, dstPort, cookie) {
		log.Debug().IPAddr("ip", ip.SrcIP).Uint16("port", dstPort).Msg("cookie mismatch")
		return nil
	}

	p.conns.new(ip.SrcIP, dstPort)

	tcpLayer := &layers.TCP{
		Seq: tcp.Ack,
		Ack: tcp.Seq + 1,
		ACK: true,
		PSH: true,
	}

	hello, err := p.helloBuilder.Hello(ip.SrcIP, dstPort)
	if err != nil {
		return fmt.Errorf("build hello payload: %w", err)
	}

	packet, err := p.etherBuilder.CreatePacket(ip.SrcIP, uint16(tcp.SrcPort), tcpLayer, hello)
	if err != nil {
		return fmt.Errorf("serialize ACK + PSH (MC handshake): %w", err)
	}
	p.packetChan <- packet

	return nil
}

func (p *ControlPlane) handleDataPacket(ip *layers.IPv4, tcp *layers.TCP) error {
	log.Trace().Uint32("seq", tcp.Seq).Uint32("ack", tcp.Ack).Msg("PSH/ACK received")

	// dont acknowledge empty acks
	if len(tcp.Payload) == 0 {
		return nil
	}

	conn, addr := p.conns.state(ip, tcp)

	done, err := conn.data().Add(tcp)
	if err != nil {
		log.Warn().Err(err).Str("addr", addr.String()).Msg("packet payload")
		p.conns.remove(addr.String())
	}

	if done {
		p.responseChan <- &response.Response{
			Addr:      addr,
			Data:      conn.data().Assemble(),
			Timestamp: time.Now(),
		}
	}

	if err := p.sendAck(
		ip.SrcIP, tcp.SrcPort,
		tcp.Ack, tcp.Seq+uint32(len(tcp.Payload)),
		done,
	); err != nil {
		return fmt.Errorf("acknowledge data packet: %w", err)
	}

	return nil
}

func (p *ControlPlane) handleFIN(ip *layers.IPv4, tcp *layers.TCP) error {
	log.Trace().IPAddr("ip", ip.SrcIP).Msg("FIN")

	_, addr := p.conns.state(ip, tcp)
	p.conns.remove(addr.String())

	if err := p.sendAck(
		ip.SrcIP,
		tcp.SrcPort,
		tcp.Ack, tcp.Seq+1,
		true,
	); err != nil {
		return fmt.Errorf("acknowledge FIN: %w", err)
	}

	return nil
}

func (p *ControlPlane) handleRST(ip *layers.IPv4, tcp *layers.TCP) error {
	conn, addr := p.conns.state(ip, tcp)
	if conn != nil {
		p.conns.remove(addr.String())
	}

	log.Trace().Str("addr", addr.String()).Msg("RST")
	return nil
}

func (p *ControlPlane) sendAck(dstIP net.IP, dstPort layers.TCPPort, seq, ack uint32, fin bool) error {
	tcpLayer := &layers.TCP{
		Seq: seq,
		Ack: ack,
		ACK: true,
		FIN: fin,
	}

	packet, err := p.etherBuilder.CreatePacket(dstIP, uint16(dstPort), tcpLayer, nil)
	if err != nil {
		return fmt.Errorf("serialize ACK for FIN: %w", err)
	}
	p.packetChan <- packet

	metrics.M.ACKSend()
	return nil
}

func (p *ControlPlane) sendRST(dstIP net.IP, dstPort uint16, seq uint32) error {
	tcpLayer := &layers.TCP{
		Seq: seq,
		RST: true,
	}

	packet, err := p.etherBuilder.CreatePacket(dstIP, dstPort, tcpLayer, nil)
	if err != nil {
		return fmt.Errorf("serialize RST: %w", err)
	}
	p.packetChan <- packet

	return nil
}

func (p *ControlPlane) terminate() {
	close(p.packetChan)
	if p.responseChan != nil {
		close(p.responseChan)
	}

	syscall.Close(p.recvSock)
	log.Debug().Msg("Control plane stopped")
}

// Stop asynchronously stops the receiving loop on it's next iteration.
func (p *ControlPlane) Stop() {
	p.stop = true
}
