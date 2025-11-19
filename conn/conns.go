package conn

import (
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/sch8ill/minescan/conn/addr"
	"github.com/sch8ill/minescan/metrics"
	"github.com/sch8ill/minescan/proto"
	"github.com/sch8ill/minescan/proto/stream"
)

const (
	connTimeout        time.Duration = time.Second * 5
	connExpireInterval               = time.Second * 1
)

// conns stores all active connections
type conns struct {
	conns map[string]*conn
	proto proto.Proto
	mu    sync.RWMutex
}

func newConns(proto proto.Proto) *conns {
	return &conns{
		conns: make(map[string]*conn),
		proto: proto,
	}
}

func (c *conns) new(ip net.IP, port uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// no data stream handler for http protocol
	var dataHandler data.Stream
	if c.proto == proto.Minecraft {
		dataHandler = data.NewMC()
	}

	addr := addr.New(ip, port)
	c.conns[addr.String()] = newConn(dataHandler)
}

func (c *conns) state(ip *layers.IPv4, tcp *layers.TCP) (*conn, addr.Addr) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	addr := addr.New(ip.SrcIP, uint16(tcp.SrcPort))
	return c.conns[addr.String()], addr
}

func (c *conns) expireConns() {
	for {
		c.mu.Lock()
		for addr, conn := range c.conns {
			if time.Since(conn.lastActive) > connTimeout {
				// don't use c.remove due to mutex
				delete(c.conns, addr)
				metrics.M.ConnExpired()
			}
		}

		c.mu.Unlock()
		time.Sleep(connExpireInterval)
	}
}

func (c *conns) remove(addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.conns, addr)
}

func (c *conns) openConns() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.conns)
}
