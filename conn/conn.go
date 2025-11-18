package conn

import (
	"time"

	"github.com/sch8ill/minescan/proto/stream"
)

// conn represents an established connection.
type conn struct {
	lastActive time.Time
	stream     data.Stream
}

func newConn(stream data.Stream) *conn {
	return &conn{
		lastActive: time.Now(),
		stream:     stream,
	}
}

func (c *conn) data() data.Stream {
	c.lastActive = time.Now()
	return c.stream
}
