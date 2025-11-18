package response

import (
	"bytes"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/sch8ill/mclib/packet"
	"github.com/sch8ill/mclib/slp"
	"github.com/sch8ill/minescan/conn/addr"
	"github.com/sch8ill/minescan/metrics"
)

// Reponse holds a server's response data, address and timestamp.
type Response struct {
	Addr      addr.Addr
	Data      []byte
	Timestamp time.Time
}

// MCHandler handles responses for Minecraft connections.
type MCHandler struct {
	responses chan *Response
}

// NewMCHandler creates a new handler for minecraft responses.
func NewMCHandler(responses chan *Response) *MCHandler {
	return &MCHandler{
		responses: responses,
	}
}

// Run continuously handles responses from the response channel.
func (h *MCHandler) Run() {
	for {
		res, ok := <-h.responses
		if !ok {
			log.Debug().Msg("Response handler stopped")
			return
		}

		if err := h.handleResponse(res); err != nil {
			metrics.M.ResErr()
		}
		metrics.M.ResSuccess()
	}
}

// handleResponse handles Minecraft responses.
func (h *MCHandler) handleResponse(res *Response) error {
	buf := bytes.NewBuffer(res.Data)
	p, err := packet.NewInboundPacket(buf, time.Millisecond)
	if err != nil {
		return err
	}

	rawSlpRes, err := p.ReadString()
	if err != nil {
		return err
	}

	_, err = slp.NewResponse(rawSlpRes)
	if err != nil {
		return err
	}

	return nil
}
