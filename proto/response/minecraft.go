package response

import (
	"bytes"
	"fmt"
	"os"
	"strings"
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

	slpRes, err := slp.NewResponse(rawSlpRes)
	if err != nil {
		return err
	}

	// TODO: rm
	log.Info().Msg(slpRes.Version.Name)
	f, err := os.OpenFile("./servers.csv", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Warn().Err(err).Msg("open mc server file csv")
		return nil
	}

	defer f.Close()

	if _, err := f.WriteString(
		fmt.Sprintf("%s, %d, %s, %d, %d, %d, %d, %s, %t, %t\n",
			res.Addr.IP.String(), res.Addr.Port, slpRes.Version.Name,
			slpRes.Version.Protocol, slpRes.Players.Online, slpRes.Players.Max,
			len(slpRes.Players.Sample), strings.ReplaceAll(slpRes.Description.String(), "\n", " "),
			slpRes.PreviewsChat, slpRes.EnforcesSecureChat,
	)); err != nil {
		log.Warn().Err(err).Msg("write mc server file csv")
	}

	return nil
}
