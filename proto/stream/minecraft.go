package data

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"

	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
)

// Stream stores data packets sent through the connection and assembles them in order.
type Stream interface {
	// Add stores a data packet from the packet stream.
	Add(*layers.TCP) (bool, error)
	// Assemble concatonates all received data packets in order.
	Assemble() []byte
}

// mcStream stores a Minecraft packet send through multiple TCP packets.
type mcStream struct {
	packets      map[uint32][]byte
	expectedSize int
}

// NewMC creates a new stream receiver for storing a minecraft packet.
func NewMC() *mcStream {
	return &mcStream{packets: make(map[uint32][]byte)}
}

// Add accepts data packets and returns true if the Minecraft packet has been received fully.
func (h *mcStream) Add(packet *layers.TCP) (bool, error) {
	if len(h.packets) == 0 {
		var err error
		h.expectedSize, err = expectedSize(packet.Payload)
		if err != nil {
			return false, err
		}

		if h.expectedSize < 0 {
			return false, errors.New("packet size header below zero")
		}
	}

	if _, exists := h.packets[packet.Seq]; !exists {
		h.packets[packet.Seq] = packet.Payload
	}

	log.Trace().Int("current", h.responseSize()).Int("expected", h.expectedSize).Send()

	if h.responseSize() >= h.expectedSize {
		return true, nil
	}

	return false, nil
}

// Assemble concatonates all data packets in order.
func (h *mcStream) Assemble() []byte {
	var seqs []uint32
	for seq := range h.packets {
		seqs = append(seqs, seq)
	}
	slices.Sort(seqs)

	data := make([]byte, 0, h.expectedSize)
	for _, seq := range seqs {
		data = append(data, h.packets[seq]...)
	}

	return data
}

// responseSize calculates the total size of all received packets.
func (h *mcStream) responseSize() int {
	var size int
	for _, chunck := range h.packets {
		size += len(chunck)
	}
	return size
}

// expectedSize retreives the Minecraft packet's size header of the first packet in the stream.
func expectedSize(packet []byte) (int, error) {
	payload := make([]byte, len(packet))
	copy(payload, packet)
	buf := bytes.NewBuffer(payload)

	size, varintSize, err := readVarInt(buf)
	if err != nil {
		return 0, fmt.Errorf("read packet length: %w", err)
	}

	if float64(size) >= math.Pow(2, 32) {
		return 0, fmt.Errorf("packet length exceeds uint32: %d", size)
	}

	// packet payload size + packet length header size
	return int(size) + varintSize, nil
}

// readVarInt reads a varint from a reader and returns it value and size.
func readVarInt(conn io.Reader) (int32, int, error) {
	var num int32
	var shift uint
	var size int
	buf := make([]byte, 1)

	for {
		_, err := conn.Read(buf)
		if err != nil {
			return 0, 0, fmt.Errorf("read varint: %w", err)
		}
		size++

		byteValue := buf[0]
		num |= int32(byteValue&0x7F) << shift

		if (byteValue & 0x80) == 0 {
			break
		}

		shift += 7
		// TODO: 3 byte max for slp res?
		// https://minecraft.wiki/w/Java_Edition_protocol/Server_List_Ping
		if shift >= 32 {
			return 0, 0, errors.New("varint is too long")
		}
	}

	return num, size, nil
}
