package cookie

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"time"
)

const log4ShellCookieLen int = 20

// Log4ShellOven creates Log4Shell cookies.
type Log4ShellOven int

type Log4ShellCookie struct {
	IP        net.IP
	Port      uint16
	Info      uint16
	Timestamp time.Time
}

// NewLog4ShellOven creates a new Log4Shell cookie oven based on the given seed.
func NewLog4ShellOven(seed int) Log4ShellOven {
	return Log4ShellOven(seed)
}

// Create calculates a Log4Shell cookie and encodes it as a string.
func (o Log4ShellOven) Create(ip net.IP, port uint16, info uint16, timestamp time.Time) string {
	data := make([]byte, 0, log4ShellCookieLen)
	data = append(data, ip.To4()...)                                        // ip (4)
	data = binary.LittleEndian.AppendUint16(data, port)                     // port (2)
	data = binary.LittleEndian.AppendUint16(data, info)                     // info (2)
	data = binary.LittleEndian.AppendUint64(data, uint64(timestamp.Unix())) // timestamp (8)
	data = binary.LittleEndian.AppendUint32(data, o.hash(data))             // checksum of data + seed (4)
	return base64.URLEncoding.EncodeToString(data)
}

// Decode decodes and verfifies a given cookie with the cookie ovens seed.
func (o Log4ShellOven) Decode(rawCookie string) (Log4ShellCookie, error) {
	cookie, err := base64.URLEncoding.DecodeString(rawCookie)
	if err != nil {
		return Log4ShellCookie{}, fmt.Errorf("decode base64: %w", err)
	}

	if len(cookie) != log4ShellCookieLen {
		return Log4ShellCookie{}, fmt.Errorf("invalid log4shell cookie len: %d", len(cookie))
	}

	data := cookie[:16]
	checksum := binary.LittleEndian.Uint32(cookie[16:])
	if o.hash(data) != checksum {
		return Log4ShellCookie{}, errors.New("cookie checksum mismatch")
	}

	return Log4ShellCookie{
		IP:        data[:4],
		Port:      binary.LittleEndian.Uint16(data[4:6]),
		Info:      binary.LittleEndian.Uint16(data[6:8]),
		Timestamp: time.Unix(int64(binary.LittleEndian.Uint64(data[8:16])), 0),
	}, nil
}

func (o Log4ShellOven) hash(data []byte) uint32 {
	saltedData := append(data, binary.LittleEndian.AppendUint64(data, uint64(o))...)
	return crc32.Checksum(saltedData, crc32.IEEETable)
}
