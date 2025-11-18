package cookie

import (
	"encoding/binary"
	"hash/crc32"
	"math/rand"
	"net"
)

// SYNOven represents a cookie factory based on a certain seed.
type SYNOven int

// NewSYNOven initializes a new SYNOven with a random seed.
func NewSYNOven() SYNOven {
	return SYNOven(rand.Int())
}

// SYN calculates a cookie based on IP, port and seed using the CRC32 hashing algorithm.
func (c SYNOven) Create(ip net.IP, port uint16) uint32 {
	data := make([]byte, 14)                                                  // ip (4 bytes) + port (2 bytes) + seed (8 bytes)
	data = append(data, ip.To4()...)                                          // ip
	data = binary.LittleEndian.AppendUint16(data, port)                       // port
	data = append(data, binary.LittleEndian.AppendUint64(data, uint64(c))...) // seed
	return crc32.Checksum(data, crc32.IEEETable)
}

// Match checks whether a cookie matches IP and port and if it has been signed correctly.
func (c SYNOven) Match(ip net.IP, port uint16, cookie uint32) bool {
	return c.Create(ip, port) == cookie
}
