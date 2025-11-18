package addr

import (
	"net"
	"strconv"

)

// Addr represent IP and Port.
type Addr struct {
	IP   net.IP
	Port uint16
}

func New(ip net.IP, port uint16) Addr {
	return Addr{
		IP:   ip,
		Port: port,
	}
}

func (a Addr) String() string {
	return net.JoinHostPort(a.IP.String(), strconv.Itoa(int(a.Port)))
}
