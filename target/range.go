package target

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strings"

	"github.com/sch8ill/minescan/conn/addr"
)

// RangeInput combines an IP range with a port.
type RangeInput struct {
	ranges []*ipRange
	port   uint16
}

// NewRangeInput crates a new IP range input source.
func NewRangeInput(rawRange string, rawExcludes []string, port uint16) (*RangeInput, error) {
	targetRange, err := parseRange(rawRange)
	if err != nil {
		return nil, err
	}

	targetRanges := []*ipRange{targetRange}
	for _, rawExclude := range rawExcludes {
		exclude, err := parseRange(rawExclude)
		if err != nil {
			return nil, err
		}

		var newRanges []*ipRange
		for _, r := range targetRanges {
			excluded := r.exclude(exclude)
			if excluded != nil {
				newRanges = append(newRanges, excluded...)
			}
		}

		targetRanges = newRanges
	}

	return newRangeInput(targetRanges, port), nil
}

func newRangeInput(ranges []*ipRange, port uint16) *RangeInput {
	return &RangeInput{
		ranges: ranges,
		port:   port,
	}
}

// Target calculates the next target in the range list.
func (ri *RangeInput) Target() (addr.Addr, bool) {
	if len(ri.ranges) == 0 {
		return addr.Addr{}, true
	}

	ip, done := ri.ranges[0].next()
	if done {
		ri.ranges = ri.ranges[1:]
		if len(ri.ranges) != 0 {
			done = false
		}
	}

	return addr.Addr{
		IP:   ip,
		Port: ri.port,
	}, done
}

// Size calculates the total size of all target ranges.
func (ri *RangeInput) Size() int {
	var size int
	for _, r := range ri.ranges {
		size += r.size()
	}
	return size
}

// String formats all ranges as a string.
func (ri *RangeInput) String() string {
	var ranges []string
	for _, r := range ri.ranges {
		ranges = append(ranges, r.string())
	}

	return strings.Join(ranges, ", ")
}

// ipRange represents an IP range with the lowest and max value.
type ipRange struct {
	index uint32
	max   uint32
}

func parseRange(rawRange string) (*ipRange, error) {
	var ipRange *ipRange
	var err error

	// CIDR
	if strings.Contains(rawRange, "/") {
		ipRange, err = newCidrRange(rawRange)
	}

	// "-" range
	if strings.Contains(rawRange, "-") {
		parts := strings.Split(rawRange, "-")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid IP range: %s", rawRange)
		}
		ipRange = newRange(net.ParseIP(parts[0]), net.ParseIP(parts[1]))
	}

	// single IP
	if ip := net.ParseIP(rawRange); ip != nil {
		ipRange = newRange(ip, ip)
	}

	return ipRange, err
}

func newRange(start, end net.IP) *ipRange {
	return &ipRange{
		index: ip2int(start),
		max:   ip2int(end),
	}
}

func newCidrRange(cidr string) (*ipRange, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ones, bits := ipNet.Mask.Size()
	size := math.Pow(2, float64(bits-ones))

	return &ipRange{
		index: ip2int(ip),
		max:   ip2int(ip) + uint32(size) - 1, // start ip + size -1 (start included in size)
	}, nil
}

func (r *ipRange) next() (net.IP, bool) {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, r.index)

	r.index++
	if r.index > r.max {
		return ip, true
	}
	return ip, false
}

func (r *ipRange) exclude(exclude *ipRange) []*ipRange {
	// range == exclude
	if exclude.index == r.index && exclude.max == r.max {
		return nil
	}

	// range fully inside exclude
	if r.index <= exclude.max && r.index >= exclude.index &&
		r.max <= exclude.max && r.max >= exclude.index {
		return nil
	}

	// exclude is out of range
	if exclude.index > r.max || exclude.max < r.index {
		return []*ipRange{r}
	}

	// only exclude max is out of range or max is max
	if exclude.max >= r.max {
		r.max = exclude.index - 1
		return []*ipRange{r}
	}

	// only exclude min is out of range or min is min
	if exclude.index <= r.index {
		r.index = exclude.max + 1
		return []*ipRange{r}
	}

	var ranges []*ipRange
	// exclude max is within the range -> split range
	if exclude.max < r.max {
		// range in front of exclude range
		ranges = append(ranges, &ipRange{
			index: r.index,
			max:   exclude.index - 1,
		},
		)
		// second range
		ranges = append(ranges, &ipRange{
			index: exclude.max + 1,
			max:   r.max,
		},
		)
	}

	return ranges
}

func (r *ipRange) size() int {
	return int(r.max - r.index + 1)
}

func (r *ipRange) string() string {
	if r.index == r.max {
		return int2ip(r.index).String()
	}
	return fmt.Sprintf("%s-%s", int2ip(r.index).String(), int2ip(r.max).String())
}

func ip2int(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip.To4())
}

func int2ip(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
