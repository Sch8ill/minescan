package target

import "github.com/sch8ill/minescan/conn/addr"

// Input is the target source for the SYN sender.
type Input interface {
	// Target pops a target from the queue.
	// If it's the last target or the queue is empty, false is returned.
	Target() (addr.Addr, bool)
	// Size returns the count of remaining targets.
	Size() int
}
