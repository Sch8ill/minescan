package target

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/sch8ill/minescan/conn/addr"
)

// TXTInput wraps a target list file as an input source.
type TXTInput struct {
	scanner *bufio.Scanner
	size    int
}

// NewTXTInput creates a new TXTInput from the given file path.
// TODO: implement excludes
func NewTXTInput(path string) (*TXTInput, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	input := &TXTInput{
		scanner: bufio.NewScanner(f),
	}

	input.size, err = countTargets(path)
	if err != nil {
		return nil, err
	}

	return input, nil
}

// Target reads and parses a line from the source file.
func (i *TXTInput) Target() (addr.Addr, bool) {
	if !i.scanner.Scan() {
		return addr.Addr{}, true
	}

	a, err := net.ResolveTCPAddr("tcp", i.scanner.Text())
	if err != nil {
		// TODO
		log.Warn().Err(err).Msg("TXTInput")
		return addr.Addr{}, true
	}

	return addr.Addr{
		IP:   a.IP,
		Port: uint16(a.Port),
	}, false
}

func (i *TXTInput) Size() int {
	return i.size
}

// TODO:
// https://stackoverflow.com/questions/24562942/golang-how-do-i-determine-the-number-of-lines-in-a-file-efficiently
func countTargets(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}

	buf := make([]byte, 32*1024)
	count := 1 // +1 for first line
	lineSep := []byte{'\n'}

	for {
		c, err := f.Read(buf)
		count += bytes.Count(buf[:c], lineSep)

		switch {
		case err == io.EOF:
			return count, nil

		case err != nil:
			return count, err
		}
	}
}
