package metrics

import (
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
)

// M holds the global scan metrics.
var M = NewScanMetrics()

// Bucket groups multiple counters in one frame.
type Bucket struct {
	Start    time.Time
	Duration string

	Syn          int
	SynAck       int
	Fin          int
	Rst          int
	AckSend      int
	AckRecv      int
	ResSuccess   int
	ResErr       int
	ConnsExpired int

	// not a counter
	openConns int
}

func (b *Bucket) add(bucket Bucket) {
	b.Syn += bucket.Syn
	b.SynAck += bucket.SynAck
	b.Fin += bucket.Fin
	b.Rst += bucket.Rst
	b.AckSend += bucket.AckSend
	b.AckRecv += bucket.AckRecv
	b.ResSuccess += bucket.ResSuccess
	b.ResErr += bucket.ResErr
	b.ConnsExpired += bucket.ConnsExpired
}

// ScanMetrics represent global metrics of the scan.
type ScanMetrics struct {
	targets int
	current Bucket
	total   *Bucket
}

// NewScanMetrics creates fresh scan metrics.
func NewScanMetrics() *ScanMetrics {
	return &ScanMetrics{
		total: &Bucket{},
	}
}

// Start sets the metrics start time to now.
func (m *ScanMetrics) Start() {
	m.total.Start = time.Now()
}

// SetTargets the total number of targets to be scanned.
func (m *ScanMetrics) SetTargets(targets int) {
	m.targets = targets
}

// Reporter continuously logs the current scan metrics.
func (m *ScanMetrics) Reporter() {
	for {
		log.Info().
			Int("SYN/s", m.current.Syn).
			Int("Found", m.total.SynAck).
			Str("Done", fmt.Sprintf("%.2f%%", float64(m.total.Syn)/float64(m.targets)*100)).
			Int("Conns", m.current.openConns).
			Send()

		log.Debug().
			Int("SYN_RATE", m.current.Syn).
			Int("New_Conns", m.current.SynAck).
			Int("Exp_Conns", m.current.ConnsExpired).
			Int("ACK_RECV", m.current.AckRecv).
			Int("ACK_SEND", m.current.AckSend).
			Int("Res_Success", m.current.ResSuccess).
			Int("Res_Err", m.current.ResErr).
			Int("Found", m.total.SynAck).
			Str("Done", fmt.Sprintf("%.2f%%", float64(m.total.Syn)/float64(m.targets)*100)).
			Int("Conns", m.current.openConns).
			Int("FIN", m.current.Fin).
			Int("RST", m.current.Rst).
			Send()

		m.total.add(m.current)
		m.current = Bucket{}

		time.Sleep(time.Second)
	}
}

func (m *ScanMetrics) SendSYN() {
	m.current.Syn++
}

func (m *ScanMetrics) SynAck() {
	m.current.SynAck++
}

func (m *ScanMetrics) ACKSend() {
	m.current.AckSend++
}

func (m *ScanMetrics) ACKRecv() {
	m.current.AckRecv++
}

func (m *ScanMetrics) FIN() {
	m.current.Fin++
}

func (m *ScanMetrics) RST() {
	m.current.Rst++
}

func (m *ScanMetrics) ResSuccess() {
	m.current.ResSuccess++
}

func (m *ScanMetrics) ResErr() {
	m.current.ResErr++
}

// TODO: not in sync with cleanup job?
func (m *ScanMetrics) ConnExpired() {
	m.current.ConnsExpired++
}

func (m *ScanMetrics) OpenConns(n int) {
	m.current.openConns = n
}

// Totals returns the total scan metrics.
func (m *ScanMetrics) Totals() Bucket {
	totals := *m.total
	totals.Duration = time.Since(m.total.Start).String()
	return totals
}
