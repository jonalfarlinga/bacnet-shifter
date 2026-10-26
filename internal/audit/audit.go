// Package audit is the shifter's audit log: one JSON object per line,
// appended to a file the shifter never truncates, for everything that
// bears on who did what to the site. The file is opened append-only and
// created with mode 0600, written from one goroutine, and synced after
// each line. A nil *Log records nothing, so the callers need no check.
//
// A consumer is never made to wait for the disk: lines queue through a
// channel of QueueSize, and one the queue could not take is counted and
// reported in the Detail of the next line that is written.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// QueueSize is how many lines may wait for the disk.
const QueueSize = 1024

// Entry is one line. Every field but Time and Event is left out of the
// line when empty.
type Entry struct {
	Time  time.Time `json:"time"`
	Event string    `json:"event"`
	// Peer is the consumer's address; Prefix the consumer.peers entry it
	// matched, if any; Control the level it was served at.
	Peer    string `json:"peer,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
	Control string `json:"control,omitempty"`
	Service string `json:"service,omitempty"`
	// Device is the virtual device instance, Real the real one.
	Device   uint32  `json:"device,omitempty"`
	Real     uint32  `json:"real,omitempty"`
	Object   string  `json:"object,omitempty"`
	Property string  `json:"property,omitempty"`
	Index    *uint32 `json:"index,omitempty"`
	Priority uint8   `json:"priority,omitempty"`
	Outcome  string  `json:"outcome,omitempty"`
	Detail   string  `json:"detail,omitempty"`
}

// Events.
const (
	EventStart     = "start"
	EventWrite     = "write"
	EventRefused   = "refused"
	EventSubscribe = "subscribe"
	EventCancel    = "cancel"
	EventDropped   = "dropped"
)

// Log is an open audit file.
type Log struct {
	f       *os.File
	queue   chan Entry
	done    chan struct{}
	lost    atomic.Uint64
	written atomic.Uint64
	once    sync.Once
}

// Open opens the file append-only, creating it with mode 0600, and starts
// the writer.
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit file: %w", err)
	}
	l := &Log{f: f, queue: make(chan Entry, QueueSize), done: make(chan struct{})}
	go l.run()
	return l, nil
}

// Record queues one line. The time is set here when the entry has none.
// It never blocks: with the queue full the line is lost and counted.
func (l *Log) Record(e Entry) {
	if l == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	select {
	case l.queue <- e:
	default:
		l.lost.Add(1)
	}
}

// run writes the queue to the file until Close.
func (l *Log) run() {
	defer close(l.done)
	for e := range l.queue {
		e.Time = e.Time.UTC()
		if lost := l.lost.Swap(0); lost > 0 {
			detail := fmt.Sprintf("%d lines lost: the queue was full", lost)
			if e.Detail != "" {
				detail = e.Detail + "; " + detail
			}
			e.Detail = detail
		}
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		if _, err := l.f.Write(append(b, '\n')); err != nil {
			l.lost.Add(1)
			continue
		}
		l.f.Sync()
		l.written.Add(1)
	}
}

// Close writes what is queued and closes the file.
func (l *Log) Close() error {
	if l == nil {
		return nil
	}
	l.once.Do(func() { close(l.queue) })
	<-l.done
	return l.f.Close()
}

// Written is how many lines reached the file, Lost how many did not and
// have not yet been reported.
func (l *Log) Written() uint64 {
	if l == nil {
		return 0
	}
	return l.written.Load()
}
