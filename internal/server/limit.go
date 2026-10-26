package server

import (
	"container/list"
	"sync"
	"time"
)

// Bounded is a map of at most max entries, keyed by string, that forgets
// the entry used longest ago when a new one would exceed the bound. The
// server keeps its per-source rate limits in one; the shifter its recent
// consumers and the sources it has answered a Who-Is for. A spoofed flood
// of sources then costs a bounded amount of memory and evicts, at worst,
// the real consumers' entries, which they earn back with their next
// request.
type Bounded[V any] struct {
	mu    sync.Mutex
	max   int
	order *list.List
	items map[string]*list.Element
}

type boundedEntry[V any] struct {
	key   string
	value V
}

// NewBounded makes a map of at most max entries; max below 1 is taken as 1.
func NewBounded[V any](max int) *Bounded[V] {
	return &Bounded[V]{max: max, order: list.New(), items: map[string]*list.Element{}}
}

// Get looks a key up and marks it used.
func (b *Bounded[V]) Get(key string) (V, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.items[key]
	if !ok {
		var zero V
		return zero, false
	}
	b.order.MoveToFront(e)
	return e.Value.(*boundedEntry[V]).value, true
}

// Put sets a key, evicting the entry used longest ago when the map is full.
func (b *Bounded[V]) Put(key string, value V) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e, ok := b.items[key]; ok {
		e.Value.(*boundedEntry[V]).value = value
		b.order.MoveToFront(e)
		return
	}
	for b.order.Len() >= max(1, b.max) {
		last := b.order.Back()
		b.order.Remove(last)
		delete(b.items, last.Value.(*boundedEntry[V]).key)
	}
	b.items[key] = b.order.PushFront(&boundedEntry[V]{key: key, value: value})
}

// Delete forgets a key.
func (b *Bounded[V]) Delete(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e, ok := b.items[key]; ok {
		b.order.Remove(e)
		delete(b.items, key)
	}
}

// Len is the number of entries.
func (b *Bounded[V]) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.order.Len()
}

// Each calls f for every entry, most recently used first, and deletes
// those f returns false for. f must not call back into the map.
func (b *Bounded[V]) Each(f func(key string, value V) (keep bool)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for e := b.order.Front(); e != nil; {
		next := e.Next()
		entry := e.Value.(*boundedEntry[V])
		if !f(entry.key, entry.value) {
			b.order.Remove(e)
			delete(b.items, entry.key)
		}
		e = next
	}
}

// ---- the per-source rate limit ---------------------------------------------

// bucket is one source's token bucket.
type bucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// limiter is a token bucket per source, rate tokens a second with a burst
// of the same, in a Bounded map.
type limiter struct {
	rate    float64
	burst   float64
	sources *Bounded[*bucket]
	now     func() time.Time
}

func newLimiter(rate float64, maxSources int) *limiter {
	return &limiter{rate: rate, burst: max(1, rate), sources: NewBounded[*bucket](maxSources), now: time.Now}
}

// allow takes a token for the source, and reports false when it has none.
// A limiter with no rate allows everything.
func (l *limiter) allow(key string) bool {
	if l == nil || l.rate <= 0 {
		return true
	}
	now := l.now()
	b, ok := l.sources.Get(key)
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.sources.Put(key, b)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
