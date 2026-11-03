package main

import (
	"log"
	"sync"
	"time"

	"github.com/mirage-source/mirage-core/internal/api"
	"github.com/mirage-source/mirage-core/internal/session"
)

// statsProtocols is the refresh order. Loaded one after the other: both
// queries scan the same tables, and running them together slows each.
var statsProtocols = []session.Protocol{session.ProtocolSSH, session.ProtocolTelnet}

type cachedStats struct {
	stats *api.HoneypotStats
	at    time.Time
}

// statsCache holds the last computed HoneypotStats per protocol. The
// aggregates scan the whole corpus and take longer than any request timeout
// once it is large, so they are computed by a background ticker and the
// handler only reads this.
type statsCache struct {
	mu   sync.RWMutex
	data map[session.Protocol]cachedStats
}

func (c *statsCache) get(p session.Protocol) (*api.HoneypotStats, time.Time, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.data[p]
	return e.stats, e.at, ok
}

// refresh reloads every protocol. A failed load is logged and leaves that
// protocol's previous value in place, and does not stop the others.
func (c *statsCache) refresh(load func(session.Protocol) (*api.HoneypotStats, error), now func() time.Time) {
	for _, p := range statsProtocols {
		s, err := load(p)
		if err != nil {
			log.Printf("computing %s stats (keeping the previous value): %v", p, err)
			continue
		}
		c.mu.Lock()
		if c.data == nil {
			c.data = map[session.Protocol]cachedStats{}
		}
		c.data[p] = cachedStats{stats: s, at: now()}
		c.mu.Unlock()
	}
}
