package shared

import (
	"sync"
	"time"
)

const (
	ttlFull         = 1 * time.Hour
	ttlPartial      = 15 * time.Minute
	cleanupInterval = 10 * time.Minute
)

// SourceMetadata records the outcome of a single external service call.
type SourceMetadata struct {
	Source      string    `json:"source"`
	Success     bool      `json:"success"`
	Error       *string   `json:"error"`
	RetrievedAt time.Time `json:"retrieved_at"`
}

type cacheEntry struct {
	data   []byte
	expiry time.Time
}

// Cache is an in-memory TTL cache safe for concurrent use.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
}

// NewCache creates a Cache and starts the background cleanup goroutine.
func NewCache() *Cache {
	c := &Cache{
		entries: make(map[string]cacheEntry),
	}
	go c.cleanup()
	return c
}

// Get returns the cached bytes for key if present and unexpired.
func (c *Cache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiry) {
		return nil, false
	}
	return e.data, true
}

// Set stores data under key. TTL is chosen by inspecting sources:
//   - all sources succeeded → 1 hour
//   - any source failed     → 15 minutes
//   - all sources failed    → not cached
func (c *Cache) Set(key string, data []byte, sources []SourceMetadata) {
	ttl := selectTTL(sources)
	if ttl == 0 {
		return
	}
	c.mu.Lock()
	c.entries[key] = cacheEntry{
		data:   data,
		expiry: time.Now().Add(ttl),
	}
	c.mu.Unlock()
}

// Delete removes a single entry from the cache.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	delete(c.entries, key)
	c.mu.Unlock()
}

func selectTTL(sources []SourceMetadata) time.Duration {
	if len(sources) == 0 {
		return ttlFull
	}
	anyFailed := false
	allFailed := true
	for _, s := range sources {
		if s.Success {
			allFailed = false
		} else {
			anyFailed = true
		}
	}
	if allFailed {
		return 0
	}
	if anyFailed {
		return ttlPartial
	}
	return ttlFull
}

func (c *Cache) cleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		c.mu.Lock()
		for key, e := range c.entries {
			if now.After(e.expiry) {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}
