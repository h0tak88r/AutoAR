package utils

import (
	"sync"
	"time"
)

// CacheEntry represents a cached value with expiration
type CacheEntry struct {
	Data      interface{}
	ExpiresAt time.Time
}

// Cache is a simple in-memory cache with TTL
type Cache struct {
	mu    sync.RWMutex
	items map[string]CacheEntry
}

// NewCache creates a new cache instance
func NewCache() *Cache {
	c := &Cache{
		items: make(map[string]CacheEntry),
	}
	
	// Start cleanup goroutine
	go c.cleanupExpired()
	
	return c
}

// Set stores a value in the cache with TTL
func (c *Cache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.items[key] = CacheEntry{
		Data:      value,
		ExpiresAt: time.Now().Add(ttl),
	}
}

// Get retrieves a value from the cache
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	entry, exists := c.items[key]
	if !exists {
		return nil, false
	}
	
	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}
	
	return entry.Data, true
}

// Delete removes a value from the cache
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	delete(c.items, key)
}

// Clear removes all items from the cache
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.items = make(map[string]CacheEntry)
}

// cleanupExpired removes expired entries periodically
func (c *Cache) cleanupExpired() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.items {
			if now.After(entry.ExpiresAt) {
				delete(c.items, key)
			}
		}
		c.mu.Unlock()
	}
}

// Global cache instance
var globalCache = NewCache()

// GetCache returns the global cache instance
func GetCache() *Cache {
	return globalCache
}
