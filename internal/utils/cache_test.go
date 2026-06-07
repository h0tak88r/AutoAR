package utils

import (
	"testing"
	"time"
)

func TestCacheSetAndGet(t *testing.T) {
	c := NewCache()

	// Get non-existent key
	if val, ok := c.Get("missing"); ok || val != nil {
		t.Errorf("Get(missing) = (%v, %v), want (nil, false)", val, ok)
	}

	// Set and get
	c.Set("key1", "value1", time.Minute)
	val, ok := c.Get("key1")
	if !ok {
		t.Fatal("Get(key1) returned false, want true")
	}
	if val != "value1" {
		t.Errorf("Get(key1) = %q, want %q", val, "value1")
	}
}

func TestCacheExpiration(t *testing.T) {
	c := NewCache()
	c.Set("key1", "value1", 10*time.Millisecond)

	// Should exist immediately
	if _, ok := c.Get("key1"); !ok {
		t.Fatal("Get(key1) should return true before expiry")
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	if _, ok := c.Get("key1"); ok {
		t.Error("Get(key1) should return false after expiry")
	}
}

func TestCacheDelete(t *testing.T) {
	c := NewCache()
	c.Set("key1", "value1", time.Minute)
	c.Delete("key1")

	if _, ok := c.Get("key1"); ok {
		t.Error("Get(key1) should return false after delete")
	}

	// Deleting a non-existent key should not panic
	c.Delete("nonexistent")
}

func TestCacheClear(t *testing.T) {
	c := NewCache()
	c.Set("key1", "value1", time.Minute)
	c.Set("key2", "value2", time.Minute)
	c.Clear()

	if _, ok := c.Get("key1"); ok {
		t.Error("Get(key1) should return false after clear")
	}
	if _, ok := c.Get("key2"); ok {
		t.Error("Get(key2) should return false after clear")
	}
}

func TestCacheConcurrent(t *testing.T) {
	c := NewCache()
	done := make(chan struct{})

	go func() {
		for i := range 100 {
			c.Set("key", i, time.Minute)
		}
		close(done)
	}()

	for range 100 {
		c.Get("key")
	}

	<-done
}

func TestGetCache(t *testing.T) {
	c := GetCache()
	if c == nil {
		t.Fatal("GetCache() returned nil")
	}

	c.Set("test", "value", time.Minute)
	val, ok := c.Get("test")
	if !ok || val != "value" {
		t.Errorf("GetCache().Get(test) = (%v, %v), want (\"value\", true)", val, ok)
	}
	c.Clear()
}
