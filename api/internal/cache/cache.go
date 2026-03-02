// Package cache provides a simple caching abstraction.
//
// The Store interface is deliberately minimal so that the in-process Memory
// implementation can be swapped for a Redis backend later without touching
// call sites — just pass a different Store implementation at startup.
//
// Migration path to Redis:
//
//	type RedisStore struct{ client *redis.Client }
//	func (r *RedisStore) Get(ctx, key) ([]byte, bool, error) { ... }
//	func (r *RedisStore) Set(ctx, key, value, ttl) error     { ... }
package cache

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// Store is the caching interface. Both Memory and a future Redis implementation
// satisfy it.
type Store interface {
	Get(ctx context.Context, key string) ([]byte, bool, error)
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
}

// GetJSON retrieves a cached value and unmarshals it into T.
// Returns (zero, false, nil) on cache miss.
func GetJSON[T any](ctx context.Context, s Store, key string) (T, bool, error) {
	var zero T
	raw, ok, err := s.Get(ctx, key)
	if err != nil || !ok {
		return zero, false, err
	}
	var v T
	if err := json.Unmarshal(raw, &v); err != nil {
		return zero, false, err
	}
	return v, true, nil
}

// SetJSON marshals value and stores it with the given TTL.
func SetJSON[T any](ctx context.Context, s Store, key string, value T, ttl time.Duration) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.Set(ctx, key, raw, ttl)
}

// Memory is an in-process TTL cache backed by sync.RWMutex + map.
// A background goroutine is not used; stale entries are evicted lazily on Get.
// For production Redis swap: replace NewMemory() call in main.go with NewRedisStore().
type Memory struct {
	mu    sync.RWMutex
	items map[string]memoryEntry
}

type memoryEntry struct {
	value     []byte
	expiresAt time.Time
}

// NewMemory returns a ready-to-use in-memory cache.
func NewMemory() *Memory {
	return &Memory{items: make(map[string]memoryEntry)}
}

func (m *Memory) Get(_ context.Context, key string) ([]byte, bool, error) {
	m.mu.RLock()
	entry, ok := m.items[key]
	m.mu.RUnlock()
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false, nil
	}
	return entry.value, true, nil
}

func (m *Memory) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	m.mu.Lock()
	m.items[key] = memoryEntry{value: value, expiresAt: time.Now().Add(ttl)}
	m.mu.Unlock()
	return nil
}
