package uiapi

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/NorskHelsenett/spam/internal/cache"
	"github.com/NorskHelsenett/spam/internal/events"
	"github.com/NorskHelsenett/spam/internal/poller"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	"gorm.io/gorm"
)

type SyncStatus string

const (
	SyncStatusRunning SyncStatus = "running"
	SyncStatusDone    SyncStatus = "done"
	SyncStatusFailed  SyncStatus = "failed"
)

type ProviderSyncState struct {
	ProviderID   string             `json:"provider_id"`
	ProviderName string             `json:"provider_name,omitempty"`
	Status       SyncStatus         `json:"status"`
	StartedAt    *time.Time         `json:"started_at,omitempty"`
	FinishedAt   *time.Time         `json:"finished_at,omitempty"`
	Result       *poller.SyncResult `json:"result,omitempty"`
	Error        string             `json:"error,omitempty"`
}

// SyncManager runs provider syncs in the background, deduplicates concurrent
// requests for the same provider, and broadcasts SSE progress events.
type SyncManager struct {
	mu     sync.Mutex
	states map[string]*ProviderSyncState
	db     *gorm.DB
	store  *providerconfig.Store
	cache  cache.Store
}

func NewSyncManager(db *gorm.DB, store *providerconfig.Store, c cache.Store) *SyncManager {
	return &SyncManager{
		states: make(map[string]*ProviderSyncState),
		db:     db,
		store:  store,
		cache:  c,
	}
}

// GetAllStatuses returns a snapshot of all known sync states.
func (m *SyncManager) GetAllStatuses() map[string]ProviderSyncState {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]ProviderSyncState, len(m.states))
	for k, v := range m.states {
		out[k] = *v
	}
	return out
}

// IsRunning returns true if a sync is currently active for providerID.
func (m *SyncManager) IsRunning(providerID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.states[providerID]
	return ok && s.Status == SyncStatusRunning
}

// StartSync starts a background sync for the given provider.
// Returns (true, state) when started, or (false, state) if already running.
func (m *SyncManager) StartSync(providerID string) (bool, ProviderSyncState) {
	m.mu.Lock()
	if s, ok := m.states[providerID]; ok && s.Status == SyncStatusRunning {
		current := *s
		m.mu.Unlock()
		return false, current
	}
	now := time.Now()
	state := &ProviderSyncState{
		ProviderID: providerID,
		Status:     SyncStatusRunning,
		StartedAt:  &now,
	}
	m.states[providerID] = state
	snapshot := *state
	m.mu.Unlock()

	go m.runSync(providerID)
	return true, snapshot
}

func (m *SyncManager) updateState(providerID string, fn func(*ProviderSyncState)) ProviderSyncState {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.states[providerID]; ok {
		fn(s)
		return *s
	}
	return ProviderSyncState{ProviderID: providerID}
}

func (m *SyncManager) emitEvent(event string, state ProviderSyncState) {
	data, err := json.Marshal(state)
	if err != nil {
		log.Printf("sync manager: marshal event %s: %v", event, err)
		return
	}
	events.DispatchStreamEvent(event, data)
}

func (m *SyncManager) runSync(providerID string) {
	ctx := context.Background()

	m.mu.Lock()
	var startState ProviderSyncState
	if s, ok := m.states[providerID]; ok {
		startState = *s
	}
	m.mu.Unlock()
	m.emitEvent(events.StreamEventProviderSyncStarted, startState)

	// Phase 1: discover repos, upsert to DB, queue scan jobs.
	p := poller.New(m.db, m.store)
	result, err := p.SyncProvider(ctx, providerID)
	if err != nil {
		now := time.Now()
		state := m.updateState(providerID, func(s *ProviderSyncState) {
			s.Status = SyncStatusFailed
			s.FinishedAt = &now
			s.Error = err.Error()
		})
		m.emitEvent(events.StreamEventProviderSyncFailed, state)
		return
	}

	state := m.updateState(providerID, func(s *ProviderSyncState) {
		s.Result = result
		s.ProviderName = result.ProviderName
	})
	m.emitEvent(events.StreamEventProviderSyncProgress, state)

	// Phase 2: refresh repo details/contributors cache for all repos.
	var provider providerconfig.ProviderInstance
	if err := m.db.WithContext(ctx).Where("id = ?", providerID).First(&provider).Error; err == nil {
		log.Printf("sync manager: warming cache for %s", provider.DisplayName)
		warmProvider(ctx, m.db, m.store, m.cache, provider, true)
	}

	now := time.Now()
	finalState := m.updateState(providerID, func(s *ProviderSyncState) {
		s.Status = SyncStatusDone
		s.FinishedAt = &now
	})
	m.emitEvent(events.StreamEventProviderSyncCompleted, finalState)
	log.Printf("sync manager: done for provider %s", providerID)
}
