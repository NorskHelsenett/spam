package events

import (
	"encoding/json"
	"sync"
	"sync/atomic"
)

const (
	StreamEventProviderSyncStarted   = "provider_sync_started"
	StreamEventProviderSyncProgress  = "provider_sync_progress"
	StreamEventProviderSyncCompleted = "provider_sync_completed"
	StreamEventProviderSyncFailed    = "provider_sync_failed"

	StreamEventNewUser = "new_user"

	StreamEventScamIngest = "scam_ingest"

	StreamEventVulnMetaUpdated = "vuln_meta_updated"
)

type StreamEvent struct {
	Event   string
	Payload json.RawMessage
}

type streamClient struct {
	id      string
	userID  string
	isAdmin bool
	ch      chan StreamEvent
}

var (
	streamSeq uint64
	streamMu  sync.RWMutex
	streams   = make(map[string]map[string]*streamClient)
)

func registerStream(userID string, isAdmin bool) *streamClient {
	clientID := nextStreamID()
	client := &streamClient{
		id:      clientID,
		userID:  userID,
		isAdmin: isAdmin,
		ch:      make(chan StreamEvent, 8),
	}

	streamMu.Lock()
	defer streamMu.Unlock()

	if streams[userID] == nil {
		streams[userID] = make(map[string]*streamClient)
	}
	streams[userID][clientID] = client

	return client
}

func unregisterStream(client *streamClient) {
	if client == nil {
		return
	}

	streamMu.Lock()
	defer streamMu.Unlock()

	if clients, ok := streams[client.userID]; ok {
		delete(clients, client.id)
		if len(clients) == 0 {
			delete(streams, client.userID)
		}
	}
	close(client.ch)
}

// DispatchStreamEvent forwards a notification payload to connected clients.
func DispatchStreamEvent(event string, payload json.RawMessage) {
	if event == "" {
		return
	}
	dispatch(StreamEvent{Event: event, Payload: payload})
}

// adminOnlyEvents is the set of SSE events that are only meaningful
// to admin users — non-admin clients can't trigger or act on them, so
// we skip the fan-out to keep their channel buffers (cap 8) free for
// events they actually care about. Driven by StartSync from the admin
// providers page; non-admins literally have no UI surface for these.
var adminOnlyEvents = map[string]struct{}{
	StreamEventNewUser:               {},
	StreamEventProviderSyncStarted:   {},
	StreamEventProviderSyncProgress:  {},
	StreamEventProviderSyncCompleted: {},
	StreamEventProviderSyncFailed:    {},
}

func dispatch(evt StreamEvent) {
	streamMu.RLock()
	defer streamMu.RUnlock()

	_, adminOnly := adminOnlyEvents[evt.Event]

	for _, clients := range streams {
		for _, client := range clients {
			if adminOnly && !client.isAdmin {
				continue
			}
			select {
			case client.ch <- evt:
			default:
			}
		}
	}
}

func nextStreamID() string {
	seq := atomic.AddUint64(&streamSeq, 1)
	return "stream-" + itoa(seq)
}

func itoa(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for value > 0 {
		i--
		buf[i] = byte('0' + value%10)
		value /= 10
	}
	return string(buf[i:])
}
