package events

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"gorm.io/gorm"
)

const NotifyChannel = "spam_events"

type NotifyMessage struct {
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
}

// NotifyEvent publishes a notification payload within the current transaction.
func NotifyEvent(tx *gorm.DB, event string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	msg, err := json.Marshal(NotifyMessage{Event: event, Payload: body})
	if err != nil {
		return err
	}
	return tx.Exec("SELECT pg_notify(?, ?)", NotifyChannel, string(msg)).Error
}

// StartNotificationListener listens for Postgres NOTIFY messages and dispatches them to SSE clients.
func StartNotificationListener(ctx context.Context, dsn string) {
	go listenLoop(ctx, dsn)
}

func listenLoop(ctx context.Context, dsn string) {
	backoff := 2 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}

		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			sleep(ctx, backoff)
			continue
		}

		if _, err := conn.Exec(ctx, "LISTEN "+NotifyChannel); err != nil {
			_ = conn.Close(ctx)
			sleep(ctx, backoff)
			continue
		}

		for {
			if ctx.Err() != nil {
				_ = conn.Close(ctx)
				return
			}
			notification, err := conn.WaitForNotification(ctx)
			if err != nil {
				_ = conn.Close(ctx)
				break
			}

			var msg NotifyMessage
			if err := json.Unmarshal([]byte(notification.Payload), &msg); err != nil {
				continue
			}
			DispatchStreamEvent(msg.Event, msg.Payload)
		}
	}
}

func sleep(ctx context.Context, delay time.Duration) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
		return
	}
}
