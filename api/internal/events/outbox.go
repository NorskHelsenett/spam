package events

import (
	"encoding/json"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	EventJobCreated       = "JOB_CREATED"
	EventJobStatusChanged = "JOB_STATUS_CHANGED"
)

// EmitEvent writes an append-only outbox event within an existing transaction.
func EmitEvent(tx *gorm.DB, eventType, aggregateType, aggregateID string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	event := OutboxEvent{
		ID:            uuid.NewString(),
		EventType:     eventType,
		AggregateType: aggregateType,
		AggregateID:   aggregateID,
		Payload:       data,
	}

	return tx.Create(&event).Error
}

