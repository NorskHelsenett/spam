package events

import (
	"time"

	"gorm.io/datatypes"
)

// OutboxEvent is an append-only event record for downstream processing.
type OutboxEvent struct {
	ID            string         `gorm:"primaryKey;size:36"`
	EventType     string         `gorm:"size:64;index;not null"`
	AggregateType string         `gorm:"size:64;index"`
	AggregateID   string         `gorm:"size:64;index"`
	Payload       datatypes.JSON `gorm:"type:jsonb"`
	CreatedAt     time.Time
}
