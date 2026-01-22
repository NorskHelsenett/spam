package events

import (
	"encoding/json"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	EventJobCreated       = "JOB_CREATED"
	EventJobStatusChanged = "JOB_STATUS_CHANGED"
	EventSBOMBound        = "SBOM_BOUND"
	EventSBOMParsed       = "SBOM_PARSED"
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

func EmitSBOMBound(tx *gorm.DB, sbomID string, payload interface{}) error {
	return EmitEvent(tx, EventSBOMBound, "sbom", sbomID, payload)
}

func EmitSBOMParsed(tx *gorm.DB, sbomID string, payload interface{}) error {
	return EmitEvent(tx, EventSBOMParsed, "sbom", sbomID, payload)
}
