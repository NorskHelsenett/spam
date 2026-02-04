package uiapi

import (
	"context"
	"encoding/json"
	"time"

	"github.com/NorskHelsenett/spam/internal/runner"
	"gorm.io/gorm"
)

type k8sSnapshot struct {
	Events    []runner.K8sEvent `json:"events,omitempty"`
	PodStatus *runner.PodStatus `json:"pod_status,omitempty"`
	UpdatedAt time.Time         `json:"updated_at"`
}

func persistK8sSnapshot(ctx context.Context, db *gorm.DB, runID string, events []runner.K8sEvent, podStatus *runner.PodStatus) error {
	if len(events) == 0 && podStatus == nil {
		return nil
	}

	resultMap, err := loadRunResultMap(ctx, db, runID)
	if err != nil {
		return err
	}

	snapshot := k8sSnapshot{
		Events:    events,
		PodStatus: podStatus,
		UpdatedAt: time.Now().UTC(),
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}

	resultMap["k8s"] = json.RawMessage(payload)
	return saveRunResultMap(ctx, db, runID, resultMap)
}

func loadPersistedK8sSnapshot(ctx context.Context, db *gorm.DB, runID string) ([]runner.K8sEvent, *runner.PodStatus, bool, error) {
	resultMap, err := loadRunResultMap(ctx, db, runID)
	if err != nil {
		return nil, nil, false, err
	}

	raw, ok := resultMap["k8s"]
	if !ok || len(raw) == 0 {
		return nil, nil, false, nil
	}

	var snapshot k8sSnapshot
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		return nil, nil, false, err
	}

	if len(snapshot.Events) == 0 && snapshot.PodStatus == nil {
		return nil, nil, false, nil
	}

	return snapshot.Events, snapshot.PodStatus, true, nil
}

func loadRunResultMap(ctx context.Context, db *gorm.DB, runID string) (map[string]json.RawMessage, error) {
	var row struct {
		Result json.RawMessage `gorm:"column:result"`
	}

	if err := db.WithContext(ctx).Table("jobs").
		Select("result").
		Where("id = ?", runID).
		Scan(&row).Error; err != nil {
		return nil, err
	}

	if len(row.Result) == 0 {
		return map[string]json.RawMessage{}, nil
	}

	var resultMap map[string]json.RawMessage
	if err := json.Unmarshal(row.Result, &resultMap); err != nil {
		return nil, err
	}

	if resultMap == nil {
		resultMap = map[string]json.RawMessage{}
	}

	return resultMap, nil
}

func saveRunResultMap(ctx context.Context, db *gorm.DB, runID string, resultMap map[string]json.RawMessage) error {
	payload, err := json.Marshal(resultMap)
	if err != nil {
		return err
	}

	return db.WithContext(ctx).
		Table("jobs").
		Where("id = ?", runID).
		Update("result", payload).Error
}
