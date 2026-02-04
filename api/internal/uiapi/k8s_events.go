package uiapi

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/jobs"
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

	return loadPersistedK8sSnapshotFromResult(resultMap)
}

func loadPersistedK8sSnapshotFromResult(resultMap map[string]json.RawMessage) ([]runner.K8sEvent, *runner.PodStatus, bool, error) {
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

	return parseRunResultMap(row.Result)
}

func parseRunResultMap(raw json.RawMessage) (map[string]json.RawMessage, error) {
	if len(raw) == 0 {
		return map[string]json.RawMessage{}, nil
	}

	var resultMap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &resultMap); err != nil {
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

func correctRunStatusFromSnapshot(ctx context.Context, db *gorm.DB, runID string, status string, events []runner.K8sEvent, podStatus *runner.PodStatus) (string, string, bool) {
	if status == string(jobs.JobStatusFailed) {
		return status, "", false
	}

	if failed, message := inferK8sFailure(events, podStatus); failed {
		errorText := message
		if errorText == "" {
			errorText = "k8s runner failed to start"
		}
		now := time.Now()
		if err := db.WithContext(ctx).Table("jobs").
			Where("id = ?", runID).
			Updates(map[string]interface{}{
				"status":      jobs.JobStatusFailed,
				"error":       errorText,
				"finished_at": now,
				"updated_at":  now,
			}).Error; err == nil {
			return string(jobs.JobStatusFailed), errorText, true
		}
		return string(jobs.JobStatusFailed), errorText, false
	}

	return status, "", false
}

func inferK8sFailure(events []runner.K8sEvent, podStatus *runner.PodStatus) (bool, string) {
	if podStatus != nil && podStatus.IsError {
		if podStatus.WaitingMessage != "" {
			return true, podStatus.WaitingMessage
		}
		if podStatus.Message != "" {
			return true, podStatus.Message
		}
		if podStatus.WaitingReason != "" {
			return true, podStatus.WaitingReason
		}
		if podStatus.Reason != "" {
			return true, podStatus.Reason
		}
		return true, "pod reported error"
	}

	for i := len(events) - 1; i >= 0; i-- {
		reason := strings.ToLower(events[i].Reason)
		if strings.Contains(reason, "backoff") ||
			strings.Contains(reason, "failed") ||
			strings.Contains(reason, "errimagepull") ||
			strings.Contains(reason, "imagepullbackoff") {
			if events[i].Message != "" {
				return true, events[i].Message
			}
			return true, events[i].Reason
		}
	}

	return false, ""
}
