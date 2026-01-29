package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/NorskHelsenett/spam/internal/config"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// K8sClient wraps the Kubernetes client.
type K8sClient struct {
	clientset *kubernetes.Clientset
	cfg       config.RunnerConfig
}

// NewK8sClient creates a new Kubernetes client.
func NewK8sClient(cfg config.RunnerConfig) (*K8sClient, error) {
	if cfg.LocalMode {
		return &K8sClient{cfg: cfg}, nil
	}

	var k8sConfig *rest.Config
	var err error

	if cfg.KubeconfigPath != "" {
		k8sConfig, err = clientcmd.BuildConfigFromFlags("", cfg.KubeconfigPath)
	} else {
		k8sConfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s clientset: %w", err)
	}

	return &K8sClient{
		clientset: clientset,
		cfg:       cfg,
	}, nil
}

// CreateRunJob creates a Kubernetes job for a run.
func (k *K8sClient) CreateRunJob(ctx context.Context, runID, cloneURL, ref, token string) (string, string, error) {
	if k.cfg.LocalMode {
		return k.createLocalDockerRun(ctx, runID, cloneURL, ref, token)
	}

	return k.createK8sJob(ctx, runID, cloneURL, ref, token)
}

func (k *K8sClient) createK8sJob(ctx context.Context, runID, cloneURL, ref, token string) (string, string, error) {
	jobName := fmt.Sprintf("run-%s", runID[:8])
	namespace := k.cfg.Namespace

	ttlSeconds := k.cfg.TTLSeconds
	backoffLimit := int32(2)
	activeDeadline := k.cfg.ActiveDeadline

	// Non-root user
	runAsNonRoot := true
	runAsUser := int64(1000)

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":    "spam-runner",
				"app.kubernetes.io/part-of": "spam",
				"spam.io/run-id":            runID,
			},
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &ttlSeconds,
			BackoffLimit:            &backoffLimit,
			ActiveDeadlineSeconds:   &activeDeadline,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name":    "spam-runner",
						"app.kubernetes.io/part-of": "spam",
						"spam.io/run-id":            runID,
					},
				},
				Spec: corev1.PodSpec{
					RestartPolicy:      corev1.RestartPolicyNever,
					ServiceAccountName: k.cfg.ServiceAccount,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &runAsNonRoot,
						RunAsUser:    &runAsUser,
					},
					Containers: []corev1.Container{
						{
							Name:  "runner",
							Image: k.cfg.Image,
							Env: []corev1.EnvVar{
								{Name: "WORKER_URL", Value: k.cfg.WorkerURL},
								{Name: "RUN_ID", Value: runID},
								{Name: "RUN_TOKEN", Value: token},
								{Name: "REPO_CLONE_URL", Value: cloneURL},
								{Name: "REPO_REF", Value: ref},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("256Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("1"),
									corev1.ResourceMemory: resource.MustParse("2Gi"),
								},
							},
						},
					},
				},
			},
		},
	}

	created, err := k.clientset.BatchV1().Jobs(namespace).Create(ctx, job, metav1.CreateOptions{})
	if err != nil {
		return "", "", fmt.Errorf("failed to create job: %w", err)
	}

	return created.Name, namespace, nil
}

func (k *K8sClient) createLocalDockerRun(ctx context.Context, runID, cloneURL, ref, token string) (string, string, error) {
	args := []string{
		"run", "--rm",
		"-e", fmt.Sprintf("WORKER_URL=%s", k.cfg.WorkerURL),
		"-e", fmt.Sprintf("RUN_ID=%s", runID),
		"-e", fmt.Sprintf("RUN_TOKEN=%s", token),
		"-e", fmt.Sprintf("REPO_CLONE_URL=%s", cloneURL),
	}
	if ref != "" {
		args = append(args, "-e", fmt.Sprintf("REPO_REF=%s", ref))
	}
	args = append(args, k.cfg.Image)

	cmd := exec.CommandContext(ctx, "docker", args...)

	// Run in background
	go func() {
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("docker run failed: %v\nOutput: %s", err, string(output))
		}
	}()

	return fmt.Sprintf("docker-%s", runID[:8]), "local", nil
}

// DeleteJob deletes a Kubernetes job.
func (k *K8sClient) DeleteJob(ctx context.Context, jobName, namespace string) error {
	if k.cfg.LocalMode {
		// For local mode, we can't easily stop a detached docker run
		// The container will complete on its own
		log.Printf("local mode: cannot delete job %s", jobName)
		return nil
	}

	propagationPolicy := metav1.DeletePropagationBackground
	return k.clientset.BatchV1().Jobs(namespace).Delete(ctx, jobName, metav1.DeleteOptions{
		PropagationPolicy: &propagationPolicy,
	})
}


// RunExecutor handles creating and managing runs.
type RunExecutor struct {
	k8s    *K8sClient
	server *Server
	cfg    config.RunnerConfig
}

// NewRunExecutor creates a new run executor.
func NewRunExecutor(cfg config.RunnerConfig, server *Server) (*RunExecutor, error) {
	k8s, err := NewK8sClient(cfg)
	if err != nil {
		return nil, err
	}

	return &RunExecutor{
		k8s:    k8s,
		server: server,
		cfg:    cfg,
	}, nil
}

// CreateRunPayload is imported from jobs package via interface, define local for internal use.
type createRunPayloadInternal struct {
	RepoID    string `json:"repo_id,omitempty"`
	Provider  string `json:"provider,omitempty"`
	CloneURL  string `json:"clone_url"`
	Ref       string `json:"ref,omitempty"`
	CommitSHA string `json:"commit_sha,omitempty"`
}

// ExecuteRun starts a run by creating a K8s job or Docker container.
// This implements jobs.RunExecutor interface.
func (e *RunExecutor) ExecuteRun(ctx context.Context, runID string, payload interface{}) error {
	// Convert payload to expected format
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	var p createRunPayloadInternal
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}
	// Generate run token (valid for 2 hours)
	token, err := GenerateRunToken(e.cfg.HMACKey, runID, 2*time.Hour)
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}

	// Create K8s job or Docker container
	jobName, namespace, err := e.k8s.CreateRunJob(ctx, runID, p.CloneURL, p.Ref, token)
	if err != nil {
		return fmt.Errorf("create job: %w", err)
	}

	// Update run with K8s job info
	updates := map[string]interface{}{
		"k8s_job_name":  jobName,
		"k8s_namespace": namespace,
		"updated_at":    time.Now(),
	}
	if err := e.server.db.WithContext(ctx).Model(&Run{}).Where("id = ?", runID).Updates(updates).Error; err != nil {
		return fmt.Errorf("update run: %w", err)
	}

	log.Printf("created run job: run_id=%s job=%s/%s", runID, namespace, jobName)
	return nil
}

// CancelRun cancels a running job.
func (e *RunExecutor) CancelRun(ctx context.Context, runID, jobName, namespace string) error {
	// Send cancel signal via WebSocket
	if err := e.server.SendCancel(runID); err != nil {
		log.Printf("failed to send cancel signal: %v", err)
	}

	// Delete K8s job
	if err := e.k8s.DeleteJob(ctx, jobName, namespace); err != nil {
		return fmt.Errorf("delete job: %w", err)
	}

	return nil
}
