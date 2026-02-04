package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
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

	client := &K8sClient{
		clientset: clientset,
		cfg:       cfg,
	}

	// Auto-discover annotations from current pod if running in cluster
	if cfg.KubeconfigPath == "" {
		if err := client.discoverPodAnnotations(); err != nil {
			log.Printf("warning: failed to discover pod annotations: %v", err)
			// Non-fatal, continue without inherited annotations
		}
	}

	return client, nil
}

// discoverPodAnnotations queries the current pod's annotations and merges them into config.
func (k *K8sClient) discoverPodAnnotations() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Get pod name and namespace from downward API env vars
	podName := os.Getenv("POD_NAME")
	namespace := os.Getenv("POD_NAMESPACE")

	if podName == "" || namespace == "" {
		return fmt.Errorf("POD_NAME or POD_NAMESPACE not set")
	}

	pod, err := k.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get pod: %w", err)
	}

	// Filter annotations to inherit (exclude K8s internal ones)
	if k.cfg.PodAnnotations == nil {
		k.cfg.PodAnnotations = make(map[string]string)
	}

	for key, value := range pod.Annotations {
		// Skip Kubernetes internal annotations
		if strings.HasPrefix(key, "kubernetes.io/") ||
			strings.HasPrefix(key, "k8s.io/") ||
			strings.HasPrefix(key, "kubectl.kubernetes.io/") {
			continue
		}
		// Skip ArgoCD tracking annotations (should be unique per resource)
		if strings.HasPrefix(key, "argocd.argoproj.io/tracking-id") ||
			strings.HasPrefix(key, "argocd.argoproj.io/instance") {
			continue
		}
		// Skip other identity-specific annotations
		if strings.HasPrefix(key, "deployment.kubernetes.io/") ||
			strings.HasPrefix(key, "replicaset.kubernetes.io/") {
			continue
		}
		// Add annotation if not already configured
		if _, exists := k.cfg.PodAnnotations[key]; !exists {
			k.cfg.PodAnnotations[key] = value
			log.Printf("inherited annotation: %s=%s", key, value)
		}
	}

	return nil
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
					Annotations: k.cfg.PodAnnotations,
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
							ImagePullPolicy: corev1.PullIfNotPresent,
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
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: &[]bool{false}[0],
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
								SeccompProfile: &corev1.SeccompProfile{
									Type: corev1.SeccompProfileTypeRuntimeDefault,
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

// GetJobStatus returns the status of a Kubernetes job.
func (k *K8sClient) GetJobStatus(ctx context.Context, jobName, namespace string) (*batchv1.Job, error) {
	if k.cfg.LocalMode {
		return nil, fmt.Errorf("job status not available in local mode")
	}

	return k.clientset.BatchV1().Jobs(namespace).Get(ctx, jobName, metav1.GetOptions{})
}

// PodStatus contains the status of a pod including any waiting/error states.
type PodStatus struct {
	Phase           string `json:"phase"`
	Reason          string `json:"reason,omitempty"`
	Message         string `json:"message,omitempty"`
	ContainerStatus string `json:"container_status,omitempty"`
	WaitingReason   string `json:"waiting_reason,omitempty"`
	WaitingMessage  string `json:"waiting_message,omitempty"`
	IsError         bool   `json:"is_error"`
}

// GetPodStatus retrieves the status of the pod associated with a job.
// It returns error states like ImagePullBackOff, ErrImagePull, CrashLoopBackOff, etc.
func (k *K8sClient) GetPodStatus(ctx context.Context, jobName, namespace string) (*PodStatus, error) {
	if k.cfg.LocalMode {
		return nil, fmt.Errorf("pod status not available in local mode")
	}

	// Find the pod created by this job
	pods, err := k.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("job-name=%s", jobName),
	})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return &PodStatus{
			Phase:   "Pending",
			Reason:  "NoPod",
			Message: "no pods found for job",
		}, nil
	}

	pod := pods.Items[0]
	status := &PodStatus{
		Phase: string(pod.Status.Phase),
	}

	// Check pod-level conditions
	for _, cond := range pod.Status.Conditions {
		if cond.Type == corev1.PodScheduled && cond.Status == corev1.ConditionFalse {
			status.Reason = cond.Reason
			status.Message = cond.Message
			if cond.Reason == "Unschedulable" {
				status.IsError = true
			}
		}
	}

	// Check container statuses for waiting/error states
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name == "runner" {
			status.ContainerStatus = "unknown"
			if cs.State.Running != nil {
				status.ContainerStatus = "running"
			} else if cs.State.Terminated != nil {
				status.ContainerStatus = "terminated"
				if cs.State.Terminated.ExitCode != 0 {
					status.Reason = cs.State.Terminated.Reason
					status.Message = cs.State.Terminated.Message
					status.IsError = true
				}
			} else if cs.State.Waiting != nil {
				status.ContainerStatus = "waiting"
				status.WaitingReason = cs.State.Waiting.Reason
				status.WaitingMessage = cs.State.Waiting.Message

				// Mark specific waiting states as errors
				switch cs.State.Waiting.Reason {
				case "ImagePullBackOff", "ErrImagePull", "InvalidImageName":
					status.IsError = true
					status.Reason = cs.State.Waiting.Reason
					status.Message = cs.State.Waiting.Message
				case "CrashLoopBackOff":
					status.IsError = true
					status.Reason = cs.State.Waiting.Reason
					status.Message = cs.State.Waiting.Message
				case "CreateContainerConfigError", "CreateContainerError":
					status.IsError = true
					status.Reason = cs.State.Waiting.Reason
					status.Message = cs.State.Waiting.Message
				}
			}
			break
		}
	}

	// Also check init container statuses
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.State.Waiting != nil {
			switch cs.State.Waiting.Reason {
			case "ImagePullBackOff", "ErrImagePull", "InvalidImageName":
				status.IsError = true
				status.Reason = cs.State.Waiting.Reason
				status.Message = cs.State.Waiting.Message
				status.WaitingReason = cs.State.Waiting.Reason
				status.WaitingMessage = cs.State.Waiting.Message
			}
		}
	}

	return status, nil
}

// K8sEvent represents a Kubernetes event.
type K8sEvent struct {
	Type           string    `json:"type"`            // Normal, Warning
	Reason         string    `json:"reason"`          // Scheduled, Pulling, Pulled, Created, Started, etc.
	Message        string    `json:"message"`         // Human-readable description
	Source         string    `json:"source"`          // Component that reported the event
	FirstTimestamp time.Time `json:"first_timestamp"` // When the event was first recorded
	LastTimestamp  time.Time `json:"last_timestamp"`  // When the event was last recorded
	Count          int32     `json:"count"`           // Number of times this event occurred
	Object         string    `json:"object"`          // Object this event is about (job, pod)
}

// GetJobEvents retrieves Kubernetes events for a job and its pods.
func (k *K8sClient) GetJobEvents(ctx context.Context, jobName, namespace string) ([]K8sEvent, error) {
	if k.cfg.LocalMode {
		return nil, fmt.Errorf("events not available in local mode")
	}

	var result []K8sEvent

	// Get events for the job
	jobFieldSelector := fmt.Sprintf("involvedObject.kind=Job,involvedObject.name=%s", jobName)
	jobEvents, err := k.clientset.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: jobFieldSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("list job events: %w", err)
	}

	for _, e := range jobEvents.Items {
		result = append(result, K8sEvent{
			Type:           e.Type,
			Reason:         e.Reason,
			Message:        e.Message,
			Source:         e.Source.Component,
			FirstTimestamp: e.FirstTimestamp.Time,
			LastTimestamp:  e.LastTimestamp.Time,
			Count:          e.Count,
			Object:         "job/" + jobName,
		})
	}

	// Find pods created by this job and get their events
	pods, err := k.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("job-name=%s", jobName),
	})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}

	for _, pod := range pods.Items {
		podFieldSelector := fmt.Sprintf("involvedObject.kind=Pod,involvedObject.name=%s", pod.Name)
		podEvents, err := k.clientset.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{
			FieldSelector: podFieldSelector,
		})
		if err != nil {
			log.Printf("failed to list events for pod %s: %v", pod.Name, err)
			continue
		}

		for _, e := range podEvents.Items {
			result = append(result, K8sEvent{
				Type:           e.Type,
				Reason:         e.Reason,
				Message:        e.Message,
				Source:         e.Source.Component,
				FirstTimestamp: e.FirstTimestamp.Time,
				LastTimestamp:  e.LastTimestamp.Time,
				Count:          e.Count,
				Object:         "pod/" + pod.Name,
			})
		}
	}

	// Sort events by timestamp
	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if result[i].FirstTimestamp.After(result[j].FirstTimestamp) {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result, nil
}

// GetPodLogs retrieves logs from the runner pod associated with a job.
func (k *K8sClient) GetPodLogs(ctx context.Context, jobName, namespace string, tailLines *int64) (string, error) {
	if k.cfg.LocalMode {
		return "", fmt.Errorf("pod logs not available in local mode")
	}

	// Find the pod created by this job
	pods, err := k.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("job-name=%s", jobName),
	})
	if err != nil {
		return "", fmt.Errorf("list pods: %w", err)
	}

	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pods found for job %s", jobName)
	}

	// Get logs from the first pod (jobs typically have one pod)
	pod := pods.Items[0]
	opts := &corev1.PodLogOptions{
		Container: "runner",
	}
	if tailLines != nil {
		opts.TailLines = tailLines
	}

	req := k.clientset.CoreV1().Pods(namespace).GetLogs(pod.Name, opts)
	logs, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("stream logs: %w", err)
	}
	defer logs.Close()

	// Read all logs
	var result []byte
	buf := make([]byte, 2048)
	for {
		n, err := logs.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if err != nil {
			break
		}
	}

	return string(result), nil
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
	ProviderID string `json:"provider_id,omitempty"`
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
