package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/NorskHelsenett/spam/internal/config"
	"github.com/NorskHelsenett/spam/internal/jobs"
	"github.com/NorskHelsenett/spam/internal/providerconfig"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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
func (k *K8sClient) CreateRunJob(ctx context.Context, runID, cloneURL, ref, token, commitSHA string) (string, string, error) {
	return k.createK8sJob(ctx, runID, cloneURL, ref, token, commitSHA)
}

func (k *K8sClient) createK8sJob(ctx context.Context, runID, cloneURL, ref, token, commitSHA string) (string, string, error) {
	jobName := fmt.Sprintf("run-%s", runID[:8])
	namespace := k.cfg.Namespace

	ttlSeconds := k.cfg.TTLSeconds
	backoffLimit := int32(0)
	activeDeadline := k.cfg.ActiveDeadline

	// Non-root user
	runAsNonRoot := true
	runAsUser := int64(1000)

	// Labels carry Helm + ArgoCD tracking metadata so the dynamically
	// created Job shows up as part of the parent Application rather than
	// as an orphaned resource. ReleaseName/ChartName come from Helm via
	// SPAM_RELEASE_NAME / SPAM_CHART_NAME env vars.
	runLabels := map[string]string{
		"app.kubernetes.io/name":      "spam-repo-runner",
		"app.kubernetes.io/component": "repo-runner",
		"spam.io/run-id":              runID,
	}
	if k.cfg.ReleaseName != "" {
		runLabels["app.kubernetes.io/instance"] = k.cfg.ReleaseName
		runLabels["app.kubernetes.io/managed-by"] = "Helm"
	}
	if k.cfg.ChartName != "" {
		runLabels["helm.sh/chart"] = k.cfg.ChartName
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: namespace,
			Labels:    runLabels,
		},
		Spec: batchv1.JobSpec{
			TTLSecondsAfterFinished: &ttlSeconds,
			BackoffLimit:            &backoffLimit,
			ActiveDeadlineSeconds:   &activeDeadline,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      runLabels,
					Annotations: k.cfg.PodAnnotations,
				},
				Spec: corev1.PodSpec{
					RestartPolicy:                corev1.RestartPolicyNever,
					ServiceAccountName:           k.cfg.ServiceAccount,
					AutomountServiceAccountToken: &[]bool{false}[0],
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: &runAsNonRoot,
						RunAsUser:    &runAsUser,
					},
					Volumes: []corev1.Volume{
						{
							Name: "tmp",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium:    corev1.StorageMediumMemory,
									SizeLimit: resource.NewQuantity(256*1024*1024, resource.BinarySI),
								},
							},
						},
						{
							Name: "work",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
						{
							Name: "home",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{
									Medium:    corev1.StorageMediumMemory,
									SizeLimit: resource.NewQuantity(10*1024*1024, resource.BinarySI),
								},
							},
						},
					},
					InitContainers: []corev1.Container{
						{
							Name:            "clone",
							Image:           k.cfg.Image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Env: func() []corev1.EnvVar {
								envs := []corev1.EnvVar{
									{Name: "RUNNER_MODE", Value: "clone"},
									{Name: "WORKER_URL", Value: k.cfg.WorkerURL},
									{Name: "RUN_ID", Value: runID},
									{Name: "RUN_TOKEN", Value: token},
									{Name: "REPO_CLONE_URL", Value: cloneURL},
									{Name: "REPO_REF", Value: ref},
									{Name: "RUNNER_EGRESS_SELF_TEST_ENABLED", Value: fmt.Sprintf("%t", k.cfg.EgressSelfTest.Enabled)},
									{Name: "RUNNER_EGRESS_SELF_TEST_URL", Value: k.cfg.EgressSelfTest.URL},
									{Name: "RUNNER_EGRESS_SELF_TEST_TIMEOUT_SECONDS", Value: fmt.Sprintf("%d", k.cfg.EgressSelfTest.TimeoutSeconds)},
								}
								if commitSHA != "" {
									envs = append(envs, corev1.EnvVar{Name: "REPO_COMMIT_SHA", Value: commitSHA})
								}
								return envs
							}(),
							VolumeMounts: []corev1.VolumeMount{
								{Name: "tmp", MountPath: "/tmp"},
								{Name: "work", MountPath: "/work"},
								{Name: "home", MountPath: "/home/runner"},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: &[]bool{false}[0],
								ReadOnlyRootFilesystem:   &[]bool{true}[0],
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
								SeccompProfile: &corev1.SeccompProfile{
									Type: corev1.SeccompProfileTypeRuntimeDefault,
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:            "runner",
							Image:           k.cfg.Image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Env: func() []corev1.EnvVar {
								envs := []corev1.EnvVar{
									{Name: "RUNNER_MODE", Value: "scan"},
									{Name: "WORKER_URL", Value: k.cfg.WorkerURL},
									{Name: "RUN_ID", Value: runID},
									{Name: "RUN_TOKEN", Value: token},
									{Name: "REPO_CLONE_URL", Value: cloneURL},
									{Name: "REPO_REF", Value: ref},
									// Prevent third-party tools from phoning home
									{Name: "SYFT_CHECK_FOR_APP_UPDATE", Value: "false"},
								}
								if commitSHA != "" {
									envs = append(envs, corev1.EnvVar{Name: "REPO_COMMIT_SHA", Value: commitSHA})
								}
								return envs
							}(),
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
							VolumeMounts: []corev1.VolumeMount{
								{Name: "tmp", MountPath: "/tmp"},
								{Name: "work", MountPath: "/work", ReadOnly: true},
								{Name: "home", MountPath: "/home/runner"},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: &[]bool{false}[0],
								ReadOnlyRootFilesystem:   &[]bool{true}[0],
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
	if err == nil {
		return created.Name, namespace, nil
	}

	if !apierrors.IsAlreadyExists(err) {
		return "", "", fmt.Errorf("failed to create job: %w", err)
	}

	// Job already exists — attempt to adopt or replace it
	existing, getErr := k.GetJobStatus(ctx, jobName, namespace)
	if getErr != nil {
		return "", "", fmt.Errorf("job already exists and failed to get status: %w", getErr)
	}

	// Verify the existing job belongs to this run
	if existing.Labels["spam.io/run-id"] != runID {
		return "", "", fmt.Errorf("job %s already exists for a different run (label=%s)", jobName, existing.Labels["spam.io/run-id"])
	}

	// If the K8s job is still active or already succeeded, adopt it
	if existing.Status.Active > 0 || existing.Status.Succeeded > 0 {
		log.Printf("adopting existing k8s job: job=%s/%s active=%d succeeded=%d", namespace, jobName, existing.Status.Active, existing.Status.Succeeded)
		return existing.Name, namespace, nil
	}

	// If the K8s job has failed, delete it and create a new one. Deletion is
	// asynchronous — the API server may return before the object is gone —
	// so poll Create until AlreadyExists stops firing or the context expires
	// instead of sleeping a fixed 2s.
	if existing.Status.Failed > 0 {
		log.Printf("replacing failed k8s job: job=%s/%s failed=%d", namespace, jobName, existing.Status.Failed)
		propagationPolicy := metav1.DeletePropagationBackground
		if delErr := k.clientset.BatchV1().Jobs(namespace).Delete(ctx, jobName, metav1.DeleteOptions{
			PropagationPolicy: &propagationPolicy,
		}); delErr != nil {
			return "", "", fmt.Errorf("failed to delete old job: %w", delErr)
		}

		retryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		for {
			retried, retryErr := k.clientset.BatchV1().Jobs(namespace).Create(retryCtx, job, metav1.CreateOptions{})
			if retryErr == nil {
				return retried.Name, namespace, nil
			}
			if !apierrors.IsAlreadyExists(retryErr) {
				return "", "", fmt.Errorf("failed to recreate job after deletion: %w", retryErr)
			}
			select {
			case <-retryCtx.Done():
				return "", "", fmt.Errorf("timed out waiting for old job %s/%s to be deleted", namespace, jobName)
			case <-time.After(200 * time.Millisecond):
			}
		}
	}

	// Job exists but has no active/succeeded/failed pods (e.g. just created) — adopt it
	log.Printf("adopting existing k8s job (no terminal status): job=%s/%s", namespace, jobName)
	return existing.Name, namespace, nil
}


// DeleteJob deletes a Kubernetes job.
func (k *K8sClient) DeleteJob(ctx context.Context, jobName, namespace string) error {
	propagationPolicy := metav1.DeletePropagationBackground
	return k.clientset.BatchV1().Jobs(namespace).Delete(ctx, jobName, metav1.DeleteOptions{
		PropagationPolicy: &propagationPolicy,
	})
}

// GetJobStatus returns the status of a Kubernetes job.
func (k *K8sClient) GetJobStatus(ctx context.Context, jobName, namespace string) (*batchv1.Job, error) {
	return k.clientset.BatchV1().Jobs(namespace).Get(ctx, jobName, metav1.GetOptions{})
}

// PodStatus contains the status of a pod including any waiting/error states.
type PodStatus struct {
	Phase               string `json:"phase"`
	Reason              string `json:"reason,omitempty"`
	Message             string `json:"message,omitempty"`
	ContainerStatus     string `json:"container_status,omitempty"`
	WaitingReason       string `json:"waiting_reason,omitempty"`
	WaitingMessage      string `json:"waiting_message,omitempty"`
	IsError             bool   `json:"is_error"`
	InitContainerStatus string `json:"init_container_status,omitempty"` // "waiting", "running", "completed", "failed"
}

// GetPodStatus retrieves the status of the pod associated with a job.
// It returns error states like ImagePullBackOff, ErrImagePull, CrashLoopBackOff, etc.
func (k *K8sClient) GetPodStatus(ctx context.Context, jobName, namespace string) (*PodStatus, error) {
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

	// Check init container statuses (clone init container)
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.Name == "clone" {
			if cs.State.Running != nil {
				status.InitContainerStatus = "running"
			} else if cs.State.Terminated != nil {
				if cs.State.Terminated.ExitCode == 0 {
					status.InitContainerStatus = "completed"
				} else {
					status.InitContainerStatus = "failed"
					status.IsError = true
					status.Reason = cs.State.Terminated.Reason
					status.Message = cs.State.Terminated.Message
				}
			} else if cs.State.Waiting != nil {
				status.InitContainerStatus = "waiting"
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

// GetJobStatusString returns a simple status string for a named job.
// Returns "not_found" when the job does not exist.
func (k *K8sClient) GetJobStatusString(ctx context.Context, jobName string) (string, error) {
	job, err := k.clientset.BatchV1().Jobs(k.cfg.Namespace).Get(ctx, jobName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "not_found", nil
		}
		return "", fmt.Errorf("get job: %w", err)
	}
	switch {
	case job.Status.Succeeded > 0:
		return "succeeded", nil
	case job.Status.Failed > 0:
		return "failed", nil
	case job.Status.Active > 0:
		return "running", nil
	default:
		return "pending", nil
	}
}

// scannerOperatorLabel marks pods the operator spawned. Used for
// CountActiveScannerPods — Jobs themselves don't need it, only the pod
// template. Distinct from the legacy adhoc label so an in-place upgrade
// can tell old bursts apart from new operator-managed pods.
const scannerOperatorLabel = "spam.io/controller"
const scannerOperatorValue = "scanner-operator"

// CountActiveScannerPods returns the count of operator-spawned scanner
// pods currently Pending or Running. Feeds the operator's desired-vs-
// observed comparison. Jobs aren't counted — each operator Job has
// parallelism=1 completions=1 so 1 Job = 1 pod; counting pods directly
// is more accurate than counting Jobs (pod scheduling failures still
// count).
func (k *K8sClient) CountActiveScannerPods(ctx context.Context) (int, error) {
	pods, err := k.clientset.CoreV1().Pods(k.cfg.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: scannerOperatorLabel + "=" + scannerOperatorValue,
	})
	if err != nil {
		return 0, fmt.Errorf("list scanner pods: %w", err)
	}
	n := 0
	for _, p := range pods.Items {
		switch p.Status.Phase {
		case corev1.PodPending, corev1.PodRunning:
			n++
		}
	}
	return n, nil
}

// CreateScannerJob spawns a single scanner pod by cloning the
// image-scanner CronJob's pod template. Jobs get a random suffix so
// back-to-back creates never collide and finished Jobs age out via TTL
// without blocking future spawns.
//
// parallelism: 1 completions: 1 is forced regardless of what the
// CronJob template says — the operator does the scale-out by spawning
// N Jobs, not by letting one Job run N pods. That way a pod that
// fails to schedule is one thing the operator observes and corrects,
// not an opaque in-Job failure.
//
// Labels + annotations are inherited from the parent CronJob so that
// tools tracking resource ownership by chart (ArgoCD groups by
// app.kubernetes.io/instance; helm by app.kubernetes.io/managed-by)
// see the operator-spawned Jobs as part of the same Application, not
// as orphans. The operator adds its own discriminator label on top.
func (k *K8sClient) CreateScannerJob(ctx context.Context) error {
	cronJobName := strings.TrimSpace(os.Getenv("IMAGE_SCAN_CRONJOB_NAME"))
	if cronJobName == "" {
		return fmt.Errorf("IMAGE_SCAN_CRONJOB_NAME not configured")
	}

	namespace := k.cfg.Namespace
	cronJob, err := k.clientset.BatchV1().CronJobs(namespace).Get(ctx, cronJobName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get cronjob %s: %w", cronJobName, err)
	}

	// 8-hex-char suffix is plenty to avoid collisions across the
	// 5-minute TTL window while keeping Job names readable.
	suffix := fmt.Sprintf("%08x", time.Now().UnixNano()&0xffffffff)
	jobName := cronJobName + "-op-" + suffix

	ttl := int32(600) // 10 min — enough to grab logs post-mortem, short enough to not clutter
	spec := cronJob.Spec.JobTemplate.Spec
	one := int32(1)
	spec.Parallelism = &one
	spec.Completions = &one
	spec.TTLSecondsAfterFinished = &ttl

	// Start from the CronJob's labels/annotations so downstream tooling
	// (ArgoCD, helm, k8s metadata selectors) sees a consistent chain of
	// ownership. Then layer on what the operator needs.
	labels := copyStringMap(cronJob.Labels)
	labels[scannerOperatorLabel] = scannerOperatorValue
	annotations := copyStringMap(cronJob.Annotations)
	annotations["spam.io/created-by"] = "scanner-operator"
	annotations["spam.io/source-cronjob"] = cronJobName

	// Pod template labels: start from whatever the CronJob declared,
	// add the operator + component labels so NetworkPolicy selectors
	// and CountActiveScannerPods match.
	if spec.Template.Labels == nil {
		spec.Template.Labels = make(map[string]string)
	} else {
		spec.Template.Labels = copyStringMap(spec.Template.Labels)
	}
	spec.Template.Labels[scannerOperatorLabel] = scannerOperatorValue
	spec.Template.Labels["app.kubernetes.io/component"] = "image-scanner"
	// Preserve instance label on pods if it's only on the CronJob.
	if spec.Template.Labels["app.kubernetes.io/instance"] == "" {
		if inst := cronJob.Labels["app.kubernetes.io/instance"]; inst != "" {
			spec.Template.Labels["app.kubernetes.io/instance"] = inst
		}
	}

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        jobName,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: spec,
	}

	if _, err := k.clientset.BatchV1().Jobs(namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create scanner job %s: %w", jobName, err)
	}
	log.Printf("scanner operator: spawned %s/%s", namespace, jobName)
	return nil
}

func copyStringMap(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src)+2)
	for k, v := range src {
		dst[k] = v
	}
	return dst
}


// CreateSBOMAdhocJob creates an ad-hoc K8s Job from an existing CronJob's template.
// If a job with the given name already exists and is still running, it returns an error.
// If it has finished (succeeded or failed), the old job is deleted before creating a new one.
func (k *K8sClient) CreateSBOMAdhocJob(ctx context.Context, cronJobName, jobName string, ttlSecondsAfterFinished int32) error {
	namespace := k.cfg.Namespace

	// Check whether a prior adhoc job still exists.
	existing, err := k.clientset.BatchV1().Jobs(namespace).Get(ctx, jobName, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("check existing job: %w", err)
	}
	if err == nil {
		// Still active — refuse to create a duplicate.
		if existing.Status.Active > 0 {
			return fmt.Errorf("ad-hoc sbom scan job is already running")
		}
		// Finished — delete it so we can recreate.
		propagation := metav1.DeletePropagationBackground
		if delErr := k.clientset.BatchV1().Jobs(namespace).Delete(ctx, jobName, metav1.DeleteOptions{
			PropagationPolicy: &propagation,
		}); delErr != nil {
			return fmt.Errorf("delete previous job: %w", delErr)
		}
	}

	// Fetch the CronJob template.
	cronJob, err := k.clientset.BatchV1().CronJobs(namespace).Get(ctx, cronJobName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get cronjob %s: %w", cronJobName, err)
	}

	// Inherit labels/annotations from the parent CronJob so ArgoCD +
	// helm see the adhoc Job as part of the same Application and don't
	// flag it as an orphan.
	labels := copyStringMap(cronJob.Labels)
	labels["spam.io/adhoc-sbom-scan"] = "true"
	annotations := copyStringMap(cronJob.Annotations)
	annotations["spam.io/created-by"] = "admin-adhoc"
	annotations["spam.io/source-cronjob"] = cronJobName

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:        jobName,
			Namespace:   namespace,
			Labels:      labels,
			Annotations: annotations,
		},
		Spec: cronJob.Spec.JobTemplate.Spec,
	}
	job.Spec.TTLSecondsAfterFinished = &ttlSecondsAfterFinished
	// Ensure pod template has the sbom-scanner component label so the network policy applies.
	if job.Spec.Template.Labels == nil {
		job.Spec.Template.Labels = make(map[string]string)
	} else {
		job.Spec.Template.Labels = copyStringMap(job.Spec.Template.Labels)
	}
	job.Spec.Template.Labels["app.kubernetes.io/component"] = "sbom-scanner"
	if inst := cronJob.Labels["app.kubernetes.io/instance"]; inst != "" {
		job.Spec.Template.Labels["app.kubernetes.io/instance"] = inst
	}

	if _, err := k.clientset.BatchV1().Jobs(namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("create job: %w", err)
	}
	log.Printf("created adhoc sbom scan job: %s/%s", namespace, jobName)
	return nil
}

// GetContainerLogs retrieves logs from a specific container in the pod associated with a job.
func (k *K8sClient) GetContainerLogs(ctx context.Context, jobName, namespace, container string) (string, error) {
	pods, err := k.clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("job-name=%s", jobName),
	})
	if err != nil {
		return "", fmt.Errorf("list pods: %w", err)
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pods found for job %s", jobName)
	}

	opts := &corev1.PodLogOptions{Container: container}
	req := k.clientset.CoreV1().Pods(namespace).GetLogs(pods.Items[0].Name, opts)
	stream, err := req.Stream(ctx)
	if err != nil {
		return "", fmt.Errorf("stream logs: %w", err)
	}
	defer stream.Close()

	var result []byte
	buf := make([]byte, 2048)
	for {
		n, err := stream.Read(buf)
		if n > 0 {
			result = append(result, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	return string(result), nil
}

// GetPodLogs retrieves logs from the runner pod associated with a job.
func (k *K8sClient) GetPodLogs(ctx context.Context, jobName, namespace string, tailLines *int64) (string, error) {
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

// Compile-time assertions that RunExecutor satisfies the job-side executor
// interfaces the worker expects. IMAGE_SCAN is not here — it is leased by
// the dedicated spam-image-scanner pod rather than executed in-worker.
var (
	_ jobs.RunExecutor        = (*RunExecutor)(nil)
	_ jobs.SBOMAdhocJobCreator = (*RunExecutor)(nil)
)

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

// ExecuteRun starts a run by creating a K8s job or Docker container.
// This implements jobs.RunExecutor interface.
func (e *RunExecutor) ExecuteRun(ctx context.Context, runID string, payload interface{}) error {
	// Convert payload to expected format
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	var p jobs.CreateRunPayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}
	if p.RepoDisabled {
		return jobs.NonRetryable(fmt.Errorf("repository is disabled; skipping runner spawn"))
	}
	if strings.TrimSpace(p.ProviderID) != "" {
		var provider providerconfig.ProviderInstance
		if err := e.server.db.WithContext(ctx).First(&provider, "id = ?", p.ProviderID).Error; err == nil {
			if provider.HealthStatus == providerconfig.ProviderHealthFailed {
				return jobs.ProviderUnavailable(fmt.Errorf("provider health is failed; will retry later"))
			}
		}
	}
	// Generate run token (valid for 2 hours)
	token, err := GenerateRunToken(e.cfg.HMACKey, runID, 2*time.Hour)
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}

	// Create K8s job or Docker container
	jobName, namespace, err := e.k8s.CreateRunJob(ctx, runID, p.CloneURL, p.Ref, token, p.CommitSHA)
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

// CreateSBOMAdhocJob implements jobs.SBOMAdhocJobCreator for the worker.
// It creates an ad-hoc SBOM scanner K8s Job from the given CronJob template,
// with a fixed 12-hour TTL so it cleans itself up.
func (e *RunExecutor) CreateSBOMAdhocJob(ctx context.Context, cronJobName string) error {
	const ttl = int32(12 * 3600)
	return e.k8s.CreateSBOMAdhocJob(ctx, cronJobName, "sbom-adhoc", ttl)
}

// CountActiveScannerPods + CreateScannerJob satisfy imagescan.PodController
// so the worker can hand a *RunExecutor to the scanner operator without
// plumbing the raw *K8sClient through. Thin passthroughs.
func (e *RunExecutor) CountActiveScannerPods(ctx context.Context) (int, error) {
	return e.k8s.CountActiveScannerPods(ctx)
}

func (e *RunExecutor) CreateScannerJob(ctx context.Context) error {
	return e.k8s.CreateScannerJob(ctx)
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
