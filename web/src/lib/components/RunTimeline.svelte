<script lang="ts">
	import {
		CheckCircle,
		XCircle,
		Clock,
		Loader2,
		AlertTriangle,
		Download,
		GitBranch,
		Package,
		Shield,
		FileCode,
		Server,
		Play,
		Upload
	} from 'lucide-svelte';

	type TimelineStep = {
		id: string;
		title: string;
		description?: string;
		timestamp?: string;
		status: 'completed' | 'running' | 'pending' | 'error' | 'warning';
		icon?: any;
		details?: string[];
		category: 'k8s' | 'run' | 'result';
	};

	type K8sEvent = {
		type: string;
		reason: string;
		message: string;
		source: string;
		first_timestamp: string;
		last_timestamp: string;
		count: number;
		object: string;
	};

	type RunLog = {
		line: string;
		ts: string;
	};

	type Props = {
		runId: string;
		status: string;
		logs: RunLog[];
		events?: K8sEvent[];
		podStatus?: {
			phase: string;
			reason?: string;
			message?: string;
			waiting_reason?: string;
			waiting_message?: string;
			is_error?: boolean;
		};
		secretCount?: number;
		sbomComponentCount?: number;
		manifestCount?: number;
		commitHash?: string;
	};

	let {
		runId,
		status,
		logs = [],
		events = [],
		podStatus,
		secretCount = 0,
		sbomComponentCount = 0,
		manifestCount = 0,
		commitHash = ''
	}: Props = $props();

	// Parse logs into timeline steps
	const parseLogsToSteps = (logs: RunLog[]): TimelineStep[] => {
		const steps: TimelineStep[] = [];
		let currentStep: TimelineStep | null = null;

		for (const log of logs) {
			const line = log.line.trim();

			// Detect step transitions
			if (line.includes('Starting run:')) {
				steps.push({
					id: 'start',
					title: 'Run Started',
					description: `Run ID: ${runId.substring(0, 8)}`,
					timestamp: log.ts,
					status: 'completed',
					icon: Play,
					category: 'run'
				});
			} else if (line.includes('Requesting access token')) {
				steps.push({
					id: 'auth',
					title: 'Authenticating',
					description: 'Requesting access token',
					timestamp: log.ts,
					status: 'completed',
					icon: Shield,
					category: 'run'
				});
			} else if (line.includes('Cloning')) {
				const match = line.match(/Cloning (https?:\/\/[^\s]+)/);
				steps.push({
					id: 'clone',
					title: 'Cloning Repository',
					description: match ? match[1].replace('.git...', '') : 'Repository',
					timestamp: log.ts,
					status: 'completed',
					icon: GitBranch,
					category: 'run'
				});
			} else if (line.includes('Commit hash:')) {
				const hash = line.match(/Commit hash:\s*([a-f0-9]+)/)?.[1];
				if (hash) {
					// Update the last clone step with commit info
					const cloneStep = steps.find((s) => s.id === 'clone');
					if (cloneStep) {
						cloneStep.details = [`Commit: ${hash.substring(0, 7)}`];
					}
				}
			} else if (line.includes('Running syft')) {
				steps.push({
					id: 'sbom',
					title: 'SBOM Generation',
					description: 'Running Syft for SBOM generation',
					timestamp: log.ts,
					status: 'completed',
					icon: Package,
					category: 'run'
				});
			} else if (line.includes('Found') && line.includes('dependency manifest')) {
				const match = line.match(/Found (\d+) dependency manifest/);
				steps.push({
					id: 'manifests-found',
					title: 'Dependency Manifests',
					description: match ? `Found ${match[1]} manifest file(s)` : 'Collecting manifests',
					timestamp: log.ts,
					status: 'completed',
					icon: FileCode,
					category: 'run'
				});
			} else if (line.includes('Running gitleaks')) {
				steps.push({
					id: 'secrets',
					title: 'Secret Detection',
					description: 'Running Gitleaks scan',
					timestamp: log.ts,
					status: 'completed',
					icon: Shield,
					category: 'run'
				});
			} else if (line.includes('leaks found:')) {
				const match = line.match(/leaks found:\s*(\d+)/);
				const count = match ? parseInt(match[1]) : 0;
				const secretStep = steps.find((s) => s.id === 'secrets');
				if (secretStep) {
					secretStep.details = [`${count} secret${count !== 1 ? 's' : ''} found`];
					if (count > 0) {
						secretStep.status = 'warning';
					}
				}
			} else if (line.includes('Uploading SBOM')) {
				steps.push({
					id: 'upload-sbom',
					title: 'Uploading SBOM',
					description: 'Sending SBOM to server',
					timestamp: log.ts,
					status: 'completed',
					icon: Upload,
					category: 'run'
				});
			} else if (line.includes('Uploading gitleaks')) {
				steps.push({
					id: 'upload-secrets',
					title: 'Uploading Secrets Report',
					description: 'Sending scan results to server',
					timestamp: log.ts,
					status: 'completed',
					icon: Upload,
					category: 'run'
				});
			} else if (line.includes('Uploading dependency manifests')) {
				steps.push({
					id: 'upload-manifests',
					title: 'Uploading Manifests',
					description: 'Sending manifests to server',
					timestamp: log.ts,
					status: 'completed',
					icon: Upload,
					category: 'run'
				});
			} else if (line.includes('Run completed successfully')) {
				steps.push({
					id: 'complete',
					title: 'Run Completed',
					description: 'All tasks finished successfully',
					timestamp: log.ts,
					status: 'completed',
					icon: CheckCircle,
					category: 'run'
				});
			} else if (line.includes('error') || line.includes('Error') || line.includes('failed')) {
				// Track errors
				const lastStep = steps[steps.length - 1];
				if (lastStep) {
					lastStep.status = 'error';
					if (!lastStep.details) lastStep.details = [];
					lastStep.details.push(line);
				}
			}
		}

		return steps;
	};

	// Parse K8s events into timeline steps
	const parseEventsToSteps = (events: K8sEvent[]): TimelineStep[] => {
		const steps: TimelineStep[] = [];
		const seen = new Set<string>();

		for (const event of events) {
			// Deduplicate similar events
			const key = `${event.reason}-${event.object}`;
			if (seen.has(key)) continue;
			seen.add(key);

			let title = event.reason;
			let description = event.message;
			let status: TimelineStep['status'] = event.type === 'Normal' ? 'completed' : 'warning';
			let icon = Server;

			// Customize based on event reason
			switch (event.reason) {
				case 'Scheduled':
					title = 'Pod Scheduled';
					icon = Server;
					description = event.message.replace('Successfully assigned ', 'Assigned to ');
					break;
				case 'Pulling':
					title = 'Pulling Image';
					icon = Download;
					description = event.message.replace('Pulling image "', '').replace('"', '');
					// Truncate long image names
					if (description.length > 60) {
						description = description.substring(0, 57) + '...';
					}
					break;
				case 'Pulled':
					title = 'Image Pulled';
					icon = Download;
					const pullMatch = event.message.match(/in ([^\s]+)/);
					description = pullMatch ? `Pulled in ${pullMatch[1]}` : 'Successfully pulled';
					break;
				case 'Created':
					title = 'Container Created';
					icon = Server;
					break;
				case 'Started':
					title = 'Container Started';
					icon = Play;
					break;
				case 'Failed':
				case 'BackOff':
					title = event.reason === 'BackOff' ? 'Image Pull Backoff' : 'Failed';
					status = 'error';
					icon = XCircle;
					break;
				case 'PolicyViolation':
					title = 'Policy Violation';
					status = event.message.includes('fail') ? 'warning' : 'completed';
					icon = AlertTriangle;
					// Truncate long policy messages
					if (description.length > 80) {
						description = description.substring(0, 77) + '...';
					}
					break;
				default:
					// Keep original
					break;
			}

			steps.push({
				id: `k8s-${event.reason}-${event.first_timestamp}`,
				title,
				description,
				timestamp: event.first_timestamp,
				status,
				icon,
				category: 'k8s',
				details: event.count > 1 ? [`Occurred ${event.count} times`] : undefined
			});
		}

		return steps;
	};

	// Build the complete timeline
	const buildTimeline = (): TimelineStep[] => {
		const k8sSteps = parseEventsToSteps(events || []);
		const runSteps = parseLogsToSteps(logs || []);

		// Combine and sort by timestamp
		const allSteps = [...k8sSteps, ...runSteps];
		allSteps.sort((a, b) => {
			if (!a.timestamp || !b.timestamp) return 0;
			return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
		});

		// Add result steps if run is completed
		if (status === 'SUCCEEDED' || status === 'FAILED') {
			if (sbomComponentCount > 0) {
				allSteps.push({
					id: 'result-sbom',
					title: 'SBOM Generated',
					description: `${sbomComponentCount} component${sbomComponentCount !== 1 ? 's' : ''} detected`,
					status: 'completed',
					icon: Package,
					category: 'result'
				});
			}

			if (secretCount !== undefined) {
				allSteps.push({
					id: 'result-secrets',
					title: 'Secret Scan Complete',
					description:
						secretCount > 0
							? `${secretCount} secret${secretCount !== 1 ? 's' : ''} found`
							: 'No secrets found',
					status: secretCount > 0 ? 'warning' : 'completed',
					icon: Shield,
					category: 'result'
				});
			}

			if (manifestCount > 0) {
				allSteps.push({
					id: 'result-manifests',
					title: 'Manifests Collected',
					description: `${manifestCount} manifest${manifestCount !== 1 ? 's' : ''} saved`,
					status: 'completed',
					icon: FileCode,
					category: 'result'
				});
			}
		}

		// Add pod error step if there's a pod issue
		if (podStatus?.is_error) {
			allSteps.unshift({
				id: 'pod-error',
				title: podStatus.waiting_reason || podStatus.reason || 'Pod Error',
				description: podStatus.waiting_message || podStatus.message || 'Pod encountered an error',
				status: 'error',
				icon: XCircle,
				category: 'k8s'
			});
		}

		return allSteps;
	};

	const timeline = $derived(buildTimeline());

	const getStatusColor = (stepStatus: string) => {
		switch (stepStatus) {
			case 'completed':
				return 'var(--success)';
			case 'running':
				return 'var(--info)';
			case 'warning':
				return 'var(--warning)';
			case 'error':
				return 'var(--error)';
			default:
				return 'var(--text-muted)';
		}
	};

	const getCategoryLabel = (category: string) => {
		switch (category) {
			case 'k8s':
				return 'Kubernetes';
			case 'run':
				return 'Runner';
			case 'result':
				return 'Results';
			default:
				return '';
		}
	};

	const formatTimestamp = (ts?: string) => {
		if (!ts) return '';
		const date = new Date(ts);
		return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
	};
</script>

<div class="timeline-container">
	{#if timeline.length === 0}
		<div class="flex items-center justify-center py-8 text-[var(--text-muted)]">
			<Loader2 class="mr-2 h-5 w-5 animate-spin" />
			Waiting for events...
		</div>
	{:else}
		<div class="timeline">
			{#each timeline as step, index (step.id)}
				{@const Icon = step.icon || Clock}
				{@const isLast = index === timeline.length - 1}
				<div class="timeline-item">
					<!-- Vertical line -->
					{#if !isLast}
						<div
							class="timeline-line"
							style="background: linear-gradient(to bottom, {getStatusColor(step.status)}, {getStatusColor(timeline[index + 1]?.status || 'pending')})"
						></div>
					{/if}

					<!-- Icon node -->
					<div
						class="timeline-node"
						style="background: {getStatusColor(step.status)}20; border-color: {getStatusColor(step.status)}"
					>
						<Icon
							class="h-4 w-4 {step.status === 'running' ? 'animate-spin' : ''}"
							style="color: {getStatusColor(step.status)}"
						/>
					</div>

					<!-- Content -->
					<div class="timeline-content">
						<div class="flex items-start justify-between gap-2">
							<div class="flex-1">
								<div class="flex items-center gap-2">
									<span class="font-medium text-[var(--text-bright)]">{step.title}</span>
									<span
										class="rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wider"
										style="background: {getStatusColor(step.status)}15; color: {getStatusColor(step.status)}"
									>
										{getCategoryLabel(step.category)}
									</span>
								</div>
								{#if step.description}
									<p class="mt-0.5 text-sm text-[var(--text-secondary)]">{step.description}</p>
								{/if}
								{#if step.details && step.details.length > 0}
									<div class="mt-1 space-y-0.5">
										{#each step.details as detail}
											<p class="text-xs text-[var(--text-muted)]">{detail}</p>
										{/each}
									</div>
								{/if}
							</div>
							{#if step.timestamp}
								<span class="whitespace-nowrap text-xs text-[var(--text-muted)]">
									{formatTimestamp(step.timestamp)}
								</span>
							{/if}
						</div>
					</div>
				</div>
			{/each}
		</div>
	{/if}
</div>

<style>
	.timeline-container {
		padding: 1rem 0;
	}

	.timeline {
		position: relative;
	}

	.timeline-item {
		position: relative;
		display: flex;
		gap: 1rem;
		padding-bottom: 1.5rem;
	}

	.timeline-item:last-child {
		padding-bottom: 0;
	}

	.timeline-line {
		position: absolute;
		left: 15px;
		top: 32px;
		bottom: 0;
		width: 2px;
		opacity: 0.5;
	}

	.timeline-node {
		flex-shrink: 0;
		display: flex;
		align-items: center;
		justify-content: center;
		width: 32px;
		height: 32px;
		border-radius: 50%;
		border: 2px solid;
	}

	.timeline-content {
		flex: 1;
		min-width: 0;
		padding-top: 4px;
	}
</style>
