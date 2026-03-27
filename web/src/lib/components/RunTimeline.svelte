<script lang="ts">
	import {
		XCircle,
		Loader2,
		AlertTriangle,
		Download,
		GitBranch,
		Package,
		Shield,
		FileCode,
		Server,
		Play,
		Upload,
		Trash2,
		Terminal,
		ChevronDown,
		ChevronUp
	} from 'lucide-svelte';

	type TimelineStep = {
		id: string;
		title: string;
		description?: string;
		timestamp?: string;
		status: 'completed' | 'running' | 'pending' | 'error' | 'warning';
		icon?: any;
		details?: string[];
		category: 'k8s' | 'run' | 'event';
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
		container?: string;
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
			container_status?: string;
			waiting_reason?: string;
			waiting_message?: string;
			is_error?: boolean;
			init_container_status?: string;
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

	let showRawLogs = $state(false);
	let showAllEvents = $state(false);

	// Define essential steps only
	const ALL_STEPS: Array<{
		id: string;
		title: string;
		defaultDescription: string;
		icon: any;
		category: 'k8s' | 'run';
	}> = [
		{ id: 'k8s-started', title: 'Runner Started', defaultDescription: 'Pod scheduled on cluster', icon: Play, category: 'k8s' },
		{ id: 'k8s-clone', title: 'Cloning Repository', defaultDescription: 'Fetching source code', icon: GitBranch, category: 'k8s' },
		// Run steps (main container)
		{ id: 'run-sbom', title: 'SBOM Generation', defaultDescription: 'Running Syft scanner', icon: Package, category: 'run' },
		{ id: 'run-manifests', title: 'Collecting Manifests', defaultDescription: 'Finding dependency files', icon: FileCode, category: 'run' },
		{ id: 'run-secrets', title: 'Secret Detection', defaultDescription: 'Running BetterLeaks scan', icon: Shield, category: 'run' },
		{ id: 'run-upload', title: 'Uploading Results', defaultDescription: 'Sending data to server', icon: Upload, category: 'run' },
	];

	// Strip ANSI escape codes (colors, bold, etc.) from log lines
	const stripAnsi = (str: string) => str.replace(/\x1b\[[0-9;]*m/g, '');

	// Convert ANSI escape codes to HTML spans with theme-aware colors
	const ansiToHtml = (str: string): string => {
		const colors: Record<string, string> = {
			'30': 'var(--text-muted)',     // black
			'31': 'var(--red-dim)',        // red
			'32': 'var(--green-dim)',      // green
			'33': 'var(--yellow-dim)',     // yellow
			'34': 'var(--blue-dim)',       // blue
			'35': 'var(--purple-dim)',     // magenta
			'36': 'var(--aqua-dim)',       // cyan
			'37': 'var(--text-secondary)', // white
			'90': 'var(--text-muted)',     // bright black (gray)
			'91': 'var(--red)',            // bright red
			'92': 'var(--green)',          // bright green
			'93': 'var(--yellow)',         // bright yellow
			'94': 'var(--blue)',           // bright blue
			'95': 'var(--purple)',         // bright magenta
			'96': 'var(--aqua)',           // bright cyan
			'97': 'var(--text-bright)',    // bright white
		};

		// HTML-escape first to prevent XSS
		const escaped = str
			.replace(/&/g, '&amp;')
			.replace(/</g, '&lt;')
			.replace(/>/g, '&gt;');

		let result = '';
		let openSpans = 0;

		// Split on ANSI sequences, keeping the delimiters
		const parts = escaped.split(/(\x1b\[[0-9;]*m)/);
		for (const part of parts) {
			const match = part.match(/\x1b\[([0-9;]*)m/);
			if (!match) {
				result += part;
				continue;
			}

			const codes = match[1].split(';');
			for (const code of codes) {
				if (code === '0' || code === '') {
					// Reset — close all open spans
					while (openSpans > 0) { result += '</span>'; openSpans--; }
				} else if (code === '1') {
					result += '<span style="font-weight:bold">';
					openSpans++;
				} else if (colors[code]) {
					result += `<span style="color:${colors[code]}">`;
					openSpans++;
				}
			}
		}
		// Close any remaining open spans
		while (openSpans > 0) { result += '</span>'; openSpans--; }
		return result;
	};

	// Track completed step data from logs/events
	type CompletedStepData = {
		timestamp?: string;
		description?: string;
		details?: string[];
		status: 'completed' | 'running' | 'error' | 'warning';
	};

	// Parse logs to extract completed step data
	const parseLogsToCompletedSteps = (logs: RunLog[]): Map<string, CompletedStepData> => {
		const completed = new Map<string, CompletedStepData>();

		for (const log of logs) {
			const line = stripAnsi(log.line).trim();

			if (line.includes('Commit hash:')) {
				const hash = line.match(/Commit hash:\s*([a-f0-9]+)/)?.[1];
				const existing = completed.get('k8s-clone');
				if (existing && hash) {
					existing.details = [`Commit: ${hash.substring(0, 7)}`];
				}
			} else if (line.includes('Running syft')) {
				completed.set('run-sbom', {
					timestamp: log.ts,
					description: 'Generating software bill of materials',
					status: 'completed'
				});
			} else if (line.includes('Collecting dependency manifest files')) {
				const existing = completed.get('run-manifests');
				if (!existing) {
					completed.set('run-manifests', {
						timestamp: log.ts,
						description: 'Finding dependency files',
						status: 'running'
					});
				}
			} else if (line.includes('Found') && line.includes('dependency manifest')) {
				const match = line.match(/Found (\d+) dependency manifest/);
				completed.set('run-manifests', {
					timestamp: log.ts,
					description: match ? `Found ${match[1]} manifest file(s)` : 'Manifests collected',
					status: 'completed'
				});
			} else if (line.includes('Running BetterLeaks')) {
				const manifests = completed.get('run-manifests');
				if (manifests && manifests.status === 'running') {
					completed.set('run-manifests', {
						timestamp: log.ts,
						description: 'No manifest files found',
						status: 'completed'
					});
				}
				completed.set('run-secrets', {
					timestamp: log.ts,
					description: 'Scanning for secrets',
					status: 'completed'
				});
			} else if (line.includes('leaks found:')) {
				const match = line.match(/leaks found:\s*(\d+)/);
				const count = match ? parseInt(match[1]) : 0;
				const existing = completed.get('run-secrets');
				if (existing) {
					existing.details = [`${count} secret${count !== 1 ? 's' : ''} found`];
					if (count > 0) {
						existing.status = 'warning';
					}
				}
			} else if (line.includes('Uploading SBOM') || line.includes('Uploading BetterLeaks') || line.includes('Uploading dependency')) {
				const existing = completed.get('run-upload');
				if (!existing) {
					completed.set('run-upload', {
						timestamp: log.ts,
						description: 'Uploading results to server',
						status: 'completed'
					});
				}
			} else if (line.includes('Run completed successfully')) {
				// Mark upload as definitely complete
				const upload = completed.get('run-upload');
				if (upload) {
					upload.description = 'All results uploaded';
				}
			}
		}

		return completed;
	};

	// Derive clone step status from pod's init container status
	const parseInitContainerStatus = (): CompletedStepData | null => {
		if (!podStatus?.init_container_status) return null;
		switch (podStatus.init_container_status) {
			case 'running':
				return { description: 'Fetching source code', status: 'running' };
			case 'completed':
				return { description: 'Source code fetched', status: 'completed' };
			case 'failed':
				return { description: podStatus.message || 'Clone failed', status: 'error' };
			case 'waiting':
				return { description: 'Waiting to start', status: 'running' };
			default:
				return null;
		}
	};

	// Parse K8s events to extract completed step data
	const parseEventsToCompletedSteps = (events: K8sEvent[]): Map<string, CompletedStepData> => {
		const completed = new Map<string, CompletedStepData>();

		for (const event of events) {
			switch (event.reason) {
				case 'Scheduled':
				case 'Pulling':
				case 'Pulled':
				case 'Created':
				case 'Started':
					// Mark runner as started on any pod progress event
					if (!completed.has('k8s-started')) {
						completed.set('k8s-started', {
							timestamp: event.first_timestamp,
							description: 'Pod running on cluster',
							status: 'completed'
						});
					}
					break;
				case 'Failed':
				case 'BackOff':
					completed.set('k8s-started', {
						timestamp: event.first_timestamp,
						description: event.message.substring(0, 60),
						status: 'error'
					});
					break;
			}
		}

		return completed;
	};

	// Get all K8s events as timeline items (for history)
	const getAllK8sEvents = (events: K8sEvent[]): TimelineStep[] => {
		const eventSteps: TimelineStep[] = [];

		for (const event of events) {
			let icon = Server;
			let stepStatus: TimelineStep['status'] = event.type === 'Normal' ? 'completed' : 'warning';
			let title = event.reason;

			switch (event.reason) {
				case 'Scheduled':
					icon = Server;
					title = 'Pod Scheduled';
					break;
				case 'Pulling':
					icon = Download;
					title = 'Pulling Image';
					break;
				case 'Pulled':
					icon = Download;
					title = 'Image Pulled';
					break;
				case 'Created':
					icon = Server;
					title = 'Container Created';
					break;
				case 'Started':
					icon = Play;
					title = 'Container Started';
					break;
				case 'Failed':
				case 'BackOff':
					icon = XCircle;
					title = event.reason === 'BackOff' ? 'Image Pull Backoff' : 'Failed';
					stepStatus = 'error';
					break;
				case 'PolicyViolation':
					icon = AlertTriangle;
					title = 'Policy Violation';
					stepStatus = event.message.includes('fail') ? 'warning' : 'completed';
					break;
				case 'Killing':
					icon = Trash2;
					title = 'Stopping Container';
					break;
			}

			eventSteps.push({
				id: `event-${event.reason}-${event.first_timestamp}-${event.object}`,
				title,
				description: event.message.length > 80 ? event.message.substring(0, 77) + '...' : event.message,
				timestamp: event.first_timestamp,
				status: stepStatus,
				icon,
				category: 'event',
				details: event.count > 1 ? [`Occurred ${event.count} times`, `Source: ${event.source}`] : [`Source: ${event.source}`]
			});
		}

		return eventSteps;
	};

	// Build the complete timeline with all steps
	const buildTimeline = (): TimelineStep[] => {
		const logSteps = parseLogsToCompletedSteps(logs || []);
		const eventSteps = parseEventsToCompletedSteps(events || []);

		// Merge completed steps (log steps override event steps)
		const completedSteps = new Map([...eventSteps, ...logSteps]);

		// Add init container (clone) status
		const initStatus = parseInitContainerStatus();
		if (initStatus) {
			completedSteps.set('k8s-clone', initStatus);
		}

		// Determine current running step based on status
		let currentRunningStep: string | null = null;
		if (status === 'QUEUED') {
			currentRunningStep = 'k8s-started';
		} else if (status === 'RUNNING') {
			// Find the first incomplete step
			for (const step of ALL_STEPS) {
				if (!completedSteps.has(step.id)) {
					currentRunningStep = step.id;
					break;
				}
			}
		}

		// Build timeline
		const timeline: TimelineStep[] = [];

		// Add pod error if present
		if (podStatus?.is_error) {
			timeline.push({
				id: 'pod-error',
				title: podStatus.waiting_reason || podStatus.reason || 'Pod Error',
				description: podStatus.waiting_message || podStatus.message || 'Pod encountered an error',
				status: 'error',
				icon: XCircle,
				category: 'k8s'
			});
		}

		// Add all expected steps
		for (const stepDef of ALL_STEPS) {
			const completed = completedSteps.get(stepDef.id);

			let stepStatus: TimelineStep['status'] = 'pending';
			let details = completed?.details;

			if (completed) {
				stepStatus = completed.status;
			} else if (stepDef.id === currentRunningStep) {
				stepStatus = 'running';
			} else if (stepDef.id === 'k8s-started' && podStatus) {
				// Any pod status means the runner has started
				if (podStatus.is_error) {
					stepStatus = 'error';
				} else {
					stepStatus = 'completed';
				}
			} else if (stepDef.id === 'k8s-clone' && status === 'SUCCEEDED') {
				stepStatus = 'completed';
			} else if ((stepDef.id === 'k8s-started' || stepDef.id === 'k8s-clone') && status === 'SUCCEEDED') {
				stepStatus = 'completed';
			} else if (status === 'FAILED') {
				// If run failed and step not completed, check if it should be marked as skipped
				const stepIndex = ALL_STEPS.findIndex(s => s.id === stepDef.id);
				const lastCompletedIndex = Math.max(...Array.from(completedSteps.keys()).map(id => ALL_STEPS.findIndex(s => s.id === id)));
				if (stepIndex > lastCompletedIndex) {
					stepStatus = 'pending'; // Skipped due to failure
				}
			}

			// Add counts to specific steps when completed
			if (stepDef.id === 'run-sbom' && stepStatus === 'completed' && sbomComponentCount > 0) {
				details = [...(details || []), `${sbomComponentCount} component${sbomComponentCount !== 1 ? 's' : ''} detected`];
			}
			if (stepDef.id === 'run-manifests' && stepStatus === 'completed' && manifestCount > 0) {
				details = [...(details || []), `${manifestCount} file${manifestCount !== 1 ? 's' : ''} collected`];
			}
			if (stepDef.id === 'run-secrets' && stepStatus === 'completed') {
				if (secretCount > 0) {
					details = [...(details || []), `${secretCount} secret${secretCount !== 1 ? 's' : ''} found`];
				} else if (!details?.some(d => d.includes('secret'))) {
					details = [...(details || []), 'No secrets found'];
				}
			}

			// Context-aware title/description for K8s steps
			let title = stepDef.title;
			let description = completed?.description || stepDef.defaultDescription;

			if (stepDef.id === 'k8s-clone' && !completed) {
				if (stepStatus === 'running') {
					if (podStatus?.waiting_reason) {
						title = podStatus.waiting_reason;
						description = podStatus.waiting_message || 'Waiting...';
					} else if (podStatus?.phase === 'Pending') {
						title = 'Scheduling Pod';
						description = 'Waiting for pod to be scheduled';
					}
				} else if (stepStatus === 'error') {
					title = podStatus?.reason || 'Clone Failed';
					description = podStatus?.message || 'Init container failed';
				}
			}

			if (stepDef.id === 'k8s-started' && !completed) {
				if (stepStatus === 'running') {
					title = 'Starting Scanner';
					description = 'Waiting for scanner container to start';
				} else if (stepStatus === 'error') {
					title = podStatus?.waiting_reason || podStatus?.reason || 'Container Failed';
					description = podStatus?.waiting_message || podStatus?.message || 'Pod failed to start';
				}
			}

			timeline.push({
				id: stepDef.id,
				title,
				description,
				timestamp: completed?.timestamp,
				status: stepStatus,
				icon: stepDef.icon,
				category: stepDef.category,
				details
			});
		}

		return timeline;
	};

	const timeline = $derived(buildTimeline());
	const allEvents = $derived(getAllK8sEvents(events || []));

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
			case 'pending':
				return 'var(--text-muted)';
			default:
				return 'var(--text-muted)';
		}
	};

	const getStatusOpacity = (stepStatus: string) => {
		return stepStatus === 'pending' ? '0.5' : '1';
	};

	const getCategoryLabel = (category: string) => {
		switch (category) {
			case 'k8s':
				return 'K8s';
			case 'run':
				return 'Runner';
			case 'event':
				return 'Event';
			default:
				return '';
		}
	};

	const formatTimestamp = (ts?: string) => {
		if (!ts) return '';
		const date = new Date(ts);
		return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
	};

	// Format raw logs grouped by container with headers showing container name and job name
	const rawLogsHtml = $derived.by(() => {
		const containerLabels: Record<string, string> = {
			'clone': 'clone [init]',
			'runner': `runner [${runId.substring(0, 8)}]`,
		};
		const groups = new Map<string, string[]>();
		const order: string[] = [];

		for (const l of logs) {
			const container = l.container || 'runner';
			if (!groups.has(container)) {
				groups.set(container, []);
				order.push(container);
			}
			const ts = `<span style="color:var(--text-muted)">[${formatTimestamp(l.ts)}]</span>`;
			groups.get(container)!.push(`  ${ts} ${ansiToHtml(l.line)}`);
		}

		const sections: string[] = [];
		for (const container of order) {
			const label = containerLabels[container] || container;
			sections.push(`<span style="color:var(--aqua);font-weight:bold">── ${label} ──</span>\n${groups.get(container)!.join('\n')}`);
		}
		return sections.join('\n\n');
	});
</script>

<div class="timeline-container">
	{#if timeline.length === 0 && status === 'QUEUED'}
		<div class="flex items-center justify-center py-8 text-[var(--text-muted)]">
			<Loader2 class="mr-2 h-5 w-5 animate-spin" />
			Waiting for pod to be scheduled...
		</div>
	{:else}
		<!-- Main Timeline -->
		<div class="timeline">
			{#each timeline as step, index (step.id)}
				{@const Icon = step.icon || Server}
				{@const isLast = index === timeline.length - 1}
				{@const isPending = step.status === 'pending'}
				<div class="timeline-item" style="opacity: {getStatusOpacity(step.status)}">
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
						style="background: {getStatusColor(step.status)}20; border-color: {getStatusColor(step.status)}; {isPending ? 'border-style: dashed;' : ''}"
					>
						{#if step.status === 'running'}
							<Loader2
								class="h-4 w-4 animate-spin"
								style="color: {getStatusColor(step.status)}"
							/>
						{:else}
							<Icon
								class="h-4 w-4"
								style="color: {getStatusColor(step.status)}"
							/>
						{/if}
					</div>

					<!-- Content -->
					<div class="timeline-content">
						<div class="flex items-start justify-between gap-2">
							<div class="flex-1">
								<div class="flex items-center gap-2">
									<span class="{isPending ? 'text-[var(--text-muted)]' : 'text-[var(--text-bright)]'} font-medium">
										{step.title}
									</span>
									<span
										class="rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wider"
										style="background: {getStatusColor(step.status)}15; color: {getStatusColor(step.status)}"
									>
										{getCategoryLabel(step.category)}
									</span>
									{#if isPending}
										<span class="text-[10px] text-[var(--text-muted)]">pending</span>
									{/if}
								</div>
								{#if step.description}
									<p class="mt-0.5 text-sm {isPending ? 'text-[var(--text-muted)]' : 'text-[var(--text-secondary)]'}">
										{step.description}
									</p>
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
							{:else if isPending}
								<span class="whitespace-nowrap text-xs text-[var(--text-muted)]">--:--:--</span>
							{/if}
						</div>
					</div>
				</div>
			{/each}
		</div>

		<!-- K8s Events History -->
		{#if allEvents.length > 0}
			<div class="mt-6 border-t border-[var(--border-color)]/40 pt-4">
				<button
					type="button"
					class="flex w-full items-center justify-between text-sm text-[var(--text-secondary)] hover:text-[var(--text-bright)]"
					onclick={() => { showAllEvents = !showAllEvents; }}
				>
					<span class="flex items-center gap-2">
						<Server class="h-4 w-4" />
						Kubernetes Events ({allEvents.length})
					</span>
					{#if showAllEvents}
						<ChevronUp class="h-4 w-4" />
					{:else}
						<ChevronDown class="h-4 w-4" />
					{/if}
				</button>

				{#if showAllEvents}
					<div class="mt-4 space-y-2">
						{#each allEvents as event (event.id)}
							{@const Icon = event.icon || Server}
							<div class="flex items-start gap-3 rounded-lg bg-[var(--card-bg)]/30 p-3">
								<div
									class="flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-full"
									style="background: {getStatusColor(event.status)}20"
								>
									<Icon class="h-3 w-3" style="color: {getStatusColor(event.status)}" />
								</div>
								<div class="flex-1 min-w-0">
									<div class="flex items-center justify-between gap-2">
										<span class="text-sm font-medium text-[var(--text-bright)]">{event.title}</span>
										<span class="whitespace-nowrap text-xs text-[var(--text-muted)]">
											{formatTimestamp(event.timestamp)}
										</span>
									</div>
									<p class="mt-0.5 text-xs text-[var(--text-secondary)] break-all">{event.description}</p>
									{#if event.details}
										<div class="mt-1 flex flex-wrap gap-2">
											{#each event.details as detail}
												<span class="text-[10px] text-[var(--text-muted)]">{detail}</span>
											{/each}
										</div>
									{/if}
								</div>
							</div>
						{/each}
					</div>
				{/if}
			</div>
		{/if}

		<!-- Raw Logs Section -->
		{#if logs.length > 0}
			<div class="mt-4 border-t border-[var(--border-color)]/40 pt-4">
				<button
					type="button"
					class="flex w-full items-center justify-between text-sm text-[var(--text-secondary)] hover:text-[var(--text-bright)]"
					onclick={() => { showRawLogs = !showRawLogs; }}
				>
					<span class="flex items-center gap-2">
						<Terminal class="h-4 w-4" />
						Raw Logs ({logs.length} lines)
					</span>
					{#if showRawLogs}
						<ChevronUp class="h-4 w-4" />
					{:else}
						<ChevronDown class="h-4 w-4" />
					{/if}
				</button>

				{#if showRawLogs}
					<div class="mt-3 max-h-80 overflow-auto rounded-lg border border-[var(--border-color)]/60 bg-[var(--main-content-bg)]/80 p-4 shadow-inner">
						<pre class="code-block text-xs text-[var(--text-secondary)] whitespace-pre-wrap break-all"><code>{@html rawLogsHtml}</code></pre>
					</div>
				{/if}
			</div>
		{/if}
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

	.code-block {
		font-family: 'JetBrains Mono', monospace;
		border-radius: 0.5rem;
	}
</style>
