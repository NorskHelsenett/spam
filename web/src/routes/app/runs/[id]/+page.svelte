<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { browser } from '$app/environment';
	import { page } from '$app/stores';
	import { ArrowLeft, CheckCircle, XCircle, Clock, Loader2, GitBranch, GitCommit, Package, Shield, FileCode, Eye, Download, Activity, ExternalLink } from 'lucide-svelte';
	import RunTimeline from '$lib/components/RunTimeline.svelte';
	import Dialog from '$lib/components/Dialog.svelte';
	import Gitea from '$lib/components/icons/Gitea.svelte';
	import SecretsDialog from '$lib/components/SecretsDialog.svelte';
	import DependenciesDialog from '$lib/components/DependenciesDialog.svelte';

	type Run = {
		id: string;
		status: string;
		clone_url: string;
		provider: string;
		provider_id?: string;
		repo_id?: string;
		base_url?: string;
		repo_path: string;
		ref?: string;
		commit_sha?: string;
		error?: string;
		created_at: string;
		started_at?: string;
		finished_at?: string;
		k8s_job_name?: string;
		sbom_id?: string;
		secret_id?: string;
	};

	type Artifact = {
		type: string;
		name: string;
		count: number;
		icon: any;
		color: string;
		view_url?: string;
		download_url?: string;
		raw_data?: any;
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

	type PodStatus = {
		phase: string;
		reason?: string;
		message?: string;
		waiting_reason?: string;
		waiting_message?: string;
		is_error?: boolean;
	};

	type SecretFinding = {
		rule_id: string;
		description: string;
		file: string;
		start_line: number;
		match: string;
	};

	type RepoDependency = {
		group_path: string;
		name: string;
		ecosystem: string;
		version: string;
		sources: string[];
		direct: boolean;
		origin_path?: string;
	};
	// Note: types kept here only for the fetch function signatures; dialog logic lives in the components

	let run: Run | null = $state(null);
	let artifacts: Artifact[] = $state([]);
	let loading = $state(true);
	let error = $state('');
	let showRawDialog = $state(false);
	let rawDialogTitle = $state('');
	let rawDialogData = $state('');
	let rawDialogLoading = $state(false);
	let eventSource: EventSource | null = null;
	let lastStatus = $state('');
	let runLogs: RunLog[] = $state([]);
	let k8sEvents: K8sEvent[] = $state([]);
	let podStatus: PodStatus | null = $state(null);
	let showTimeline = $state(true);
	let k8sPollingDisabled = $state(false);
	let now = $state(Date.now());
	let ticker: ReturnType<typeof setInterval> | null = null;

	// Secrets dialog
	let secretsDialogOpen = $state(false);
	let secretsDialogLoading = $state(false);
	let secretsDialogData = $state<SecretFinding[]>([]);

	// Dependencies dialog (SBOM / Manifests)
	let dependenciesDialogOpen = $state(false);
	let dependenciesDialogLoading = $state(false);
	let dependenciesDialogData = $state<RepoDependency[]>([]);
	const openSecretsDialog = async () => {
		const id = $page.params.id;
		secretsDialogOpen = true;
		if (secretsDialogData.length > 0) return;
		secretsDialogLoading = true;
		try {
			const url = run?.repo_id
				? `/api/repos/secrets/list?repo_id=${encodeURIComponent(run.repo_id)}`
				: `/api/runs/${id}/secrets`;
			const res = await fetch(url, { credentials: 'include' });
			if (res.ok) {
				const data = await res.json();
				secretsDialogData = Array.isArray(data) ? data : (data.findings || []);
			}
		} finally {
			secretsDialogLoading = false;
		}
	};

	const openDependenciesDialog = async () => {
		dependenciesDialogOpen = true;
		if (dependenciesDialogData.length > 0) return;
		if (!run?.repo_id) return;
		dependenciesDialogLoading = true;
		try {
			const res = await fetch(`/api/repos/dependencies/list?repo_id=${encodeURIComponent(run.repo_id)}`, { credentials: 'include' });
			if (res.ok) {
				const data = await res.json();
				dependenciesDialogData = data.dependencies || [];
			}
		} finally {
			dependenciesDialogLoading = false;
		}
	};

	const loadRun = async (shouldLoadArtifacts = true) => {
		const id = $page.params.id;
		if (!id) return;

		try {
			const response = await fetch(`/api/runs/${id}`, {
				credentials: 'include'
			});
			if (!response.ok) {
				if (response.status === 404) {
					error = 'Run not found';
				} else {
					error = 'Failed to load run';
				}
				return;
			}
			const newRun = await response.json();
			const statusChanged = lastStatus && lastStatus !== newRun.status;
			run = newRun;
			lastStatus = newRun.status;
			
			// Load artifacts after getting run details, or when status changes to completed
			if (shouldLoadArtifacts && run && (run.status === 'SUCCEEDED' || run.status === 'FAILED' || statusChanged)) {
				await loadArtifacts(id, run);
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load run';
		} finally {
			loading = false;
		}
	};

	const loadK8sEvents = async (runId: string) => {
		if (k8sPollingDisabled) return false;
		try {
			const response = await fetch(`/api/runs/${runId}/events`, {
				credentials: 'include'
			});
			if (response.status === 404 || response.status === 400) {
				// K8s endpoints not available or run has no job; stop polling
				k8sPollingDisabled = true;
				if (eventsInterval) {
					clearInterval(eventsInterval);
					eventsInterval = null;
				}
				return false;
			}
			if (response.ok) {
				const data = await response.json();
				k8sEvents = data.events || [];
				podStatus = data.pod_status || null;
				return true;
			}
		} catch (e) {
			console.log('K8s events not available:', e);
		}
		return false;
	};

	const loadArtifacts = async (runId: string, runData: Run) => {
		const artifactsList: Artifact[] = [];

		// Load SBOM info
		if (runData.sbom_id) {
			try {
				const sbomResponse = await fetch(`/api/sboms/${runData.sbom_id}`, { credentials: 'include' });
				if (sbomResponse.ok) {
					const sbomData = await sbomResponse.json();
					const componentCount = sbomData.component_count || 0;
					
					artifactsList.push({
						type: 'sbom',
						name: 'Software Bill of Materials (SBOM)',
						count: componentCount,
						icon: Package,
						color: 'var(--success)',
						download_url: `/api/sboms/${runData.sbom_id}/download`,
						raw_data: sbomData
					});
				}
			} catch (e) {
				console.error('Failed to load SBOM:', e);
			}
		}

		// Load secrets info
		if (runData.secret_id) {
			try {
				const secretsResponse = await fetch(`/api/runs/${runId}/secrets`, { credentials: 'include' });
				if (secretsResponse.ok) {
					const secretsData = await secretsResponse.json();
					const secretCount = secretsData.finding_count || 0;
					
					artifactsList.push({
						type: 'secrets',
						name: 'Secret Scan Results',
						count: secretCount,
						icon: Shield,
						color: secretCount > 0 ? 'var(--warning)' : 'var(--success)',
						view_url: `/api/runs/${runId}/secrets`,
						raw_data: secretsData
					});
				}
			} catch (e) {
				console.error('Failed to load secrets:', e);
			}
		}

		// Load manifests info (if available)
		try {
			const manifestsResponse = await fetch(`/api/manifests?run_id=${runId}`, { credentials: 'include' });
			if (manifestsResponse.ok) {
				const manifestsData = await manifestsResponse.json();
				const manifestCount = manifestsData.manifests?.length || 0;
				
				if (manifestCount > 0) {
					artifactsList.push({
						type: 'manifests',
						name: 'Dependency Manifests',
						count: manifestCount,
						icon: FileCode,
						color: 'var(--accent)',
						raw_data: manifestsData.manifests
					});
				}
			}
		} catch (e) {
			// Manifests might not be available for older runs
			console.log('No manifests found for this run');
		}

		artifacts = artifactsList;
	};

	const refreshArtifactData = async (artifact: Artifact) => {
		const runId = $page.params.id;
		if (!runId) {
			return artifact.raw_data;
		}

		if (artifact.type === 'sbom' && run?.sbom_id) {
			const sbomResponse = await fetch(`/api/sboms/${run.sbom_id}`, { credentials: 'include' });
			if (sbomResponse.ok) {
				const sbomData = await sbomResponse.json();
				artifacts = artifacts.map((item) =>
					item.type === 'sbom'
						? { ...item, count: sbomData.component_count || 0, raw_data: sbomData }
						: item
				);
				return sbomData;
			}
		}

		if (artifact.type === 'secrets') {
			const secretsResponse = await fetch(`/api/runs/${runId}/secrets`, { credentials: 'include' });
			if (secretsResponse.ok) {
				const secretsData = await secretsResponse.json();
				artifacts = artifacts.map((item) =>
					item.type === 'secrets'
						? { ...item, count: secretsData.finding_count || 0, raw_data: secretsData }
						: item
				);
				return secretsData;
			}
		}

		if (artifact.type === 'manifests') {
			const manifestsResponse = await fetch(`/api/manifests?run_id=${runId}`, { credentials: 'include' });
			if (manifestsResponse.ok) {
				const manifestsData = await manifestsResponse.json();
				const manifestCount = manifestsData.manifests?.length || 0;
				artifacts = artifacts.map((item) =>
					item.type === 'manifests'
						? { ...item, count: manifestCount, raw_data: manifestsData.manifests }
						: item
				);
				return manifestsData.manifests;
			}
		}

		return artifact.raw_data;
	};

	const showRaw = async (artifact: Artifact) => {
		rawDialogTitle = artifact.name;
		rawDialogLoading = true;
		rawDialogData = '';
		showRawDialog = true;

		try {
			const latestData = await refreshArtifactData(artifact);
			if (latestData === undefined) {
				rawDialogData = JSON.stringify(artifact.raw_data, null, 2);
			} else {
				rawDialogData = JSON.stringify(latestData, null, 2);
			}
		} catch (e) {
			rawDialogData = JSON.stringify(artifact.raw_data, null, 2);
		} finally {
			rawDialogLoading = false;
		}
	};

	const connectSSE = () => {
		const id = $page.params.id;
		if (!id || !browser) return;

		// Try to connect to SSE endpoint for real-time updates
		// Note: This assumes runner SSE is available at /api/runs/{id}/stream
		// If not available, fall back to polling
		try {
			eventSource = new EventSource(`/api/runs/${id}/stream`, { withCredentials: true });

			eventSource.addEventListener('status', (event) => {
				try {
					const data = JSON.parse(event.data);
					if (run && data.status !== run.status) {
						// Status changed - update run and load artifacts
						run.status = data.status;
						lastStatus = data.status;

						// If SSE includes error message (e.g., from K8s failure), capture it
						if (data.error) run.error = data.error;

						// If SSE includes artifact IDs, update them immediately
						if (data.sbom_id) run.sbom_id = data.sbom_id;
						if (data.secret_id) run.secret_id = data.secret_id;
						if (data.commit_hash) run.commit_sha = data.commit_hash;

						// Update timestamps from SSE data
						if (data.started_at) run.started_at = data.started_at;
						if (data.finished_at) run.finished_at = data.finished_at;

						// Load artifacts with the new IDs
						// The manifest count is included in the SSE event, frontend will fetch details
						if (run.status === 'SUCCEEDED' || run.status === 'FAILED') {
							// Reload run to get latest timestamps
							loadRun(false).then(() => {
								if (run) loadArtifacts(id, run);
							});
							loadK8sEvents(id);
						}
					}
				} catch (e) {
					console.error('Failed to parse status event:', e);
				}
			});

			eventSource.addEventListener('log', (event) => {
				// Collect logs for the timeline
				try {
					const data = JSON.parse(event.data);
					runLogs = [...runLogs, { line: data.line, ts: data.ts }];
				} catch (e) {
					console.error('Failed to parse log event:', e);
				}
			});

			eventSource.addEventListener('k8s', (event) => {
				try {
					const data = JSON.parse(event.data);
					k8sEvents = data.events || [];
					podStatus = data.pod_status || null;
				} catch (e) {
					console.error('Failed to parse k8s event:', e);
				}
			});

			eventSource.onerror = () => {
				// SSE not available or connection failed, close and fall back to polling
				if (eventSource) {
					eventSource.close();
					eventSource = null;
				}
				if (run && (run.status === 'QUEUED' || run.status === 'RUNNING')) {
					setupPolling();
					startK8sPolling();
				}
			};
		} catch (e) {
			console.log('SSE not available, using polling');
			if (run && (run.status === 'QUEUED' || run.status === 'RUNNING')) {
				setupPolling();
				startK8sPolling();
			}
		}
	};

	const setupPolling = () => {
		// Fallback: poll every 3 seconds if run is active
		const interval = setInterval(() => {
			if (run && (run.status === 'QUEUED' || run.status === 'RUNNING')) {
				loadRun(false); // Don't reload artifacts on every poll
			} else {
				// Run completed, stop polling
				clearInterval(interval);
			}
		}, 3000);

		return () => clearInterval(interval);
	};

	let eventsInterval: ReturnType<typeof setInterval> | null = null;
	const startK8sPolling = () => {
		if (k8sPollingDisabled) {
			return;
		}
		if (eventsInterval) {
			clearInterval(eventsInterval);
		}
		eventsInterval = setInterval(() => {
			const id = $page.params.id;
			if (id && run?.k8s_job_name) {
				loadK8sEvents(id);
			}
		}, 5000);
	};

	onMount(async () => {
		if (!browser) return;

		const id = $page.params.id;
		if (!id) return;

		// Initial load - wait for it to complete before connecting SSE
		await loadRun(true);

		// Load K8s events if the run has a K8s job
		if (run?.k8s_job_name) {
			await loadK8sEvents(id);
		}

		// Start ticker for live duration updates
		ticker = setInterval(() => { now = Date.now(); }, 1000);

		// Try SSE for both running and completed runs to capture K8s events and logs
		connectSSE();
	});

	onDestroy(() => {
		if (eventSource) {
			eventSource.close();
			eventSource = null;
		}
		if (eventsInterval) {
			clearInterval(eventsInterval);
			eventsInterval = null;
		}
		if (ticker) {
			clearInterval(ticker);
			ticker = null;
		}
	});

	const getStatusIcon = (status: string) => {
		switch (status) {
			case 'QUEUED':
				return Clock;
			case 'RUNNING':
				return Loader2;
			case 'SUCCEEDED':
				return CheckCircle;
			case 'FAILED':
			case 'CANCELLED':
				return XCircle;
			default:
				return Clock;
		}
	};

	const getStatusColor = (status: string) => {
		switch (status) {
			case 'QUEUED':
				return 'var(--text-secondary)';
			case 'RUNNING':
				return 'var(--info)';
			case 'SUCCEEDED':
				return 'var(--success)';
			case 'FAILED':
				return 'var(--error)';
			case 'CANCELLED':
				return 'var(--warning)';
			default:
				return 'var(--text-secondary)';
		}
	};

	const formatDate = (dateStr?: string) => {
		if (!dateStr) return '-';
		return new Date(dateStr).toLocaleString('fr-FR', {
			day: '2-digit',
			month: '2-digit',
			year: 'numeric',
			hour: '2-digit',
			minute: '2-digit',
			second: '2-digit'
		});
	};

	const formatDuration = (start?: string, end?: string) => {
		if (!start) return '-';
		const startDate = new Date(start);
		const endDate = end ? new Date(end) : new Date(now);
		const diff = endDate.getTime() - startDate.getTime();

		if (diff < 1000) return '<1s';
		if (diff < 60000) return `${Math.floor(diff / 1000)}s`;
		if (diff < 3600000) return `${Math.floor(diff / 60000)}m ${Math.floor((diff % 60000) / 1000)}s`;
		return `${Math.floor(diff / 3600000)}h ${Math.floor((diff % 3600000) / 60000)}m`;
	};

	const goBack = () => {
		if (browser) history.back();
	};

	const getCommitUrl = (cloneUrl: string, provider: string, sha: string): string | null => {
		if (!cloneUrl || !sha) return null;
		// Strip .git suffix and build commit URL
		let baseUrl = cloneUrl.replace(/\.git$/, '');
		if (provider === 'gitlab') {
			return `${baseUrl}/-/commit/${sha}`;
		}
		// GitHub, Gitea, Forgejo all use /commit/{sha}
		return `${baseUrl}/commit/${sha}`;
	};

	const getInternalRepoUrl = (run: Run): string | null => {
		if (run.repo_id) {
			const params = new URLSearchParams({ repo_id: run.repo_id });
			if (run.provider_id) params.set('provider_id', run.provider_id);
			return `/app/providers/repo?${params}`;
		}
		const repoPath = run.repo_path || extractRepoPath(run.clone_url);
		if (!repoPath) return null;
		const provider = run.provider?.toLowerCase() || 'github';
		const params = new URLSearchParams({ provider, path: repoPath });
		if (run.base_url) params.set('base_url', run.base_url);
		if (run.provider_id) params.set('provider_id', run.provider_id);
		return `/app/providers/repo?${params}`;
	};

	const extractRepoPath = (cloneUrl: string): string => {
		if (!cloneUrl) return '';
		let path = cloneUrl.replace(/^https?:\/\//, '').replace(/^git@[^:]+:/, '');
		const slashIdx = path.indexOf('/');
		if (slashIdx !== -1) path = path.substring(slashIdx + 1);
		return path.replace(/\.git$/, '');
	};
</script>

<svelte:head>
	<title>Run {$page.params.id?.substring(0, 8)} • Spam Monitor</title>
</svelte:head>

<div class="space-y-6">
	<button
		type="button"
		class="inline-flex items-center gap-2 text-sm text-[var(--text-secondary)] transition hover:text-[var(--accent)]"
		onclick={goBack}
	>
		<ArrowLeft class="h-4 w-4" />
		Back
	</button>

	{#if loading}
		<div class="flex items-center justify-center py-20">
			<Loader2 class="h-8 w-8 animate-spin text-[var(--accent)]" />
		</div>
	{:else if error}
		<div class="panel-surface p-8 text-center">
			<XCircle class="mx-auto h-12 w-12 text-[var(--error)]" />
			<p class="mt-4 text-[var(--text-secondary)]">{error}</p>
		</div>
	{:else if run}
		{@const StatusIcon = getStatusIcon(run.status)}

		<article class="panel-surface space-y-6 px-6 py-8 sm:px-10">
			<div class="flex items-start justify-between gap-4">
				<div class="flex-1">
					<div class="flex items-center gap-3">
						<StatusIcon
							class="h-6 w-6 {run.status === 'RUNNING' ? 'animate-spin' : ''}"
							style="color: {getStatusColor(run.status)}"
						/>
						<h1 class="text-2xl font-semibold text-[var(--text-bright)]">
							Run {run.id.substring(0, 8)}
						</h1>
						<span
							class="rounded-full px-3 py-1 text-xs font-semibold uppercase"
							style="color: {getStatusColor(run.status)}; background: {getStatusColor(run.status)}20;"
						>
							{run.status}
						</span>
					</div>
					{#if run.error}
						<div class="mt-4 flex items-start gap-3 rounded-xl border border-[var(--error)]/30 bg-[var(--error)]/10 px-4 py-3">
							<XCircle class="mt-0.5 h-5 w-5 text-[var(--error)]" />
							<div>
								<p class="text-xs uppercase tracking-wider text-[var(--error)]">Error</p>
								<p class="mt-1 text-sm text-[var(--text-secondary)] break-words">{run.error}</p>
							</div>
						</div>
					{/if}
					<div class="mt-3 flex flex-wrap items-center gap-3">
						<a
							href={getInternalRepoUrl(run) || '#'}
							class="inline-flex items-center gap-2 rounded-lg border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-3 py-1.5 text-sm text-[var(--text-secondary)] transition hover:border-[var(--accent)]/40 hover:text-[var(--accent)]"
						>
							<GitBranch class="h-4 w-4" />
							{run.repo_path || run.clone_url}
							{#if run.ref}
								<span class="rounded bg-[var(--hover-bg)] px-1.5 py-0.5 text-xs font-medium text-[var(--text-muted)]">{run.ref}</span>
							{/if}
						</a>
						{#if run.commit_sha}
							{@const commitUrl = getCommitUrl(run.clone_url, run.provider, run.commit_sha)}
							<a
								href={commitUrl || '#'}
								target="_blank"
								rel="noopener noreferrer"
								class="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-3 py-1.5 font-mono text-xs text-[var(--text-secondary)] transition hover:border-[var(--accent)]/40 hover:text-[var(--accent)]"
								title={run.commit_sha}
							>
								<GitCommit class="h-4 w-4" />
								{run.commit_sha.substring(0, 7)}
								<ExternalLink class="h-3 w-3 opacity-50" />
							</a>
						{/if}
					</div>
				</div>
			</div>

			{#if run.status === 'SUCCEEDED' || run.status === 'FAILED'}
				{@const sbomArtifact = artifacts.find(a => a.type === 'sbom')}
				{@const secretsArtifact = artifacts.find(a => a.type === 'secrets')}
				{@const manifestsArtifact = artifacts.find(a => a.type === 'manifests')}
				<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
					<button
						type="button"
						class="metric-card rounded-2xl p-4 sm:p-6 w-full text-left cursor-pointer transition hover:ring-1 hover:ring-[var(--accent)]/40"
						onclick={openDependenciesDialog}
					>
						<div class="flex items-center justify-between">
							<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">Components</p>
							<Package class="h-5 w-5 text-[var(--success)]" />
						</div>
						<p class="mt-2 text-3xl font-bold text-[var(--text-bright)]">
							{sbomArtifact?.count ?? '-'}
						</p>
						<p class="mt-1 text-xs text-[var(--text-muted)]">from SBOM analysis</p>
					</button>
					<button
						type="button"
						class="metric-card rounded-2xl p-4 sm:p-6 w-full text-left cursor-pointer transition hover:ring-1 hover:ring-[var(--warning)]/40"
						onclick={openSecretsDialog}
					>
						<div class="flex items-center justify-between">
							<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">Secrets Found</p>
							<Shield class="h-5 w-5" style="color: {secretsArtifact && secretsArtifact.count > 0 ? 'var(--warning)' : 'var(--success)'}" />
						</div>
						<p class="mt-2 text-3xl font-bold" style="color: {secretsArtifact && secretsArtifact.count > 0 ? 'var(--warning)' : 'var(--text-bright)'}">
							{secretsArtifact?.count ?? '-'}
						</p>
						<p class="mt-1 text-xs text-[var(--text-muted)]">from secret detection scan</p>
					</button>
					<button
						type="button"
						class="metric-card rounded-2xl p-4 sm:p-6 w-full text-left cursor-pointer transition hover:ring-1 hover:ring-[var(--accent)]/40"
						onclick={openDependenciesDialog}
					>
						<div class="flex items-center justify-between">
							<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">Manifests</p>
							<FileCode class="h-5 w-5 text-[var(--accent)]" />
						</div>
						<p class="mt-2 text-3xl font-bold text-[var(--text-bright)]">
							{manifestsArtifact?.count ?? '-'}
						</p>
						<p class="mt-1 text-xs text-[var(--text-muted)]">dependency files detected</p>
					</button>
				</div>
			{/if}

			<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
				<div class="metric-card rounded-2xl p-4 sm:p-6">
					<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">Provider</p>
					{#if run.base_url}
						<a
							href="/app/providers{run.provider_id ? `?tab=${run.provider_id}` : ''}"
							class="mt-1 inline-flex items-center gap-1.5 text-sm font-semibold text-[var(--text-bright)] transition hover:text-[var(--accent)]"
						>
							{run.base_url.replace(/^https?:\/\//, '')}
						</a>
						<p class="text-xs capitalize text-[var(--text-muted)]">{run.provider || ''}</p>
					{:else}
						<a
							href="/app/providers{run.provider ? `?tab=${run.provider}` : ''}"
							class="mt-1 inline-flex items-center gap-1.5 text-lg font-semibold capitalize text-[var(--text-bright)] transition hover:text-[var(--accent)]"
						>
							{run.provider || '-'}
						</a>
					{/if}
				</div>
				<div class="metric-card rounded-2xl p-4 sm:p-6">
					<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">Duration</p>
					<p class="mt-1 font-mono text-lg font-semibold text-[var(--text-bright)]">
						{formatDuration(run.started_at, run.finished_at)}
					</p>
				</div>
				<div class="metric-card rounded-2xl p-4 sm:p-6">
					<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">Created</p>
					<p class="mt-1 text-sm text-[var(--text-bright)]">{formatDate(run.created_at)}</p>
				</div>
				<div class="metric-card rounded-2xl p-4 sm:p-6">
					<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">Finished</p>
					<p class="mt-1 text-sm text-[var(--text-bright)]">{formatDate(run.finished_at)}</p>
				</div>
			</div>

			{#if run.k8s_job_name}
				<div class="text-xs text-[var(--text-muted)]">
					K8s Job: {run.k8s_job_name}
				</div>
			{/if}
		</article>

		<!-- Timeline Section -->
		<article class="panel-surface px-6 py-6 sm:px-10">
			<div class="mb-4 flex items-center justify-between">
				<h2 class="flex items-center gap-2 text-lg font-semibold text-[var(--text-bright)]">
					<Activity class="h-5 w-5 text-[var(--accent)]" />
					Execution Timeline
				</h2>
				<button
					type="button"
					class="text-sm text-[var(--text-secondary)] hover:text-[var(--accent)]"
					onclick={() => { showTimeline = !showTimeline; }}
				>
					{showTimeline ? 'Hide' : 'Show'}
				</button>
			</div>

			{#if showTimeline}
				<RunTimeline
					runId={run.id}
					status={run.status}
					logs={runLogs}
					events={k8sEvents}
					podStatus={podStatus ?? undefined}
					secretCount={artifacts.find(a => a.type === 'secrets')?.count || 0}
					sbomComponentCount={artifacts.find(a => a.type === 'sbom')?.count || 0}
					manifestCount={artifacts.find(a => a.type === 'manifests')?.count || 0}
					commitHash={run.commit_sha || ''}
				/>
			{/if}
		</article>

		<article class="panel-surface space-y-6 px-6 py-8 sm:px-10">
			<!-- Results Section -->
			{#if run.status === 'SUCCEEDED' && artifacts.length > 0}
				<div class="space-y-4">
					<h2 class="text-lg font-semibold text-[var(--text-bright)]">Artifacts</h2>
					
					<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60">
						<table class="min-w-full text-sm">
							<thead class="border-b border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
								<tr class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
									<th class="px-5 py-3 text-left">Provider</th>
									<th class="px-5 py-3 text-left">Type</th>
									<th class="px-5 py-3 text-center">Count</th>
									<th class="px-5 py-3 text-right">Actions</th>
								</tr>
							</thead>
							<tbody class="divide-y divide-[var(--border-color)]/40 bg-[var(--card-bg)]/20">
								{#each artifacts as artifact}
									{@const Icon = artifact.icon}
									<tr class="transition hover:bg-[var(--hover-bg-subtle)]">
										<td class="px-5 py-4">
											<div class="flex items-center gap-2">
												{#if run.provider === 'gitlab'}
													<svg class="h-4 w-4 shrink-0 text-[var(--text-secondary)]" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
														<path d="M23.955 13.587l-1.342-4.135-2.664-8.189a.455.455 0 00-.867 0L16.418 9.45H7.582L4.918 1.263a.455.455 0 00-.867 0L1.386 9.45.044 13.587a.924.924 0 00.331 1.023L12 23.054l11.625-8.443a.92.92 0 00.33-1.024" />
													</svg>
												{:else if run.provider === 'gitea' || run.provider === 'forgejo'}
													<Gitea size={16} />
												{:else}
													<svg class="h-4 w-4 shrink-0 text-[var(--text-secondary)]" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
														<path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
													</svg>
												{/if}
												<div>
													<p class="text-sm font-medium text-[var(--text-bright)]">
														{run.base_url ? run.base_url.replace(/^https?:\/\//, '') : (run.provider || '-')}
													</p>
													<p class="text-xs capitalize text-[var(--text-muted)]">{run.provider || ''}</p>
												</div>
											</div>
										</td>
										<td class="px-5 py-4">
											<div class="flex items-center gap-3">
												<div style="color: {artifact.color}">
													<Icon class="h-5 w-5" />
												</div>
												<div>
													<p class="font-medium text-[var(--text-bright)]">{artifact.name}</p>
													<p class="text-xs text-[var(--text-muted)]">{artifact.type}</p>
												</div>
											</div>
										</td>
										<td class="px-5 py-4 text-center">
											<span 
												class="inline-flex items-center rounded-full px-2.5 py-0.5 text-sm font-semibold"
												style="background: {artifact.color}20; color: {artifact.color}"
											>
												{artifact.count}
												{#if artifact.type === 'sbom'}
													component{artifact.count !== 1 ? 's' : ''}
												{:else if artifact.type === 'secrets'}
													secret{artifact.count !== 1 ? 's' : ''}
												{:else if artifact.type === 'manifests'}
													file{artifact.count !== 1 ? 's' : ''}
												{/if}
											</span>
										</td>
										<td class="px-5 py-4 text-right">
											<div class="flex items-center justify-end gap-2">
												{#if artifact.raw_data}
													<button
														type="button"
														class="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-color)] px-3 py-1.5 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
														onclick={() => showRaw(artifact)}
													>
														<Eye class="h-3.5 w-3.5" />
														View Raw
													</button>
												{/if}
												{#if artifact.download_url}
													<a
														href={artifact.download_url}
														download
														class="inline-flex items-center gap-1.5 rounded-lg border border-[var(--border-color)] px-3 py-1.5 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
													>
														<Download class="h-3.5 w-3.5" />
														Download
													</a>
												{/if}
												{#if artifact.view_url && artifact.type === 'secrets'}
													<a
														href={artifact.view_url}
														target="_blank"
														class="inline-flex items-center gap-1.5 rounded-lg bg-[var(--accent)]/10 px-3 py-1.5 text-xs text-[var(--accent)] transition hover:bg-[var(--accent)]/20"
													>
														<Eye class="h-3.5 w-3.5" />
														View Details
													</a>
												{/if}
											</div>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				</div>
			{/if}

			<p class="text-xs text-[var(--text-muted)]">
				Full ID: {run.id}
			</p>
		</article>
	{/if}
</div>

<SecretsDialog bind:open={secretsDialogOpen} loading={secretsDialogLoading} data={secretsDialogData} />
<DependenciesDialog bind:open={dependenciesDialogOpen} loading={dependenciesDialogLoading} data={dependenciesDialogData} />

<!-- Raw Data Dialog -->
<Dialog bind:open={showRawDialog} showCloseButton={false} onClose={() => {}}>
	<div class="flex flex-col">
		<div class="flex items-center justify-between border-b border-[var(--border-color)] px-6 py-5">
			<h3 class="text-lg font-semibold text-[var(--text-bright)]">{rawDialogTitle}</h3>
			<button
				type="button"
				class="rounded-lg p-1 text-[var(--text-muted)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
				onclick={() => { showRawDialog = false; }}
			>
				<XCircle class="h-5 w-5" />
			</button>
		</div>
		<div class="overflow-auto px-6 py-5" style="max-height: calc(90vh - 80px);">
			{#if rawDialogLoading}
				<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
					<Loader2 class="h-4 w-4 animate-spin" />
					Loading...
				</div>
			{:else}
				<pre class="overflow-x-auto rounded-lg bg-[var(--hover-bg)] p-4 text-xs text-[var(--text-secondary)]"><code>{rawDialogData}</code></pre>
			{/if}
		</div>
	</div>
</Dialog>
