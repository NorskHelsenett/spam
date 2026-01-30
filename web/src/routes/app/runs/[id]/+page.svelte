<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { browser } from '$app/environment';
	import { page } from '$app/stores';
	import { ArrowLeft, CheckCircle, XCircle, Clock, Loader2, GitBranch, Package, Shield, FileCode, Eye, Download } from 'lucide-svelte';

	type Run = {
		id: string;
		status: string;
		clone_url: string;
		provider: string;
		repo_path: string;
		ref?: string;
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

	let run: Run | null = $state(null);
	let artifacts: Artifact[] = $state([]);
	let loading = $state(true);
	let error = $state('');
	let showRawDialog = $state(false);
	let rawDialogTitle = $state('');
	let rawDialogData = $state('');
	let eventSource: EventSource | null = null;
	let lastStatus = $state('');

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

	const loadArtifacts = async (runId: string, runData: Run) => {
		const artifactsList: Artifact[] = [];

		// Load SBOM info
		if (runData.sbom_id) {
			try {
				const sbomResponse = await fetch(`/api/sboms/${runData.sbom_id}`, { credentials: 'include' });
				if (sbomResponse.ok) {
					const sbomData = await sbomResponse.json();
					const componentCount = sbomData.components?.length || 0;
					
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
					const secretCount = Array.isArray(secretsData) ? secretsData.length : 0;
					
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

	const showRaw = (artifact: Artifact) => {
		rawDialogTitle = artifact.name;
		rawDialogData = JSON.stringify(artifact.raw_data, null, 2);
		showRawDialog = true;
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
						
						// If SSE includes artifact IDs, update them immediately
						if (data.sbom_id) run.sbom_id = data.sbom_id;
						if (data.secret_id) run.secret_id = data.secret_id;
						
						// Load artifacts with the new IDs
						// The manifest count is included in the SSE event, frontend will fetch details
						if (run.status === 'SUCCEEDED' || run.status === 'FAILED') {
							loadArtifacts(id, run);
						}
					}
				} catch (e) {
					console.error('Failed to parse status event:', e);
				}
			});

			eventSource.addEventListener('log', () => {
				// Log events received (could display in UI later)
			});

			eventSource.onerror = () => {
				// SSE not available or connection failed, close and fall back to polling
				if (eventSource) {
					eventSource.close();
					eventSource = null;
				}
				setupPolling();
			};
		} catch (e) {
			console.log('SSE not available, using polling');
			setupPolling();
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

	onMount(() => {
		if (!browser) return;
		
		// Initial load
		loadRun(true);

		// Try SSE first, fall back to polling if not available
		connectSSE();
	});

	onDestroy(() => {
		if (eventSource) {
			eventSource.close();
			eventSource = null;
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
		return new Date(dateStr).toLocaleString();
	};

	const formatDuration = (start?: string, end?: string) => {
		if (!start) return '-';
		const startDate = new Date(start);
		const endDate = end ? new Date(end) : new Date();
		const diff = endDate.getTime() - startDate.getTime();

		if (diff < 1000) return '<1s';
		if (diff < 60000) return `${Math.floor(diff / 1000)}s`;
		if (diff < 3600000) return `${Math.floor(diff / 60000)}m ${Math.floor((diff % 60000) / 1000)}s`;
		return `${Math.floor(diff / 3600000)}h ${Math.floor((diff % 3600000) / 60000)}m`;
	};

	const goBack = () => {
		if (browser) history.back();
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

		<section class="panel-surface space-y-6 px-6 py-8 sm:px-10">
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
					<p class="mt-2 flex items-center gap-2 text-[var(--text-secondary)]">
						<GitBranch class="h-4 w-4" />
						{run.repo_path || run.clone_url}
						{#if run.ref}
							<span class="text-[var(--text-muted)]">({run.ref})</span>
						{/if}
					</p>
				</div>
			</div>

			<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
				<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
					<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">Provider</p>
					<p class="mt-1 text-lg font-semibold capitalize text-[var(--text-bright)]">{run.provider || '-'}</p>
				</div>
				<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
					<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">Duration</p>
					<p class="mt-1 font-mono text-lg font-semibold text-[var(--text-bright)]">
						{formatDuration(run.started_at, run.finished_at)}
					</p>
				</div>
				<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
					<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">Created</p>
					<p class="mt-1 text-sm text-[var(--text-bright)]">{formatDate(run.created_at)}</p>
				</div>
				<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
					<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">Finished</p>
					<p class="mt-1 text-sm text-[var(--text-bright)]">{formatDate(run.finished_at)}</p>
				</div>
			</div>

			{#if run.error}
				<div class="rounded-xl border border-[var(--error)]/30 bg-[var(--error)]/10 p-4">
					<p class="text-xs uppercase tracking-wider text-[var(--error)]">Error</p>
					<p class="mt-2 text-sm text-[var(--text-secondary)]">{run.error}</p>
				</div>
			{/if}

			{#if run.k8s_job_name}
				<div class="text-xs text-[var(--text-muted)]">
					K8s Job: {run.k8s_job_name}
				</div>
			{/if}

			<!-- Results Section -->
			{#if run.status === 'SUCCEEDED' && artifacts.length > 0}
				<div class="space-y-4">
					<h2 class="text-lg font-semibold text-[var(--text-bright)]">Artifacts</h2>
					
					<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60">
						<table class="min-w-full text-sm">
							<thead class="border-b border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
								<tr class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
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
		</section>
	{/if}
</div>

<!-- Raw Data Dialog -->
{#if showRawDialog}
	<div 
		class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" 
		onclick={() => { showRawDialog = false; }}
		role="button"
		tabindex="0"
		aria-label="Close dialog"
		onkeydown={(e) => { if (e.key === 'Escape') showRawDialog = false; }}
	>
		<div 
			class="max-h-[90vh] w-full max-w-4xl overflow-hidden rounded-2xl border border-[var(--border-color)] bg-[var(--panel-bg)] shadow-2xl" 
			role="dialog" 
			aria-modal="true"
			tabindex="-1"
			onclick={(e) => e.stopPropagation()}
			onkeydown={(e) => e.stopPropagation()}
		>
			<div class="flex items-center justify-between border-b border-[var(--border-color)] p-6">
				<h3 class="text-lg font-semibold text-[var(--text-bright)]">{rawDialogTitle}</h3>
				<button
					type="button"
					class="rounded-lg p-1 text-[var(--text-muted)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
					onclick={() => { showRawDialog = false; }}
				>
					<XCircle class="h-5 w-5" />
				</button>
			</div>
			<div class="overflow-auto p-6" style="max-height: calc(90vh - 80px);">
				<pre class="overflow-x-auto rounded-lg bg-[var(--hover-bg)] p-4 text-xs text-[var(--text-secondary)]"><code>{rawDialogData}</code></pre>
			</div>
		</div>
	</div>
{/if}