<script lang="ts">
	import { onDestroy, onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { goto } from '$app/navigation';
	import { Play, CheckCircle, XCircle, Clock, Loader2, RefreshCw } from 'lucide-svelte';

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
	};

	type RunsResponse = {
		runs: Run[];
		total_count: number;
		page: number;
		page_size: number;
	};

	type RunFilter = {
		id: string;
		label: string;
		statuses: string[];
	};

	type SortField = 'provider' | 'duration' | 'created';
	type SortDirection = 'asc' | 'desc';

	const runFilters: RunFilter[] = [
		{ id: 'all', label: 'All', statuses: [] },
		{ id: 'running', label: 'Running', statuses: ['RUNNING'] },
		{ id: 'queued', label: 'Queued', statuses: ['QUEUED'] },
		{ id: 'succeeded', label: 'Succeeded', statuses: ['SUCCEEDED'] },
		{ id: 'error', label: 'Error', statuses: ['FAILED'] }
	];

	let runs: Run[] = $state([]);
	let loading = $state(true);
	let error = $state('');
	let totalCount = $state(0);
	let page = $state(1);
	let pageSize = $state(20);
	let selectedFilter = $state(runFilters[0]);
	let searchInput = $state('');
	let searchTerm = $state('');
	let searchDebounce: ReturnType<typeof setTimeout> | null = null;
	let sortField = $state<SortField>('created');
	let sortDirection = $state<SortDirection>('desc');

	let loadRunsInFlight = false;
	let loadRunsQueued = false;
	let pollTimer: ReturnType<typeof setInterval> | null = null;

	const isActiveRunStatus = (status: string) => status === 'QUEUED' || status === 'RUNNING';

	/** Restart the polling interval based on whether there are active runs. */
	const reschedulePoll = () => {
		if (pollTimer) clearInterval(pollTimer);
		const hasActive = runs.some((r) => isActiveRunStatus(r.status));
		pollTimer = setInterval(loadRuns, hasActive ? 5_000 : 30_000);
	};

	const getStatusQuery = () =>
		selectedFilter.statuses.length > 0 ? `&status=${encodeURIComponent(selectedFilter.statuses.join(','))}` : '';
	const getRepoQuery = () =>
		searchTerm.trim().length > 0 ? `&repo_path=${encodeURIComponent(searchTerm.trim())}` : '';

	const loadRuns = async () => {
		if (loadRunsInFlight) {
			loadRunsQueued = true;
			return;
		}
		loadRunsInFlight = true;
		loading = true;
		error = '';
		try {
			const response = await fetch(
				`/api/runs?page=${page}&page_size=${pageSize}${getStatusQuery()}${getRepoQuery()}`,
				{
				credentials: 'include'
				}
			);
			if (!response.ok) {
				throw new Error('Failed to load runs');
			}
			const data: RunsResponse = await response.json();
			runs = data.runs;
			totalCount = data.total_count;
			reschedulePoll();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load runs';
		} finally {
			loading = false;
			loadRunsInFlight = false;
			if (loadRunsQueued) {
				loadRunsQueued = false;
				loadRuns();
			}
		}
	};

	const setFilter = (filter: RunFilter) => {
		if (selectedFilter.id === filter.id) return;
		selectedFilter = filter;
		page = 1;
		loadRuns();
	};

	const applySearch = () => {
		const next = searchInput.trim();
		if (next === searchTerm) return;
		searchTerm = next;
		page = 1;
		loadRuns();
	};

	const scheduleSearch = () => {
		if (searchDebounce) {
			clearTimeout(searchDebounce);
		}
		searchDebounce = setTimeout(() => {
			searchDebounce = null;
			applySearch();
		}, 300);
	};

	let activeRunStream: EventSource | null = null;

	const startActiveRunStream = () => {
		if (!browser || activeRunStream) return;
		activeRunStream = new EventSource('/api/runs/active/stream', { withCredentials: true });
		activeRunStream.addEventListener('active_runs', (event) => {
			try {
				const active = JSON.parse(event.data) as Array<{ id: string; status: string; error?: string }>;
				const activeById = new Map(active.map((r) => [r.id, r]));
				let needsReload = false;
				runs = runs.map((run) => {
					const update = activeById.get(run.id);
					if (!update || update.status === run.status) return run;
					if (isActiveRunStatus(run.status) && !isActiveRunStatus(update.status)) {
						needsReload = true;
					}
					return { ...run, status: update.status, error: update.error ?? run.error };
				});
				if (needsReload && !loadRunsInFlight) {
					setTimeout(loadRuns, 500);
				}
			} catch {
				// ignore malformed events
			}
		});
	};

	const stopActiveRunStream = () => {
		if (activeRunStream) {
			activeRunStream.close();
			activeRunStream = null;
		}
	};

	onMount(() => {
		if (!browser) return;
		loadRuns();
		startActiveRunStream();
	});

	onDestroy(() => {
		if (searchDebounce) {
			clearTimeout(searchDebounce);
			searchDebounce = null;
		}
		if (pollTimer) {
			clearInterval(pollTimer);
			pollTimer = null;
		}
		stopActiveRunStream();
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
				return XCircle;
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

	const formatDate = (dateStr: string) => {
		const date = new Date(dateStr);
		const now = new Date();
		const diff = now.getTime() - date.getTime();

		if (diff < 60000) return 'Just now';
		if (diff < 3600000) return `${Math.floor(diff / 60000)} min ago`;
		if (diff < 86400000) return `${Math.floor(diff / 3600000)} hours ago`;
		return date.toLocaleDateString();
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

	const durationMs = (run: Run) => {
		if (!run.started_at) return 0;
		const startDate = new Date(run.started_at).getTime();
		const endDate = run.finished_at ? new Date(run.finished_at).getTime() : Date.now();
		return Math.max(0, endDate - startDate);
	};

	const createdMs = (run: Run) => new Date(run.created_at).getTime();

	const sortedRuns = $derived.by(() => {
		const sorted = [...runs];
		sorted.sort((a, b) => {
			let compare = 0;
			if (sortField === 'provider') {
				compare = (a.provider || '').localeCompare(b.provider || '', undefined, { sensitivity: 'base' });
			} else if (sortField === 'duration') {
				compare = durationMs(a) - durationMs(b);
			} else {
				compare = createdMs(a) - createdMs(b);
			}
			return sortDirection === 'asc' ? compare : -compare;
		});
		return sorted;
	});

	const toggleSort = (field: SortField) => {
		if (sortField === field) {
			sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
			return;
		}
		sortField = field;
		sortDirection = field === 'created' ? 'desc' : 'asc';
	};

	const sortIndicator = (field: SortField) => {
		if (sortField !== field) return '';
		return sortDirection === 'asc' ? '↑' : '↓';
	};
</script>

<svelte:head>
	<title>Runs • Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Runs</h1>
				<p class="text-sm text-[var(--text-tertiary)]">SBOM generation and security scanning jobs</p>
			</div>
			<button
				type="button"
				class="btn btn-ghost"
				onclick={loadRuns}
			>
				<RefreshCw size={16} class={loading ? 'animate-spin' : ''} />
				Refresh
			</button>
		</header>

		{#if error}
			<div class="rounded-2xl border border-[var(--error)]/30 bg-[var(--error)]/10 p-4 text-sm text-[var(--error)]">
				{error}
			</div>
		{/if}

		<div class="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
			<div class="flex flex-wrap gap-2">
				{#each runFilters as filter}
					<button
						type="button"
						class={`btn ${selectedFilter.id === filter.id ? 'btn-secondary filter-active' : 'btn-ghost'}`}
						onclick={() => setFilter(filter)}
					>
						{filter.label}
					</button>
				{/each}
			</div>
			<div class="flex items-center gap-2">
				<input
					type="search"
					class="input h-9 w-48 py-2 text-sm"
					placeholder="Search repo..."
					bind:value={searchInput}
					oninput={scheduleSearch}
					onkeydown={(event) => {
						if (event.key === 'Enter') applySearch();
					}}
				/>
			</div>
		</div>

		{#if loading && runs.length === 0}
			<div class="flex items-center justify-center py-12">
				<Loader2 size={24} class="animate-spin text-[var(--accent)]" />
			</div>
		{:else if runs.length === 0}
			<div class="flex flex-col items-center justify-center py-12 text-center">
				<Play size={48} class="mb-4 text-[var(--text-muted)]" />
				<p class="text-lg text-[var(--text-secondary)]">No runs yet</p>
				<p class="mt-1 text-sm text-[var(--text-muted)]">Trigger a scan from a repository page to create a run</p>
			</div>
		{:else}
			<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
				<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
					<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
							<tr>
								<th class="px-5 py-3 text-left">Status</th>
								<th class="px-5 py-3 text-left">Repository</th>
								<th class="px-5 py-3 text-left">
									<button type="button" class="sort-btn" onclick={() => toggleSort('provider')}>
										Provider {sortIndicator('provider')}
									</button>
								</th>
								<th class="px-5 py-3 text-left">Branch</th>
								<th class="px-5 py-3 text-left">
									<button type="button" class="sort-btn" onclick={() => toggleSort('duration')}>
										Duration {sortIndicator('duration')}
									</button>
								</th>
								<th class="px-5 py-3 text-left">
									<button type="button" class="sort-btn" onclick={() => toggleSort('created')}>
										Created {sortIndicator('created')}
									</button>
								</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
							{#each sortedRuns as run}
								{@const StatusIcon = getStatusIcon(run.status)}
					<tr class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]" onclick={() => goto(`/app/runs/${run.id}`)}>
									<td class="px-5 py-3">
									<span class="flex items-center gap-2" style={`color: ${getStatusColor(run.status)}`}>
										<StatusIcon size={16} class={run.status === 'RUNNING' ? 'animate-spin' : ''} />
										<span class="text-xs font-semibold uppercase">{run.status}</span>
									</span>
								</td>
								<td class="px-5 py-3 font-semibold text-[var(--text-bright)]">
									{run.repo_path || run.clone_url}
								</td>
								<td class="px-5 py-3">{run.provider || '-'}</td>
								<td class="px-5 py-3">{run.ref || 'default'}</td>
								<td class="px-5 py-3 font-mono text-xs">
									{formatDuration(run.started_at, run.finished_at)}
								</td>
								<td class="px-5 py-3 text-xs text-[var(--text-tertiary)]">
									{formatDate(run.created_at)}
								</td>
							</tr>
							{#if run.error}
								<tr class="bg-[var(--error)]/5">
									<td colspan="6" class="px-5 py-2 text-xs text-[var(--error)]">
										Error: {run.error}
									</td>
								</tr>
							{/if}
						{/each}
					</tbody>
				</table>
			</div>

			<div class="flex items-center justify-between text-sm text-[var(--text-tertiary)]">
				<span>Showing {runs.length} of {totalCount} runs</span>
				{#if totalCount > pageSize}
					<div class="flex gap-2">
						<button
							type="button"
							class="btn btn-ghost"
							disabled={page === 1}
							onclick={() => { page--; loadRuns(); }}
						>
							Previous
						</button>
						<button
							type="button"
							class="btn btn-ghost"
							disabled={page * pageSize >= totalCount}
							onclick={() => { page++; loadRuns(); }}
						>
							Next
						</button>
					</div>
				{/if}
			</div>
		{/if}
	</section>
</div>

<style>
	.filter-active {
		border-color: color-mix(in srgb, var(--accent) 45%, var(--border-color));
		background: color-mix(in srgb, var(--accent) 16%, transparent);
		color: var(--text-bright);
	}

	.sort-btn {
		display: inline-flex;
		align-items: center;
		gap: 0.3rem;
		color: inherit;
		font: inherit;
		background: transparent;
		border: none;
		padding: 0;
	}

	.sort-btn:hover {
		color: var(--text-secondary);
	}
</style>
