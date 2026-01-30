<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
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

	let runs: Run[] = $state([]);
	let loading = $state(true);
	let error = $state('');
	let totalCount = $state(0);
	let page = $state(1);
	let pageSize = $state(20);

	const loadRuns = async () => {
		loading = true;
		error = '';
		try {
			const response = await fetch(`/api/runs?page=${page}&page_size=${pageSize}`, {
				credentials: 'include'
			});
			if (!response.ok) {
				throw new Error('Failed to load runs');
			}
			const data: RunsResponse = await response.json();
			runs = data.runs;
			totalCount = data.total_count;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load runs';
		} finally {
			loading = false;
		}
	};

	onMount(() => {
		if (!browser) return;
		loadRuns();

		// Refresh every 10 seconds
		const interval = setInterval(loadRuns, 10000);
		return () => clearInterval(interval);
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
				class="flex items-center gap-2 rounded-full border border-[var(--border-color)] px-4 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
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
							<th class="px-5 py-3 text-left">Provider</th>
							<th class="px-5 py-3 text-left">Branch</th>
							<th class="px-5 py-3 text-left">Duration</th>
							<th class="px-5 py-3 text-left">Created</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
						{#each runs as run}
							{@const StatusIcon = getStatusIcon(run.status)}
							<tr class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]" onclick={() => window.location.href = `/app/runs/${run.id}`}>
								<td class="px-5 py-3">
									<span class="flex items-center gap-2" style={`color: ${getStatusColor(run.status)}`}>
										<StatusIcon size={16} class={run.status === 'RUNNING' ? 'animate-spin' : ''} />
										<span class="text-xs font-semibold uppercase">{run.status}</span>
									</span>
								</td>
								<td class="px-5 py-3 font-semibold text-[var(--text-bright)]">
									{run.repo_path || run.clone_url}
								</td>
								<td class="px-5 py-3 capitalize">{run.provider || '-'}</td>
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
							class="rounded-full border border-[var(--border-color)] px-3 py-1 transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
							disabled={page === 1}
							onclick={() => { page--; loadRuns(); }}
						>
							Previous
						</button>
						<button
							type="button"
							class="rounded-full border border-[var(--border-color)] px-3 py-1 transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
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
