<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { page } from '$app/stores';
	import { ArrowLeft, CheckCircle, XCircle, Clock, Loader2, RefreshCw, GitBranch } from 'lucide-svelte';

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

	let run: Run | null = $state(null);
	let loading = $state(true);
	let error = $state('');

	const loadRun = async () => {
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
			run = await response.json();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load run';
		} finally {
			loading = false;
		}
	};

	onMount(() => {
		if (!browser) return;
		loadRun();

		// Refresh every 3 seconds if run is active
		const interval = setInterval(() => {
			if (run && (run.status === 'QUEUED' || run.status === 'RUNNING')) {
				loadRun();
			}
		}, 3000);

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
				<div>
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
				<button
					type="button"
					class="flex items-center gap-2 rounded-full border border-[var(--border-color)] px-4 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)]"
					onclick={loadRun}
				>
					<RefreshCw size={16} class={loading ? 'animate-spin' : ''} />
					Refresh
				</button>
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
			{#if run.status === 'SUCCEEDED' && (run.sbom_id || run.secret_id)}
				<div class="space-y-4">
					<h2 class="text-lg font-semibold text-[var(--text-bright)]">Results</h2>
					
					<div class="grid gap-4 sm:grid-cols-2">
						{#if run.sbom_id}
							<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
								<div class="flex items-center justify-between">
									<div>
										<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">SBOM</p>
										<p class="mt-1 text-sm text-[var(--text-secondary)]">Software Bill of Materials</p>
									</div>
									<CheckCircle class="h-8 w-8 text-[var(--success)]" />
								</div>
								<div class="mt-3">
									<a
										href="/api/sboms/{run.sbom_id}/download"
										download
										class="inline-flex items-center gap-2 rounded-lg bg-[var(--accent)]/10 px-3 py-1.5 text-sm text-[var(--accent)] transition hover:bg-[var(--accent)]/20"
									>
										Download SBOM
									</a>
								</div>
							</div>
						{/if}

						{#if run.secret_id}
							<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
								<div class="flex items-center justify-between">
									<div>
										<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">Secret Scan</p>
										<p class="mt-1 text-sm text-[var(--text-secondary)]">Gitleaks Results</p>
									</div>
									<CheckCircle class="h-8 w-8 text-[var(--success)]" />
								</div>
								<div class="mt-3">
									<a
										href="/api/runs/{run.id}/secrets"
										class="inline-flex items-center gap-2 rounded-lg bg-[var(--accent)]/10 px-3 py-1.5 text-sm text-[var(--accent)] transition hover:bg-[var(--accent)]/20"
									>
										View Secrets
									</a>
								</div>
							</div>
						{/if}
					</div>
				</div>
			{/if}

			<p class="text-xs text-[var(--text-muted)]">
				Full ID: {run.id}
			</p>
		</section>
	{/if}
</div>
