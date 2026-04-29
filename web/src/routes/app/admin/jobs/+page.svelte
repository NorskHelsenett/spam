<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { Layers, RefreshCw, Cpu, Database, Container, AlertCircle } from 'lucide-svelte';

	type JobCount = {
		type: string;
		running: number;
		queued: number;
		retry: number;
		failed: number;
		succeeded: number;
	};
	type RunningJob = {
		id: string;
		type: string;
		attempts: number;
		max_attempts: number;
		locked_at: string | null;
		locked_by: string;
		age_seconds: number;
	};
	type Pool = {
		name: string;
		label: string;
		description: string;
		types: string[];
		counts: JobCount[];
		running: RunningJob[];
	};
	type Response = {
		fetched_at: string;
		pools: Pool[];
	};

	let data = $state<Response | null>(null);
	let loading = $state(true);
	let error = $state('');
	// Loading flag for poll cycles other than the first; lets the UI
	// keep the previous data on screen while a refresh is in flight
	// (no jarring flash).
	let refreshing = $state(false);
	let lastUpdated = $state<Date | null>(null);

	// Poll cadence: 3s. Counts move quickly when the queue is active;
	// any longer than this and "what's running right now" gets stale.
	const POLL_INTERVAL_MS = 3000;
	let pollTimer: ReturnType<typeof setInterval> | null = null;

	const fetchJobs = async (initial = false) => {
		if (initial) loading = true;
		else refreshing = true;
		try {
			const res = await fetch('/api/admin/jobs', { credentials: 'include' });
			if (!res.ok) {
				if (res.status === 403) error = 'Admin access required.';
				else error = `Failed to load (${res.status})`;
				return;
			}
			data = (await res.json()) as Response;
			lastUpdated = new Date();
			error = '';
		} catch {
			error = 'Network error.';
		} finally {
			loading = false;
			refreshing = false;
		}
	};

	onMount(() => {
		fetchJobs(true);
		pollTimer = setInterval(() => fetchJobs(false), POLL_INTERVAL_MS);
	});
	onDestroy(() => {
		if (pollTimer) clearInterval(pollTimer);
	});

	const poolIcon = (name: string) => {
		switch (name) {
			case 'main':
				return Cpu;
			case 'vuln-meta':
				return Database;
			case 'image-scan':
				return Container;
			default:
				return Layers;
		}
	};

	const poolTotalRunning = (p: Pool) => p.counts.reduce((a, c) => a + c.running, 0);
	const poolTotalQueued = (p: Pool) => p.counts.reduce((a, c) => a + c.queued + c.retry, 0);
	const poolTotalFailed = (p: Pool) => p.counts.reduce((a, c) => a + c.failed, 0);

	const fmt = (n: number) => n.toLocaleString('en-US').replace(/,/g, ' ');

	const fmtAge = (s: number) => {
		if (s < 60) return `${s}s`;
		if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`;
		const h = Math.floor(s / 3600);
		const m = Math.floor((s % 3600) / 60);
		return `${h}h ${m}m`;
	};

	const fmtRelative = (d: Date | null) => {
		if (!d) return '';
		const diff = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
		if (diff < 5) return 'just now';
		if (diff < 60) return `${diff}s ago`;
		return `${Math.floor(diff / 60)}m ago`;
	};
</script>

<svelte:head>
	<title>Admin · Jobs — Spam Monitor</title>
</svelte:head>

<div class="space-y-4">
	<article class="panel-surface space-y-2 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex items-start justify-between gap-4">
			<div class="flex items-center gap-3">
				<Layers class="h-10 w-10 flex-shrink-0 text-[var(--accent)]" />
				<div>
					<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Jobs</h1>
					<p class="text-sm text-[var(--text-tertiary)]">
						Live queue across all worker pools. Updates every {POLL_INTERVAL_MS / 1000}s.
					</p>
				</div>
			</div>
			<div class="flex items-center gap-2 text-xs text-[var(--text-tertiary)]">
				{#if refreshing}
					<RefreshCw class="h-3 w-3 animate-spin" />
				{/if}
				{#if lastUpdated}
					<span>Updated {fmtRelative(lastUpdated)}</span>
				{/if}
			</div>
		</header>
	</article>

	{#if loading}
		<div class="flex items-center justify-center py-20">
			<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
		</div>
	{:else if error}
		<div class="rounded-2xl border border-[var(--red)]/30 bg-[var(--red)]/10 px-4 py-3 text-sm text-[var(--red)]">{error}</div>
	{:else if data}
		<div class="grid gap-4 lg:grid-cols-3">
			{#each data.pools as pool (pool.name)}
				{@const Icon = poolIcon(pool.name)}
				{@const totalRunning = poolTotalRunning(pool)}
				{@const totalQueued = poolTotalQueued(pool)}
				{@const totalFailed = poolTotalFailed(pool)}
				<section class="panel-surface flex flex-col gap-4 px-6 py-6">
					<header class="space-y-1">
						<div class="flex items-center gap-2">
							<Icon class="h-5 w-5 flex-shrink-0 text-[var(--accent)]" />
							<h2 class="text-base font-semibold text-[var(--text-bright)]">{pool.label}</h2>
						</div>
						<p class="text-xs leading-snug text-[var(--text-tertiary)]">{pool.description}</p>
					</header>

					<!-- Pool totals -->
					<div class="grid grid-cols-3 gap-2">
						<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-3 py-2">
							<p class="text-[0.6rem] uppercase tracking-[0.2em] text-[var(--text-muted)]">Running</p>
							<p class="mt-1 text-xl font-semibold tabular-nums text-[var(--text-bright)]">{fmt(totalRunning)}</p>
						</div>
						<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-3 py-2">
							<p class="text-[0.6rem] uppercase tracking-[0.2em] text-[var(--text-muted)]">Queued</p>
							<p class="mt-1 text-xl font-semibold tabular-nums text-[var(--text-bright)]">{fmt(totalQueued)}</p>
						</div>
						<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-3 py-2">
							<p class="text-[0.6rem] uppercase tracking-[0.2em] text-[var(--text-muted)]">Failed</p>
							<p class="mt-1 text-xl font-semibold tabular-nums {totalFailed > 0 ? 'text-red-400' : 'text-[var(--text-bright)]'}">{fmt(totalFailed)}</p>
						</div>
					</div>

					<!-- Per-type counts -->
					<div class="overflow-hidden rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
						<table class="min-w-full text-xs">
							<thead class="text-[0.6rem] uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
								<tr>
									<th class="px-3 py-2 text-left">Type</th>
									<th class="px-2 py-2 text-right">Run</th>
									<th class="px-2 py-2 text-right">Queue</th>
									<th class="px-2 py-2 text-right">Retry</th>
									<th class="px-2 py-2 text-right">Fail</th>
									<th class="px-2 py-2 text-right text-[var(--text-muted)]">Done</th>
								</tr>
							</thead>
							<tbody class="divide-y divide-[var(--border-color)]/40">
								{#each pool.counts as c (c.type)}
									<tr class="text-[var(--text-secondary)]">
										<td class="px-3 py-1.5 font-mono text-[10px] text-[var(--text-bright)]">{c.type}</td>
										<td class="px-2 py-1.5 text-right tabular-nums {c.running > 0 ? 'text-[var(--accent)]' : 'text-[var(--text-muted)]'}">{c.running > 0 ? fmt(c.running) : '—'}</td>
										<td class="px-2 py-1.5 text-right tabular-nums {c.queued > 0 ? 'text-[var(--text-bright)]' : 'text-[var(--text-muted)]'}">{c.queued > 0 ? fmt(c.queued) : '—'}</td>
										<td class="px-2 py-1.5 text-right tabular-nums {c.retry > 0 ? 'text-yellow-400' : 'text-[var(--text-muted)]'}">{c.retry > 0 ? fmt(c.retry) : '—'}</td>
										<td class="px-2 py-1.5 text-right tabular-nums {c.failed > 0 ? 'text-red-400' : 'text-[var(--text-muted)]'}">{c.failed > 0 ? fmt(c.failed) : '—'}</td>
										<td class="px-2 py-1.5 text-right tabular-nums text-[var(--text-tertiary)]">{c.succeeded > 0 ? fmt(c.succeeded) : '—'}</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>

					<!-- Currently running -->
					<div>
						<h3 class="mb-2 text-[0.65rem] font-semibold uppercase tracking-[0.18em] text-[var(--text-tertiary)]">Currently running</h3>
						{#if pool.running.length === 0}
							<p class="text-xs text-[var(--text-muted)]">Idle.</p>
						{:else}
							<ul class="space-y-1.5">
								{#each pool.running as job (job.id)}
									<li class="flex items-start justify-between gap-3 rounded-lg border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40 px-3 py-2 text-xs">
										<div class="min-w-0 flex-1 space-y-0.5">
											<div class="flex items-center gap-2">
												<span class="font-mono text-[10px] text-[var(--accent)]">{job.type}</span>
												{#if job.attempts > 1}
													<span class="inline-flex items-center gap-1 rounded-full border border-yellow-500/30 bg-yellow-500/10 px-1.5 py-0 text-[10px] text-yellow-400" title="Retry attempt">
														<AlertCircle class="h-2.5 w-2.5" /> {job.attempts}/{job.max_attempts}
													</span>
												{/if}
											</div>
											<div class="truncate font-mono text-[10px] text-[var(--text-tertiary)]" title={job.id}>{job.id}</div>
											{#if job.locked_by}
												<div class="truncate text-[10px] text-[var(--text-muted)]" title={job.locked_by}>by {job.locked_by}</div>
											{/if}
										</div>
										<span class="shrink-0 self-center font-mono text-[10px] text-[var(--text-muted)] tabular-nums">{fmtAge(job.age_seconds)}</span>
									</li>
								{/each}
							</ul>
						{/if}
					</div>
				</section>
			{/each}
		</div>
	{/if}
</div>
