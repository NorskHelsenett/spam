<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { Layers, RefreshCw, Cpu, Database, Container, AlertCircle, Rss, BookOpen } from 'lucide-svelte';

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

	// Result payload written by the FETCH_KEV / FETCH_EPSS workers.
	// Two shapes: while running, EPSS streams `{status: "ingesting",
	// rows_written}`; after success, both feeds set
	// `{status: "ingested", rows}`. KEV stays empty mid-flight (small
	// payload, ingest is fast enough that progress reporting would
	// add noise).
	type FeedResult = {
		status?: string;
		rows?: number;
		rows_written?: number;
	};
	type FeedStatus = {
		feed: 'kev' | 'epss';
		job_id?: string;
		status?: string;
		created_at?: string | null;
		started_at?: string | null;
		finished_at?: string | null;
		error?: string;
		result?: FeedResult;
		next_scheduled_at?: string | null;
	};
	type FeedsResponse = {
		fetched_at: string;
		feeds: FeedStatus[];
	};

	type MatViewStatus = {
		name: string;
		populated: boolean;
		refreshed_at: string | null;
	};
	type MatViewsResponse = {
		views: MatViewStatus[];
	};

	let data = $state<Response | null>(null);
	let feeds = $state<FeedStatus[]>([]);
	let matviews = $state<MatViewStatus[]>([]);
	let loading = $state(true);
	let error = $state('');
	// Loading flag for poll cycles other than the first; lets the UI
	// keep the previous data on screen while a refresh is in flight
	// (no jarring flash).
	let refreshing = $state(false);
	let lastUpdated = $state<Date | null>(null);
	// Per-feed manual-trigger state — disables the button between
	// click and the next poll cycle so a user can't double-fire while
	// the optimistic state is in flight.
	let triggering = $state<Record<string, boolean>>({ kev: false, epss: false });

	// Poll cadence: 3s. Counts move quickly when the queue is active;
	// any longer than this and "what's running right now" gets stale.
	const POLL_INTERVAL_MS = 3000;
	let pollTimer: ReturnType<typeof setInterval> | null = null;

	const fetchJobs = async (initial = false) => {
		if (initial) loading = true;
		else refreshing = true;
		try {
			const [jobsRes, feedsRes, viewsRes] = await Promise.all([
				fetch('/api/admin/jobs', { credentials: 'include' }),
				fetch('/api/admin/feeds/status', { credentials: 'include' }),
				fetch('/api/admin/views/status', { credentials: 'include' })
			]);
			if (!jobsRes.ok) {
				if (jobsRes.status === 403) error = 'Admin access required.';
				else error = `Failed to load (${jobsRes.status})`;
				return;
			}
			data = (await jobsRes.json()) as Response;
			if (feedsRes.ok) {
				const fr = (await feedsRes.json()) as FeedsResponse;
				feeds = fr.feeds ?? [];
			}
			if (viewsRes.ok) {
				const vr = (await viewsRes.json()) as MatViewsResponse;
				matviews = vr.views ?? [];
			}
			lastUpdated = new Date();
			error = '';
		} catch {
			error = 'Network error.';
		} finally {
			loading = false;
			refreshing = false;
		}
	};

	const triggerFeedRefresh = async (feed: 'kev' | 'epss') => {
		triggering = { ...triggering, [feed]: true };
		try {
			const res = await fetch(`/api/admin/feeds/${feed}/refresh`, {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ reason: 'manual admin refresh' })
			});
			if (!res.ok && res.status !== 409) {
				// 409 = already running, which is fine — the next poll
				// will surface the existing job's progress.
				const text = await res.text();
				error = text || `Failed to trigger ${feed.toUpperCase()} refresh`;
			} else {
				// Force an immediate refresh so the user sees the
				// queued/running state without waiting for the 3s tick.
				await fetchJobs(false);
			}
		} catch {
			error = `Network error triggering ${feed.toUpperCase()} refresh`;
		} finally {
			triggering = { ...triggering, [feed]: false };
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

	const fmtRelativeISO = (iso: string | null | undefined) => {
		if (!iso) return '—';
		const t = new Date(iso).getTime();
		if (isNaN(t)) return '—';
		const diffSec = Math.floor((Date.now() - t) / 1000);
		if (diffSec < 0) {
			// Future timestamp — used for next_scheduled_at.
			const ahead = -diffSec;
			if (ahead < 60) return `in ${ahead}s`;
			if (ahead < 3600) return `in ${Math.floor(ahead / 60)}m`;
			if (ahead < 86400) return `in ${Math.floor(ahead / 3600)}h ${Math.floor((ahead % 3600) / 60)}m`;
			return `in ${Math.floor(ahead / 86400)}d`;
		}
		if (diffSec < 60) return `${diffSec}s ago`;
		if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
		if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
		return `${Math.floor(diffSec / 86400)}d ago`;
	};

	// EPSS publishes ~250k rows daily — used to estimate progress
	// percentage when the worker reports rows_written without a total.
	// Slight overshoot on a smaller daily snapshot just caps the bar
	// near 100%, which is fine.
	const EPSS_EXPECTED_ROWS = 250_000;

	const feedByName = (name: 'kev' | 'epss') => feeds.find((f) => f.feed === name);

	const isFeedRunning = (f: FeedStatus | undefined) =>
		!!f && (f.status === 'RUNNING' || f.status === 'QUEUED' || f.status === 'RETRY');

	const feedProgressPct = (f: FeedStatus | undefined): number | null => {
		if (!f || f.status !== 'RUNNING') return null;
		const written = f.result?.rows_written ?? 0;
		if (written <= 0) return null;
		const pct = Math.min(99, (written / EPSS_EXPECTED_ROWS) * 100);
		return pct;
	};
</script>

<svelte:head>
	<title>Jobs · Settings — Spam Monitor</title>
</svelte:head>

<div class="space-y-4">
	<article class="panel-surface space-y-2 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex items-start justify-between gap-4">
			<div class="flex items-center gap-3">
				<Layers class="h-8 w-8 flex-shrink-0 text-[var(--accent)]" />
				<div>
					<h2 class="text-xl font-semibold text-[var(--text-bright)]">Jobs</h2>
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

					<!-- Bulk vuln feeds (KEV + EPSS) — only attached to the
					     main pool because that's where these jobs run. -->
					{#if pool.name === 'main'}
						<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-3">
							<div class="mb-2 flex items-center gap-2">
								<Rss class="h-3 w-3 text-[var(--accent)]" />
								<h3 class="text-[0.65rem] font-semibold uppercase tracking-[0.18em] text-[var(--text-tertiary)]">Vuln feeds</h3>
							</div>
							<ul class="space-y-2">
								{#each [{ key: 'kev', label: 'CISA KEV', cadence: 'every 6h' }, { key: 'epss', label: 'FIRST.org EPSS', cadence: 'daily 05:00 Oslo' }] as row (row.key)}
									{@const f = feedByName(row.key as 'kev' | 'epss')}
									{@const running = isFeedRunning(f)}
									{@const pct = feedProgressPct(f)}
									<li class="space-y-1">
										<div class="flex items-center justify-between gap-2">
											<div class="min-w-0 flex-1">
												<div class="flex items-center gap-2">
													<span class="font-mono text-[10px] font-semibold text-[var(--text-bright)]">{row.label}</span>
													{#if running}
														<span class="inline-flex items-center gap-1 rounded-full border border-[var(--accent)]/40 bg-[var(--accent)]/10 px-1.5 py-0 text-[10px] text-[var(--accent)]">
															<RefreshCw class="h-2.5 w-2.5 animate-spin" />
															{f?.status?.toLowerCase() ?? 'running'}
														</span>
													{:else if f?.status === 'FAILED'}
														<span class="inline-flex items-center gap-1 rounded-full border border-red-500/40 bg-red-500/10 px-1.5 py-0 text-[10px] text-red-400">failed</span>
													{:else if f?.status === 'SUCCEEDED'}
														<span class="text-[10px] text-[var(--text-muted)]">·</span>
													{/if}
												</div>
												<div class="text-[10px] text-[var(--text-muted)]">
													{row.cadence}
													{#if f?.finished_at && f.status === 'SUCCEEDED'}
														· last refreshed {fmtRelativeISO(f.finished_at)}
														{#if f.result?.rows}<span class="text-[var(--text-tertiary)]"> · {fmt(f.result.rows)} rows</span>{/if}
													{:else if f?.status === 'FAILED' && f?.error}
														· <span class="text-red-400" title={f.error}>{f.error.length > 50 ? f.error.slice(0, 50) + '…' : f.error}</span>
													{/if}
													{#if !running && f?.next_scheduled_at}
														· next {fmtRelativeISO(f.next_scheduled_at)}
													{/if}
												</div>
											</div>
											<button
												type="button"
												class="shrink-0 rounded-full border border-[var(--border-color)] px-2.5 py-1 text-[10px] font-medium text-[var(--text-secondary)] transition hover:border-[var(--accent)] hover:text-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-40"
												disabled={running || triggering[row.key]}
												onclick={() => triggerFeedRefresh(row.key as 'kev' | 'epss')}
											>
												Refresh
											</button>
										</div>
										{#if running && pct !== null}
											<div class="space-y-0.5">
												<div class="h-1 w-full overflow-hidden rounded-full bg-[var(--hover-bg)]">
													<div class="h-full bg-[var(--accent)] transition-all duration-500" style="width: {pct}%"></div>
												</div>
												<div class="text-[10px] text-[var(--text-muted)]">
													{fmt(f?.result?.rows_written ?? 0)} rows
												</div>
											</div>
										{:else if running && f?.status === 'RUNNING'}
											<div class="h-1 w-full overflow-hidden rounded-full bg-[var(--hover-bg)]">
												<div class="h-full w-1/3 animate-pulse bg-[var(--accent)]"></div>
											</div>
										{/if}
									</li>
								{/each}
							</ul>
						</div>
					{/if}

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

		<!-- Materialised views: state + last refresh. These are NOT
		     queue-backed jobs — they run as in-process goroutines under
		     advisory locks (one replica wins, others observe lock-held
		     and exit). Surfaced here so operators can answer "is the
		     view warm?" without a psql session. -->
		<section class="panel-surface space-y-4 px-6 py-6">
			<header class="space-y-1">
				<div class="flex items-center gap-2">
					<BookOpen class="h-5 w-5 flex-shrink-0 text-[var(--accent)]" />
					<h2 class="text-base font-semibold text-[var(--text-bright)]">Materialised views</h2>
				</div>
				<p class="text-xs leading-snug text-[var(--text-tertiary)]">
					In-process refresh under per-MV advisory lock. <code class="font-mono text-[10px]">populated=false</code> means the first-populate goroutine is still running (or has failed) — readers short-circuit to empty until it finishes.
				</p>
			</header>

			<div class="overflow-hidden rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
				<table class="min-w-full text-xs">
					<thead class="text-[0.6rem] uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
						<tr>
							<th class="px-3 py-2 text-left">Name</th>
							<th class="px-2 py-2 text-left">State</th>
							<th class="px-2 py-2 text-right">Last refresh</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-[var(--border-color)]/40">
						{#each matviews as mv (mv.name)}
							<tr class="text-[var(--text-secondary)]">
								<td class="px-3 py-1.5 font-mono text-[10px] text-[var(--text-bright)]">{mv.name}</td>
								<td class="px-2 py-1.5">
									{#if mv.populated}
										<span class="inline-flex items-center gap-1 text-[var(--green)]">
											<span class="h-1.5 w-1.5 rounded-full bg-[var(--green)]"></span>
											populated
										</span>
									{:else}
										<span class="inline-flex items-center gap-1 text-yellow-400">
											<span class="h-1.5 w-1.5 rounded-full bg-yellow-400"></span>
											populating
										</span>
									{/if}
								</td>
								<td class="px-2 py-1.5 text-right tabular-nums text-[var(--text-tertiary)]">
									{fmtRelativeISO(mv.refreshed_at)}
								</td>
							</tr>
						{/each}
						{#if matviews.length === 0}
							<tr>
								<td colspan="3" class="px-3 py-3 text-center text-[var(--text-muted)]">No materialised views.</td>
							</tr>
						{/if}
					</tbody>
				</table>
			</div>
		</section>
	{/if}
</div>
