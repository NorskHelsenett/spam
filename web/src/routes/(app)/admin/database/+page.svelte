<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { browser } from '$app/environment';
	import RotateCw from 'lucide-svelte/icons/rotate-cw';
	import Database from 'lucide-svelte/icons/database';
	import TriangleAlert from 'lucide-svelte/icons/triangle-alert';
	import Sparkles from 'lucide-svelte/icons/sparkles';
	import Wrench from 'lucide-svelte/icons/wrench';
	import CircleCheck from 'lucide-svelte/icons/circle-check';
	import CircleX from 'lucide-svelte/icons/circle-x';
	import ChevronUp from 'lucide-svelte/icons/chevron-up';
	import ChevronDown from 'lucide-svelte/icons/chevron-down';
	import Activity from 'lucide-svelte/icons/activity';
	import Zap from 'lucide-svelte/icons/zap';

	type TableRow = {
		schema: string;
		name: string;
		total_bytes: number;
		table_bytes: number;
		indexes_bytes: number;
		toast_bytes: number;
		live_rows: number;
		dead_rows: number;
		dead_ratio: number;
		last_vacuum?: string;
		last_autovacuum?: string;
		last_analyze?: string;
		last_autoanalyze?: string;
		seq_scan: number;
		idx_scan: number;
	};

	type StorageResponse = {
		fetched_at: string;
		database: string;
		database_bytes: number;
		table_count: number;
		total_table_bytes: number;
		tables: TableRow[];
	};

	type SortKey =
		| 'name'
		| 'total'
		| 'table'
		| 'indexes'
		| 'toast'
		| 'rows'
		| 'dead'
		| 'seq'
		| 'vacuumed'
		| 'analyzed';
	type SortDir = 'asc' | 'desc';

	type MaintenanceOp = 'analyze' | 'vacuum_analyze';

	type MaintenanceJob = {
		job_id: string;
		status: 'QUEUED' | 'RUNNING' | 'RETRY' | 'SUCCEEDED' | 'FAILED' | string;
		schema: string;
		table: string;
		operation: MaintenanceOp | string;
		created_at: string;
		finished_at?: string;
		error?: string;
		result?: { duration_ms?: number };
	};

	type ActivityResponse = {
		fetched_at: string;
		database: string;
		num_backends: number;
		xact_commit: number;
		xact_rollback: number;
		blks_read: number;
		blks_hit: number;
		cache_hit_ratio: number;
		tup_returned: number;
		tup_fetched: number;
		tup_inserted: number;
		tup_updated: number;
		tup_deleted: number;
		conflicts: number;
		temp_files: number;
		temp_bytes: number;
		deadlocks: number;
		checksum_failures: number;
		stats_reset?: string;
	};

	type LiveQuery = {
		pid: number;
		username?: string;
		application_name?: string;
		client_addr?: string;
		state?: string;
		wait_event_type?: string;
		wait_event?: string;
		query_start?: string;
		state_change?: string;
		duration_seconds: number;
		query?: string;
	};

	type SlowQuery = {
		query_id: string;
		query: string;
		calls: number;
		total_ms: number;
		mean_ms: number;
		max_ms?: number;
		rows: number;
		shared_blks_hit: number;
		shared_blks_read: number;
	};

	type SlowQueriesResponse = {
		installed: boolean;
		how_to_install?: string;
		top_by_total?: SlowQuery[];
		top_by_mean?: SlowQuery[];
	};

	let data = $state<StorageResponse | null>(null);
	let loading = $state(true);
	let refreshing = $state(false);
	let error = $state('');
	let sortKey: SortKey = $state('total');
	let sortDir: SortDir = $state('desc');

	let activity = $state<ActivityResponse | null>(null);
	let liveQueries = $state<LiveQuery[]>([]);
	let slowQueries = $state<SlowQueriesResponse | null>(null);
	let slowView: 'total' | 'mean' = $state('total');

	let maintenanceJobs = $state<MaintenanceJob[]>([]);
	let maintenancePollTimer: ReturnType<typeof setTimeout> | null = null;
	let maintenanceActionError = $state('');

	let bulkRunning = $state(false);
	let bulkSummary = $state<{ enqueued: number; skipped: number; total_tables: number; operation: string } | null>(null);

	// Latest job per (schema, table). First entry wins because /recent
	// returns newest first.
	const latestByTable = $derived.by(() => {
		const map = new Map<string, MaintenanceJob>();
		for (const job of maintenanceJobs) {
			const key = `${job.schema}.${job.table}`;
			if (!map.has(key)) map.set(key, job);
		}
		return map;
	});

	// Any job that hasn't reached a terminal state — drives the poll loop.
	const hasActiveMaintenance = $derived(
		maintenanceJobs.some((j) => j.status === 'QUEUED' || j.status === 'RUNNING' || j.status === 'RETRY')
	);

	const formatBytes = (bytes: number | null | undefined) => {
		if (bytes == null) return '—';
		if (bytes < 1024) return `${bytes} B`;
		const units = ['KB', 'MB', 'GB', 'TB'];
		let value = bytes / 1024;
		let i = 0;
		while (value >= 1024 && i < units.length - 1) {
			value /= 1024;
			i++;
		}
		return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[i]}`;
	};

	const formatNumber = (n: number) => new Intl.NumberFormat().format(n);

	const formatRelative = (iso?: string) => {
		if (!iso) return 'never';
		const d = new Date(iso);
		if (Number.isNaN(d.getTime())) return '—';
		const diff = Date.now() - d.getTime();
		const min = Math.round(diff / 60_000);
		if (min < 1) return 'just now';
		if (min < 60) return `${min}m ago`;
		const hr = Math.round(min / 60);
		if (hr < 24) return `${hr}h ago`;
		const day = Math.round(hr / 24);
		if (day < 30) return `${day}d ago`;
		const mo = Math.round(day / 30);
		return `${mo}mo ago`;
	};

	const lastTouched = (row: TableRow) => {
		const candidates = [row.last_vacuum, row.last_autovacuum].filter(Boolean) as string[];
		if (candidates.length === 0) return undefined;
		return candidates.sort().pop();
	};

	const lastAnalyzed = (row: TableRow) => {
		const candidates = [row.last_analyze, row.last_autoanalyze].filter(Boolean) as string[];
		if (candidates.length === 0) return undefined;
		return candidates.sort().pop();
	};

	const tsOf = (iso?: string) => (iso ? new Date(iso).getTime() : 0);

	const sortedTables = $derived.by(() => {
		if (!data?.tables) return [];
		const copy = [...data.tables];
		const mul = sortDir === 'asc' ? 1 : -1;
		copy.sort((a, b) => {
			switch (sortKey) {
				case 'name':
					return mul * a.name.localeCompare(b.name);
				case 'table':
					return mul * (a.table_bytes - b.table_bytes);
				case 'indexes':
					return mul * (a.indexes_bytes - b.indexes_bytes);
				case 'toast':
					return mul * (a.toast_bytes - b.toast_bytes);
				case 'rows':
					return mul * (a.live_rows - b.live_rows);
				case 'dead':
					return mul * (a.dead_ratio - b.dead_ratio);
				case 'seq':
					return mul * (a.seq_scan - b.seq_scan);
				case 'vacuumed':
					return mul * (tsOf(lastTouched(a)) - tsOf(lastTouched(b)));
				case 'analyzed':
					return mul * (tsOf(lastAnalyzed(a)) - tsOf(lastAnalyzed(b)));
				case 'total':
				default:
					return mul * (a.total_bytes - b.total_bytes);
			}
		});
		return copy;
	});

	// First click on a header picks the column's natural direction
	// (sizes/rows desc, name asc, dates desc). Subsequent clicks toggle.
	const defaultDir: Record<SortKey, SortDir> = {
		name: 'asc',
		total: 'desc',
		table: 'desc',
		indexes: 'desc',
		toast: 'desc',
		rows: 'desc',
		dead: 'desc',
		seq: 'desc',
		vacuumed: 'desc',
		analyzed: 'desc'
	};

	const toggleSort = (key: SortKey) => {
		if (sortKey === key) {
			sortDir = sortDir === 'asc' ? 'desc' : 'asc';
		} else {
			sortKey = key;
			sortDir = defaultDir[key];
		}
	};

	const load = async () => {
		loading = true;
		refreshing = true;
		error = '';
		try {
			const response = await fetch('/api/admin/db/storage', { credentials: 'include' });
			if (!response.ok) {
				error = response.status === 403 ? 'Admin access required.' : 'Failed to load storage stats.';
				data = null;
				return;
			}
			data = await response.json();
		} catch {
			error = 'Failed to load storage stats.';
		} finally {
			loading = false;
			setTimeout(() => {
				refreshing = false;
			}, 600);
		}
	};

	const loadActivity = async () => {
		try {
			const response = await fetch('/api/admin/db/activity', { credentials: 'include' });
			if (!response.ok) return;
			activity = await response.json();
		} catch {
			// Soft-fail.
		}
	};

	const loadLive = async () => {
		try {
			const response = await fetch('/api/admin/db/live-queries', { credentials: 'include' });
			if (!response.ok) return;
			const json = await response.json();
			liveQueries = json.queries ?? [];
		} catch {
			// Soft-fail.
		}
	};

	const loadSlow = async () => {
		try {
			const response = await fetch('/api/admin/db/slow-queries', { credentials: 'include' });
			if (!response.ok) return;
			slowQueries = await response.json();
		} catch {
			// Soft-fail.
		}
	};

	const runBulkMaintenance = async (op: MaintenanceOp) => {
		const label = op === 'vacuum_analyze' ? 'VACUUM ANALYZE' : 'ANALYZE';
		if (!browser) return;
		const confirmed = window.confirm(
			`Run ${label} on every non-empty table in the database?\n\n` +
				`This enqueues one job per table. Tables with rows currently being ` +
				`maintained are skipped. ${label} does not acquire an exclusive lock — ` +
				`reads and writes continue normally.`
		);
		if (!confirmed) return;
		bulkRunning = true;
		bulkSummary = null;
		maintenanceActionError = '';
		try {
			const response = await fetch('/api/admin/db/maintenance/all', {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ operation: op })
			});
			if (!response.ok) {
				maintenanceActionError = `Bulk ${label} failed (${response.status}).`;
				return;
			}
			bulkSummary = await response.json();
			await loadMaintenance();
			pollMaintenance();
		} catch {
			maintenanceActionError = `Bulk ${label} failed.`;
		} finally {
			bulkRunning = false;
		}
	};

	const loadMaintenance = async () => {
		try {
			const response = await fetch('/api/admin/db/maintenance/recent', { credentials: 'include' });
			if (!response.ok) return;
			const json = await response.json();
			maintenanceJobs = json.jobs ?? [];
		} catch {
			// Soft-fail — the page is still useful without history.
		}
	};

	const pollMaintenance = () => {
		if (maintenancePollTimer) clearTimeout(maintenancePollTimer);
		maintenancePollTimer = setTimeout(async () => {
			await loadMaintenance();
			if (hasActiveMaintenance) {
				pollMaintenance();
			} else {
				// One final storage refresh once everything settles so
				// dead-tuple ratios reflect what just ran.
				load();
			}
		}, 3000);
	};

	const runMaintenance = async (row: TableRow, op: MaintenanceOp) => {
		maintenanceActionError = '';
		try {
			const response = await fetch('/api/admin/db/maintenance', {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ schema: row.schema, table: row.name, operation: op })
			});
			if (!response.ok) {
				if (response.status === 409) {
					maintenanceActionError = `${row.name}: already queued or running.`;
				} else {
					maintenanceActionError = `${row.name}: failed to enqueue.`;
				}
				return;
			}
			await loadMaintenance();
			pollMaintenance();
		} catch {
			maintenanceActionError = `${row.name}: failed to enqueue.`;
		}
	};

	const maintenanceLabel = (op: string) => {
		if (op === 'vacuum_analyze') return 'VACUUM ANALYZE';
		if (op === 'analyze') return 'ANALYZE';
		return op;
	};

	const formatDuration = (ms?: number) => {
		if (ms == null) return '';
		if (ms < 1000) return `${ms}ms`;
		const s = ms / 1000;
		if (s < 60) return `${s.toFixed(1)}s`;
		const m = Math.floor(s / 60);
		const r = Math.round(s - m * 60);
		return `${m}m ${r}s`;
	};

	const formatMs = (ms: number) => {
		if (ms < 1) return `${ms.toFixed(2)}ms`;
		if (ms < 1000) return `${ms.toFixed(1)}ms`;
		const s = ms / 1000;
		if (s < 60) return `${s.toFixed(1)}s`;
		const m = Math.floor(s / 60);
		const r = Math.round(s - m * 60);
		return `${m}m ${r}s`;
	};

	const formatCompactNumber = (n: number) => {
		if (n < 1000) return `${n}`;
		if (n < 1_000_000) return `${(n / 1000).toFixed(1)}k`;
		if (n < 1_000_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
		return `${(n / 1_000_000_000).toFixed(1)}B`;
	};

	const truncate = (s: string | undefined, n: number) => {
		if (!s) return '';
		const flat = s.replace(/\s+/g, ' ').trim();
		return flat.length > n ? flat.slice(0, n) + '…' : flat;
	};

	const bloatTone = (ratio: number) => {
		if (ratio >= 0.3) return 'text-red-400';
		if (ratio >= 0.15) return 'text-amber-400';
		return 'text-[var(--text-tertiary)]';
	};

	const scanTone = (row: TableRow) => {
		const total = row.seq_scan + row.idx_scan;
		if (total === 0) return '';
		const ratio = row.seq_scan / total;
		if (ratio >= 0.5 && row.live_rows > 10_000) return 'text-amber-400';
		return '';
	};

	const refreshAll = async () => {
		await Promise.all([load(), loadActivity(), loadLive(), loadSlow(), loadMaintenance()]);
		if (hasActiveMaintenance) pollMaintenance();
	};

	onMount(() => {
		if (browser) refreshAll();
	});

	onDestroy(() => {
		if (maintenancePollTimer) clearTimeout(maintenancePollTimer);
	});
</script>

<svelte:head>
	<title>Database storage • Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Database storage</h1>
				<p class="text-sm text-[var(--text-tertiary)]">
					PostgreSQL size, row counts, and bloat signals. Useful for chasing performance issues.
				</p>
			</div>
			<button type="button" class="btn btn-ghost" onclick={refreshAll} disabled={refreshing}>
				<span class="inline-flex h-[14px] w-[14px] items-center justify-center {refreshing ? 'animate-spin' : ''}">
					<RotateCw size={14} />
				</span>
				Refresh
			</button>
		</header>

		{#if error}
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">
				{error}
			</div>
		{/if}

		<div class="grid grid-cols-2 gap-3 sm:grid-cols-4">
			<div class="metric-card space-y-1 rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Database</h3>
				<p class="text-2xl font-bold text-[var(--text-bright)]">{loading ? '—' : (data?.database ?? '—')}</p>
				<p class="text-xs text-[var(--text-muted)]">connected schema</p>
			</div>
			<div class="metric-card space-y-1 rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Total size</h3>
				<p class="text-2xl font-bold text-[var(--text-bright)]">{loading ? '—' : formatBytes(data?.database_bytes)}</p>
				<p class="text-xs text-[var(--text-muted)]">pg_database_size</p>
			</div>
			<div class="metric-card space-y-1 rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Tables</h3>
				<p class="text-2xl font-bold text-[var(--text-bright)]">{loading ? '—' : (data?.table_count ?? '—')}</p>
				<p class="text-xs text-[var(--text-muted)]">user-schema relations</p>
			</div>
			<div class="metric-card space-y-1 rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Tables + indexes</h3>
				<p class="text-2xl font-bold text-[var(--text-bright)]">{loading ? '—' : formatBytes(data?.total_table_bytes)}</p>
				<p class="text-xs text-[var(--text-muted)]">sum of pg_total_relation_size</p>
			</div>
		</div>

		{#if activity}
			{@const hitPct = activity.cache_hit_ratio * 100}
			<div class="space-y-2">
				<div class="flex items-baseline justify-between">
					<h2 class="text-sm font-semibold uppercase tracking-[0.2em] text-[var(--text-tertiary)]">Activity</h2>
					{#if activity.stats_reset}
						<p class="text-xs text-[var(--text-muted)]">stats since {formatRelative(activity.stats_reset)}</p>
					{/if}
				</div>
				<div class="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
					<div class="metric-card space-y-1 rounded-2xl p-4">
						<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Cache hit</h3>
						<p class="text-2xl font-bold {hitPct >= 99 ? 'text-emerald-400' : hitPct >= 95 ? 'text-[var(--text-bright)]' : 'text-amber-400'}">{hitPct.toFixed(2)}%</p>
						<p class="text-xs text-[var(--text-muted)]">blks_hit / total reads</p>
					</div>
					<div class="metric-card space-y-1 rounded-2xl p-4">
						<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Backends</h3>
						<p class="text-2xl font-bold text-[var(--text-bright)]">{activity.num_backends}</p>
						<p class="text-xs text-[var(--text-muted)]">connections in this DB</p>
					</div>
					<div class="metric-card space-y-1 rounded-2xl p-4">
						<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Deadlocks</h3>
						<p class="text-2xl font-bold {activity.deadlocks > 0 ? 'text-amber-400' : 'text-[var(--text-bright)]'}">{formatCompactNumber(activity.deadlocks)}</p>
						<p class="text-xs text-[var(--text-muted)]">since stats reset</p>
					</div>
					<div class="metric-card space-y-1 rounded-2xl p-4">
						<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Conflicts</h3>
						<p class="text-2xl font-bold {activity.conflicts > 0 ? 'text-amber-400' : 'text-[var(--text-bright)]'}">{formatCompactNumber(activity.conflicts)}</p>
						<p class="text-xs text-[var(--text-muted)]">canceled queries</p>
					</div>
					<div class="metric-card space-y-1 rounded-2xl p-4">
						<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Temp spill</h3>
						<p class="text-2xl font-bold {activity.temp_bytes > 1024 * 1024 * 1024 ? 'text-amber-400' : 'text-[var(--text-bright)]'}">{formatBytes(activity.temp_bytes)}</p>
						<p class="text-xs text-[var(--text-muted)]">{formatCompactNumber(activity.temp_files)} files</p>
					</div>
					<div class="metric-card space-y-1 rounded-2xl p-4">
						<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Rollbacks</h3>
						<p class="text-2xl font-bold text-[var(--text-bright)]">{formatCompactNumber(activity.xact_rollback)}</p>
						<p class="text-xs text-[var(--text-muted)]">{formatCompactNumber(activity.xact_commit)} commits</p>
					</div>
				</div>
				{#if activity.checksum_failures > 0}
					<div class="rounded-2xl border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">
						<strong>{activity.checksum_failures} checksum failure{activity.checksum_failures === 1 ? '' : 's'}</strong> — possible page corruption. Inspect <code class="rounded bg-black/30 px-1">pg_stat_database.checksum_last_failure</code>.
					</div>
				{/if}
				<p class="text-[11px] text-[var(--text-muted)]">
					PostgreSQL doesn't aggregate statement-timeout cancellations or per-query errors in pg_catalog — those go to the server log. The signals above are what's visible: deadlocks, conflicts (canceled queries), and temp-file spill (queries too big for <code class="rounded bg-[var(--hover-bg)] px-1">work_mem</code>).
				</p>
			</div>
		{/if}
	</section>

	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">Tables</h2>
				<p class="text-sm text-[var(--text-tertiary)]">
					Per-table size, live rows, dead-tuple ratio, and last (auto)vacuum. Click
					<Sparkles class="inline" size={11} /> to run <code class="rounded bg-[var(--hover-bg)] px-1 py-0.5 text-xs">ANALYZE</code>
					(refresh planner stats, no locks) or <Wrench class="inline" size={11} /> for
					<code class="rounded bg-[var(--hover-bg)] px-1 py-0.5 text-xs">VACUUM ANALYZE</code> (reclaim dead tuples in-place, no exclusive lock).
				</p>
			</div>
			<div class="flex flex-wrap items-center gap-2">
				<button
					type="button"
					class="btn btn-ghost inline-flex items-center gap-2 text-xs"
					onclick={() => runBulkMaintenance('analyze')}
					disabled={bulkRunning}
					title="Enqueue ANALYZE on every non-empty user table"
				>
					<Sparkles size={13} />
					Analyze all
				</button>
				<button
					type="button"
					class="btn btn-ghost inline-flex items-center gap-2 text-xs"
					onclick={() => runBulkMaintenance('vacuum_analyze')}
					disabled={bulkRunning}
					title="Enqueue VACUUM ANALYZE on every non-empty user table"
				>
					<Wrench size={13} />
					Vacuum analyze all
				</button>
			</div>
		</header>

		{#if bulkSummary}
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-3 text-sm text-[var(--text-secondary)]">
				Queued <span class="font-semibold text-[var(--text-bright)]">{bulkSummary.enqueued}</span>
				of {bulkSummary.total_tables} tables for {maintenanceLabel(bulkSummary.operation)}
				{#if bulkSummary.skipped > 0}<span class="text-[var(--text-tertiary)]"> ({bulkSummary.skipped} skipped — already running)</span>{/if}.
			</div>
		{/if}

		{#if maintenanceActionError}
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-3 text-sm text-[var(--error)]">
				{maintenanceActionError}
			</div>
		{/if}

		{#if loading}
			<p class="text-sm text-[var(--text-secondary)]">Loading…</p>
		{:else if !data || sortedTables.length === 0}
			<p class="text-sm text-[var(--text-secondary)]">No tables found.</p>
		{:else}
			<div class="overflow-x-auto rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
				<table class="w-full text-sm">
					<thead class="text-[10px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
						<tr class="border-b border-[var(--border-color)]/40">
							{#each [
								{ key: 'name' as SortKey, label: 'Table', align: 'left' },
								{ key: 'total' as SortKey, label: 'Total', align: 'right' },
								{ key: 'table' as SortKey, label: 'Table', align: 'right' },
								{ key: 'indexes' as SortKey, label: 'Indexes', align: 'right' },
								{ key: 'toast' as SortKey, label: 'Toast', align: 'right' },
								{ key: 'rows' as SortKey, label: 'Live rows', align: 'right' },
								{ key: 'dead' as SortKey, label: 'Dead', align: 'right' },
								{ key: 'seq' as SortKey, label: 'Seq / Idx', align: 'right' },
								{ key: 'vacuumed' as SortKey, label: 'Vacuumed', align: 'right' },
								{ key: 'analyzed' as SortKey, label: 'Analyzed', align: 'right' }
							] as col (col.key)}
								<th class="px-4 py-3 font-semibold {col.align === 'right' ? 'text-right' : 'text-left'}">
									<button
										type="button"
										class="inline-flex items-center gap-1 uppercase tracking-[0.18em] transition hover:text-[var(--text-secondary)] {sortKey === col.key ? 'text-[var(--text-bright)]' : ''}"
										onclick={() => toggleSort(col.key)}
									>
										<span>{col.label}</span>
										{#if sortKey === col.key}
											{#if sortDir === 'asc'}
												<ChevronUp size={11} />
											{:else}
												<ChevronDown size={11} />
											{/if}
										{/if}
									</button>
								</th>
							{/each}
							<th class="px-4 py-3 text-right font-semibold">Maintenance</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-[var(--border-color)]/40">
						{#each sortedTables as row (row.schema + '.' + row.name)}
							{@const latest = latestByTable.get(`${row.schema}.${row.name}`)}
							{@const busy = !!latest && (latest.status === 'QUEUED' || latest.status === 'RUNNING' || latest.status === 'RETRY')}
							<tr class="transition hover:bg-[var(--hover-bg-subtle)]">
								<td class="px-4 py-3">
									<div class="flex items-center gap-2">
										<Database size={14} class="text-[var(--text-tertiary)]" />
										<div class="min-w-0">
											<div class="truncate font-medium text-[var(--text-bright)]">{row.name}</div>
											{#if row.schema !== 'public'}
												<div class="text-[10px] uppercase tracking-[0.12em] text-[var(--text-tertiary)]">{row.schema}</div>
											{/if}
										</div>
									</div>
								</td>
								<td class="px-4 py-3 text-right font-mono text-[var(--text-bright)]">{formatBytes(row.total_bytes)}</td>
								<td class="px-4 py-3 text-right font-mono text-[var(--text-secondary)]">{formatBytes(row.table_bytes)}</td>
								<td class="px-4 py-3 text-right font-mono text-[var(--text-secondary)]">{formatBytes(row.indexes_bytes)}</td>
								<td class="px-4 py-3 text-right font-mono text-[var(--text-tertiary)]">{row.toast_bytes > 0 ? formatBytes(row.toast_bytes) : '—'}</td>
								<td class="px-4 py-3 text-right font-mono text-[var(--text-secondary)]">{formatNumber(row.live_rows)}</td>
								<td class="px-4 py-3 text-right font-mono {bloatTone(row.dead_ratio)}">
									{#if row.dead_rows > 0}
										<div class="inline-flex items-center justify-end gap-1">
											{#if row.dead_ratio >= 0.15}
												<TriangleAlert size={12} />
											{/if}
											<span>{(row.dead_ratio * 100).toFixed(1)}%</span>
										</div>
										<div class="text-[10px] text-[var(--text-tertiary)]">{formatNumber(row.dead_rows)}</div>
									{:else}
										<span class="text-[var(--text-tertiary)]">—</span>
									{/if}
								</td>
								<td class="px-4 py-3 text-right font-mono text-xs {scanTone(row)}">
									<span title="Sequential scans">{formatNumber(row.seq_scan)}</span>
									<span class="text-[var(--text-tertiary)]">/</span>
									<span title="Index scans" class="text-[var(--text-secondary)]">{formatNumber(row.idx_scan)}</span>
								</td>
								<td class="px-4 py-3 text-right text-xs text-[var(--text-tertiary)]">{formatRelative(lastTouched(row))}</td>
								<td class="px-4 py-3 text-right text-xs text-[var(--text-tertiary)]">{formatRelative(lastAnalyzed(row))}</td>
								<td class="px-4 py-3 text-right">
									<div class="flex items-center justify-end gap-1.5">
										{#if busy}
											<span class="inline-flex items-center gap-1 text-[10px] uppercase tracking-[0.12em] text-amber-400">
												<span class="inline-flex h-3 w-3 items-center justify-center"><RotateCw size={10} class="animate-spin" /></span>
												{latest.status === 'RUNNING' ? maintenanceLabel(latest.operation) : 'Queued'}
											</span>
										{:else}
											{#if latest && latest.status === 'SUCCEEDED'}
												<span class="inline-flex items-center gap-1 text-[10px] text-[var(--text-tertiary)]" title="Last: {maintenanceLabel(latest.operation)} • {formatDuration(latest.result?.duration_ms)} • {formatRelative(latest.finished_at)}">
													<CircleCheck size={11} class="text-emerald-400" />
													{formatDuration(latest.result?.duration_ms)}
												</span>
											{:else if latest && latest.status === 'FAILED'}
												<span class="inline-flex items-center gap-1 text-[10px] text-red-400" title={latest.error || 'failed'}>
													<CircleX size={11} />
													failed
												</span>
											{/if}
											<button
												type="button"
												class="rounded-full p-1 text-[var(--text-tertiary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-secondary)]"
												onclick={() => runMaintenance(row, 'analyze')}
												title="ANALYZE — refresh planner stats only (no locks, fast)"
												aria-label="Analyze {row.name}"
											>
												<Sparkles size={13} />
											</button>
											<button
												type="button"
												class="rounded-full p-1 text-[var(--text-tertiary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-secondary)]"
												onclick={() => runMaintenance(row, 'vacuum_analyze')}
												title="VACUUM ANALYZE — reclaim dead tuples in-place and refresh stats (no exclusive lock)"
												aria-label="Vacuum analyze {row.name}"
											>
												<Wrench size={13} />
											</button>
										{/if}
									</div>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</section>

	<section class="panel-surface space-y-4 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-2 sm:flex-row sm:items-baseline sm:justify-between">
			<div>
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">Live queries</h2>
				<p class="text-sm text-[var(--text-tertiary)]">
					Active backends from <code class="rounded bg-[var(--hover-bg)] px-1 py-0.5 text-xs">pg_stat_activity</code>. Long durations or sustained
					<code class="rounded bg-[var(--hover-bg)] px-1 py-0.5 text-xs">Lock</code> waits are the queries most likely to be slow or timing out.
				</p>
			</div>
			<button type="button" class="btn btn-ghost text-xs" onclick={loadLive}>
				<Activity size={12} /> Reload
			</button>
		</header>

		{#if liveQueries.length === 0}
			<p class="text-sm text-[var(--text-secondary)]">No active queries.</p>
		{:else}
			<div class="overflow-x-auto rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
				<table class="w-full text-sm">
					<thead class="text-[10px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
						<tr class="border-b border-[var(--border-color)]/40">
							<th class="px-4 py-3 text-left font-semibold">PID</th>
							<th class="px-4 py-3 text-left font-semibold">App / user</th>
							<th class="px-4 py-3 text-left font-semibold">State</th>
							<th class="px-4 py-3 text-left font-semibold">Wait</th>
							<th class="px-4 py-3 text-right font-semibold">Duration</th>
							<th class="px-4 py-3 text-left font-semibold">Query</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-[var(--border-color)]/40">
						{#each liveQueries as q (q.pid)}
							{@const slow = q.duration_seconds >= 60}
							{@const idleTx = q.state === 'idle in transaction' || q.state === 'idle in transaction (aborted)'}
							<tr class="transition hover:bg-[var(--hover-bg-subtle)]">
								<td class="px-4 py-3 font-mono text-xs text-[var(--text-tertiary)]">{q.pid}</td>
								<td class="px-4 py-3 text-xs">
									<div class="text-[var(--text-bright)]">{q.application_name || '—'}</div>
									<div class="text-[10px] text-[var(--text-tertiary)]">{q.username || ''}{q.client_addr ? ` · ${q.client_addr}` : ''}</div>
								</td>
								<td class="px-4 py-3 text-xs {idleTx ? 'text-amber-400' : 'text-[var(--text-secondary)]'}">{q.state || '—'}</td>
								<td class="px-4 py-3 text-xs text-[var(--text-tertiary)]">
									{#if q.wait_event_type}
										<span class="rounded-full border border-[var(--border-color)]/60 px-2 py-0.5 text-[10px] uppercase tracking-[0.1em] {q.wait_event_type === 'Lock' ? 'text-amber-400' : ''}">
											{q.wait_event_type}{q.wait_event ? ` · ${q.wait_event}` : ''}
										</span>
									{:else}
										—
									{/if}
								</td>
								<td class="px-4 py-3 text-right font-mono text-xs {slow ? 'text-amber-400' : 'text-[var(--text-secondary)]'}">{q.duration_seconds}s</td>
								<td class="max-w-[480px] px-4 py-3">
									<code class="block whitespace-pre-wrap break-words font-mono text-[11px] leading-snug text-[var(--text-secondary)]" title={q.query}>{truncate(q.query, 240)}</code>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</section>

	<section class="panel-surface space-y-4 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-2 sm:flex-row sm:items-baseline sm:justify-between">
			<div>
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">Slow queries</h2>
				<p class="text-sm text-[var(--text-tertiary)]">
					Aggregate query stats from <code class="rounded bg-[var(--hover-bg)] px-1 py-0.5 text-xs">pg_stat_statements</code>. The biggest signal for "which queries are eating the database".
				</p>
			</div>
			{#if slowQueries?.installed}
				<div class="flex items-center gap-2">
					<button
						type="button"
						class="btn btn-ghost text-xs {slowView === 'total' ? 'text-[var(--text-bright)]' : ''}"
						onclick={() => (slowView = 'total')}
					>
						By total time
					</button>
					<button
						type="button"
						class="btn btn-ghost text-xs {slowView === 'mean' ? 'text-[var(--text-bright)]' : ''}"
						onclick={() => (slowView = 'mean')}
					>
						By mean time
					</button>
				</div>
			{/if}
		</header>

		{#if !slowQueries}
			<p class="text-sm text-[var(--text-secondary)]">Loading…</p>
		{:else if !slowQueries.installed}
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--text-secondary)]">
				<p class="mb-2 font-medium text-[var(--text-bright)]">pg_stat_statements is not installed.</p>
				<p class="mb-3 text-[var(--text-tertiary)]">
					This is the most useful extension for diagnosing slow queries — it records per-query call counts, total time, mean time, and rows. To enable it:
				</p>
				<pre class="overflow-x-auto rounded-xl bg-black/40 p-3 text-[11px] leading-snug text-[var(--text-secondary)]"><code>{slowQueries.how_to_install}</code></pre>
			</div>
		{:else}
			{@const view = slowView === 'total' ? (slowQueries.top_by_total ?? []) : (slowQueries.top_by_mean ?? [])}
			{#if view.length === 0}
				<p class="text-sm text-[var(--text-secondary)]">pg_stat_statements is installed but empty — give it some traffic.</p>
			{:else}
				<div class="overflow-x-auto rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
					<table class="w-full text-sm">
						<thead class="text-[10px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
							<tr class="border-b border-[var(--border-color)]/40">
								<th class="px-4 py-3 text-right font-semibold">Calls</th>
								<th class="px-4 py-3 text-right font-semibold">Total</th>
								<th class="px-4 py-3 text-right font-semibold">Mean</th>
								<th class="px-4 py-3 text-right font-semibold">Rows</th>
								<th class="px-4 py-3 text-right font-semibold">Cache hit</th>
								<th class="px-4 py-3 text-left font-semibold">Query</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-[var(--border-color)]/40">
							{#each view as q (q.query_id)}
								{@const denom = q.shared_blks_hit + q.shared_blks_read}
								{@const hit = denom > 0 ? (q.shared_blks_hit / denom) * 100 : 100}
								<tr class="transition hover:bg-[var(--hover-bg-subtle)]">
									<td class="px-4 py-3 text-right font-mono text-xs text-[var(--text-secondary)]">{formatCompactNumber(q.calls)}</td>
									<td class="px-4 py-3 text-right font-mono text-xs text-[var(--text-bright)]">{formatMs(q.total_ms)}</td>
									<td class="px-4 py-3 text-right font-mono text-xs {q.mean_ms >= 100 ? 'text-amber-400' : 'text-[var(--text-secondary)]'}">{formatMs(q.mean_ms)}</td>
									<td class="px-4 py-3 text-right font-mono text-xs text-[var(--text-tertiary)]">{formatCompactNumber(q.rows)}</td>
									<td class="px-4 py-3 text-right font-mono text-xs {hit < 95 ? 'text-amber-400' : 'text-[var(--text-tertiary)]'}">{hit.toFixed(1)}%</td>
									<td class="max-w-[520px] px-4 py-3">
										<code class="block whitespace-pre-wrap break-words font-mono text-[11px] leading-snug text-[var(--text-secondary)]" title={q.query}>{truncate(q.query, 280)}</code>
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
				<p class="text-[11px] text-[var(--text-muted)] inline-flex items-center gap-1">
					<Zap size={11} /> Top 10 by {slowView === 'total' ? 'cumulative time' : 'mean time per call'}. Reset stats with <code class="rounded bg-[var(--hover-bg)] px-1">SELECT pg_stat_statements_reset();</code>
				</p>
			{/if}
		{/if}
	</section>
</div>
