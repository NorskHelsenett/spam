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

	type SortKey = 'total' | 'rows' | 'dead' | 'indexes' | 'name';

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

	let data = $state<StorageResponse | null>(null);
	let loading = $state(true);
	let refreshing = $state(false);
	let error = $state('');
	let sortKey: SortKey = $state('total');

	let maintenanceJobs = $state<MaintenanceJob[]>([]);
	let maintenancePollTimer: ReturnType<typeof setTimeout> | null = null;
	let maintenanceActionError = $state('');

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

	const sortedTables = $derived.by(() => {
		if (!data?.tables) return [];
		const copy = [...data.tables];
		switch (sortKey) {
			case 'rows':
				return copy.sort((a, b) => b.live_rows - a.live_rows);
			case 'dead':
				return copy.sort((a, b) => b.dead_ratio - a.dead_ratio);
			case 'indexes':
				return copy.sort((a, b) => b.indexes_bytes - a.indexes_bytes);
			case 'name':
				return copy.sort((a, b) => a.name.localeCompare(b.name));
			case 'total':
			default:
				return copy.sort((a, b) => b.total_bytes - a.total_bytes);
		}
	});

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

	onMount(() => {
		if (browser) {
			load();
			loadMaintenance().then(() => {
				if (hasActiveMaintenance) pollMaintenance();
			});
		}
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
			<button type="button" class="btn btn-ghost" onclick={load} disabled={refreshing}>
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
			<div class="flex items-center gap-2">
				<label class="text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]" for="sort">Sort</label>
				<select
					id="sort"
					class="rounded-xl border border-[var(--border-color)] bg-transparent px-3 py-1.5 text-sm text-[var(--text-secondary)] focus:border-[var(--accent)] focus:outline-none"
					bind:value={sortKey}
				>
					<option value="total">Total size</option>
					<option value="rows">Live rows</option>
					<option value="dead">Dead ratio</option>
					<option value="indexes">Index size</option>
					<option value="name">Name</option>
				</select>
			</div>
		</header>

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
							<th class="px-4 py-3 text-left font-semibold">Table</th>
							<th class="px-4 py-3 text-right font-semibold">Total</th>
							<th class="px-4 py-3 text-right font-semibold">Table</th>
							<th class="px-4 py-3 text-right font-semibold">Indexes</th>
							<th class="px-4 py-3 text-right font-semibold">Toast</th>
							<th class="px-4 py-3 text-right font-semibold">Live rows</th>
							<th class="px-4 py-3 text-right font-semibold">Dead</th>
							<th class="px-4 py-3 text-right font-semibold">Seq / Idx</th>
							<th class="px-4 py-3 text-right font-semibold">Vacuumed</th>
							<th class="px-4 py-3 text-right font-semibold">Analyzed</th>
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
</div>
