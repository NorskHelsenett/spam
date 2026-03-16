<script lang="ts">
	import { browser } from '$app/environment';
	import { onMount } from 'svelte';
	import { ArrowLeft, KeyRound } from 'lucide-svelte';
	import DonutChart from '$lib/components/DonutChart.svelte';
	import MultiLineChart from '$lib/components/MultiLineChart.svelte';
	import type { MultiSeries, MultiPoint } from '$lib/components/MultiLineChart.svelte';

	type TableRow = {
		repo: string;
		secret_type: string;
		unique_finding_count: number;
	};

	type DistributionRow = {
		secret_type: string;
		finding_count: number;
	};

	type TrendRaw = {
		date: string;
		secret_type: string;
		count: number;
	};

	let tableRows: TableRow[] = [];
	let distribution: DistributionRow[] = [];
	let trendRaw: TrendRaw[] = [];
	let loading = true;
	let error = '';

	const COLORS = [
		'var(--red)',
		'var(--orange)',
		'var(--yellow)',
		'var(--blue)',
		'var(--green)',
		'var(--purple)',
		'var(--aqua)',
		'var(--gray)'
	];

	$: donutTotal = distribution.reduce((s, r) => s + r.finding_count, 0);

	$: donutSegments = distribution.map((r, i) => ({
		label: r.secret_type,
		value: r.finding_count,
		color: COLORS[i % COLORS.length]
	}));

	// Pivot trend rows into per-date objects with dynamic keys
	$: ({ trendData, trendSeries } = (() => {
		// Collect all distinct secret types in order of appearance
		const typeSet = new Set<string>();
		for (const r of trendRaw) typeSet.add(r.secret_type);
		const types = Array.from(typeSet);

		// Build series metadata — "other" always last and gray
		const namedTypes = types.filter((t) => t !== 'other');
		const hasOther = types.includes('other');
		const seriesList: MultiSeries[] = [
			...namedTypes.map((t, i) => ({ key: t, label: t, color: COLORS[i % (COLORS.length - 1)] })),
			...(hasOther ? [{ key: 'other', label: 'other', color: 'var(--gray)' }] : [])
		];

		// Collect all distinct dates in order
		const dateSet = new Set<string>();
		for (const r of trendRaw) dateSet.add(r.date);
		const dates = Array.from(dateSet).sort();

		// Build pivot map date → { type: count }
		const pivot = new Map<string, Record<string, number>>();
		for (const date of dates) pivot.set(date, {});
		for (const r of trendRaw) {
			pivot.get(r.date)![r.secret_type] = r.count;
		}

		const points: MultiPoint[] = dates.map((date) => {
			const entry: MultiPoint = { date };
			for (const s of seriesList) entry[s.key] = pivot.get(date)?.[s.key] ?? 0;
			return entry;
		});

		return { trendData: points, trendSeries: seriesList };
	})());

	$: groupedByRepo = (() => {
		const map = new Map<string, TableRow[]>();
		for (const row of tableRows) {
			if (!map.has(row.repo)) map.set(row.repo, []);
			map.get(row.repo)!.push(row);
		}
		return Array.from(map.entries());
	})();

	const fmt = (n: number) => n.toLocaleString('en-US').replace(/,/g, ' ');

	const goBack = () => {
		if (browser) history.back();
	};

	type SortKey = 'repo' | 'secret_type' | 'unique_finding_count';
	let sortKey: SortKey = 'repo';
	let sortAsc = true;

	$: sortedRows = [...tableRows].sort((a, b) => {
		let cmp = 0;
		if (sortKey === 'unique_finding_count') {
			cmp = a.unique_finding_count - b.unique_finding_count;
		} else {
			cmp = a[sortKey].localeCompare(b[sortKey]);
		}
		return sortAsc ? cmp : -cmp;
	});

	const setSort = (key: SortKey) => {
		if (sortKey === key) {
			sortAsc = !sortAsc;
		} else {
			sortKey = key;
			sortAsc = true;
		}
	};

	const sortIndicator = (key: SortKey) =>
		sortKey === key ? (sortAsc ? ' ↑' : ' ↓') : '';

	onMount(async () => {
		try {
			const [tableRes, distRes, trendRes] = await Promise.all([
				fetch('/api/secrets/table', { credentials: 'include' }),
				fetch('/api/secrets/distribution', { credentials: 'include' }),
				fetch('/api/secrets/trend', { credentials: 'include' })
			]);

			if (!tableRes.ok || !distRes.ok || !trendRes.ok) {
				error = 'Failed to load secrets data';
				return;
			}

			tableRows = await tableRes.json();
			distribution = await distRes.json();
			trendRaw = await trendRes.json();
		} catch {
			error = 'Failed to fetch data';
		} finally {
			loading = false;
		}
	});
</script>

<svelte:head>
	<title>Secrets — Spam Monitor</title>
</svelte:head>

<div class="space-y-6">
	<!-- Back button -->
	<div>
		<button
			type="button"
			class="inline-flex items-center gap-2 text-sm text-[var(--text-secondary)] transition hover:text-[var(--accent)]"
			onclick={goBack}
		>
			<ArrowLeft class="h-4 w-4" />
			Back
		</button>
	</div>

	{#if loading}
		<div class="flex items-center justify-center py-20">
			<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
		</div>
	{:else if error}
		<div class="rounded-2xl border border-[var(--red)]/30 bg-[var(--red)]/10 px-4 py-3 text-sm text-[var(--red)]">
			{error}
		</div>
	{:else}
		<!-- Main stats panel -->
		<article class="panel-surface space-y-6 px-6 py-6 sm:px-10">
			<!-- Header -->
			<div>
				<div class="flex items-center gap-3">
					<KeyRound class="h-6 w-6 flex-shrink-0 text-[var(--accent)]" />
					<h1 class="text-2xl font-semibold text-[var(--text-bright)]">Secrets</h1>
				</div>
				<p class="mt-1 text-sm text-[var(--text-muted)]">
					Secret scan results across all repositories · {fmt(donutTotal)} total findings
				</p>
			</div>

			<!-- Metric cards -->
			<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Total Findings</h3>
					<p class="text-3xl font-bold text-[var(--text-bright)]">{fmt(donutTotal)}</p>
					<p class="text-xs text-[var(--text-muted)]">across {groupedByRepo.length} repos</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Secret Types</h3>
					<p class="text-3xl font-bold text-[var(--text-bright)]">{distribution.length}</p>
					<p class="text-xs text-[var(--text-muted)]">distinct rule IDs detected</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Repositories</h3>
					<p class="text-3xl font-bold text-[var(--text-bright)]">{groupedByRepo.length}</p>
					<p class="text-xs text-[var(--text-muted)]">with at least one finding</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Top Secret Type</h3>
					<p class="truncate text-xl font-bold text-[var(--text-bright)]">{distribution[0]?.secret_type ?? '—'}</p>
					<p class="text-xs text-[var(--text-muted)]">{distribution[0] ? fmt(distribution[0].finding_count) + ' findings' : 'no data'}</p>
				</div>
			</div>

			<!-- Charts -->
			<div class="grid grid-cols-1 gap-6 lg:grid-cols-3">
				<div class="metric-card rounded-2xl p-5">
					{#if distribution.length > 0}
						<DonutChart
							title="Secret type distribution"
							total={donutTotal}
							segments={donutSegments}
						/>
					{/if}
				</div>
				<div class="metric-card rounded-2xl p-5 lg:col-span-2">
					<MultiLineChart
						title="30-day trend (top 5 types + other)"
						data={trendData}
						series={trendSeries}
					/>
				</div>
			</div>
		</article>

		<!-- Data table -->
		<div class="rounded-2xl border border-[var(--border-color)] bg-[var(--card-bg)] overflow-hidden">
			{#if tableRows.length === 0}
				<div class="flex flex-col items-center justify-center py-16 text-center">
					<KeyRound class="mb-3 h-10 w-10 text-[var(--text-muted)]" />
					<p class="text-sm font-medium text-[var(--text-secondary)]">No secrets found</p>
					<p class="mt-1 text-xs text-[var(--text-muted)]">No secret scan results yet — run a scan on a repository to see results here.</p>
				</div>
			{:else}
				<div class="overflow-x-auto">
					<table class="w-full text-xs">
						<thead>
							<tr class="border-b border-[var(--border-color)] text-[var(--text-muted)] uppercase tracking-wider">
								<th class="px-5 py-3 text-left font-medium">
									<button type="button" class="hover:text-[var(--accent)]" onclick={() => setSort('repo')}>
										Repository{sortIndicator('repo')}
									</button>
								</th>
								<th class="px-4 py-3 text-left font-medium">
									<button type="button" class="hover:text-[var(--accent)]" onclick={() => setSort('secret_type')}>
										Secret Type{sortIndicator('secret_type')}
									</button>
								</th>
								<th class="px-4 py-3 text-right font-medium">
									<button type="button" class="hover:text-[var(--accent)]" onclick={() => setSort('unique_finding_count')}>
										Unique Findings{sortIndicator('unique_finding_count')}
									</button>
								</th>
							</tr>
						</thead>
						<tbody>
							{#each sortedRows as row, i}
								<tr class="border-b border-[var(--border-color)]/50 {i % 2 === 0 ? '' : 'bg-[var(--card-bg)]/30'}">
									<td class="max-w-xs truncate px-5 py-3 font-mono text-[var(--text-secondary)]" title={row.repo}>
										{row.repo}
									</td>
									<td class="px-4 py-3 text-[var(--text-secondary)]">
										<span class="rounded-full border border-[var(--border-color)] px-2 py-0.5 text-[10px] uppercase tracking-wide text-[var(--text-muted)]">
											{row.secret_type}
										</span>
									</td>
									<td class="px-4 py-3 text-right tabular-nums font-semibold text-[var(--text-bright)]">
										{fmt(row.unique_finding_count)}
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</div>
	{/if}
</div>
