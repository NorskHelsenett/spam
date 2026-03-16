<script lang="ts">
	import { browser } from '$app/environment';
	import { onMount } from 'svelte';
	import { ArrowLeft, KeyRound, GitBranch } from 'lucide-svelte';
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

	const sortArrow = (key: SortKey) =>
		sortKey === key ? (sortAsc ? '↑' : '↓') : '↑';

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

<div class="space-y-8 sm:space-y-12">
	<!-- Stats + charts panel -->
	<article class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<!-- Header -->
		<header class="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
			<div class="flex items-center gap-3">
				<button
					type="button"
					class="inline-flex items-center gap-2 text-sm text-[var(--text-secondary)] transition hover:text-[var(--accent)]"
					onclick={goBack}
				>
					<ArrowLeft class="h-4 w-4" />
				</button>
				<KeyRound class="h-6 w-6 flex-shrink-0 text-[var(--accent)]" />
				<div>
					<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Secrets</h1>
					<p class="text-sm text-[var(--text-tertiary)]">Secret scan results across all repositories.</p>
				</div>
			</div>
		</header>

		{#if loading}
			<div class="flex items-center justify-center py-20">
				<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
			</div>
		{:else if error}
			<div class="rounded-2xl border border-[var(--red)]/30 bg-[var(--red)]/10 px-4 py-3 text-sm text-[var(--red)]">
				{error}
			</div>
		{:else}
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
		{/if}
	</article>

	<!-- Data table panel -->
	<section class="panel-surface flex flex-col gap-6 px-6 py-8 sm:px-10 sm:py-10 h-[calc(100vh-7rem)]">
		<header>
			<h2 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Findings</h2>
			<p class="text-sm text-[var(--text-tertiary)]">Per-repository secret findings from the latest scan.</p>
		</header>

		{#if !loading && !error}
			{#if tableRows.length === 0}
				<div class="flex flex-1 items-center justify-center">
					<div class="flex flex-col items-center gap-3 text-center">
						<KeyRound class="h-10 w-10 text-[var(--text-muted)]" />
						<p class="text-sm text-[var(--text-muted)]">No secrets found.</p>
					</div>
				</div>
			{:else}
				<div class="relative flex flex-1 flex-col overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
					<div class="flex-1 overflow-y-auto">
						<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
							<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
								<tr>
									<th class="cursor-pointer px-5 py-3 text-left transition hover:text-[var(--text-secondary)]" onclick={() => setSort('repo')}>
										<span class="flex items-center gap-1">
											Repository
											<span class="w-3 text-center" class:text-[var(--accent)]={sortKey === 'repo'} class:text-transparent={sortKey !== 'repo'}>
												{sortArrow('repo')}
											</span>
										</span>
									</th>
									<th class="cursor-pointer px-5 py-3 text-left transition hover:text-[var(--text-secondary)]" onclick={() => setSort('secret_type')}>
										<span class="flex items-center gap-1">
											Secret Type
											<span class="w-3 text-center" class:text-[var(--accent)]={sortKey === 'secret_type'} class:text-transparent={sortKey !== 'secret_type'}>
												{sortArrow('secret_type')}
											</span>
										</span>
									</th>
									<th class="cursor-pointer px-5 py-3 text-right transition hover:text-[var(--text-secondary)]" onclick={() => setSort('unique_finding_count')}>
										<span class="inline-flex items-center gap-1">
											Findings
											<span class="w-3 text-center" class:text-[var(--accent)]={sortKey === 'unique_finding_count'} class:text-transparent={sortKey !== 'unique_finding_count'}>
												{sortArrow('unique_finding_count')}
											</span>
										</span>
									</th>
								</tr>
							</thead>
							<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
								{#each sortedRows as row}
									<tr class="transition hover:bg-[var(--hover-bg-subtle)]">
										<td class="px-5 py-3">
											<div class="flex items-center gap-2">
												<GitBranch class="h-4 w-4 shrink-0 text-[var(--accent)]" />
												<span class="font-mono font-semibold text-[var(--text-bright)]" title={row.repo}>{row.repo}</span>
											</div>
										</td>
										<td class="px-5 py-3">
											<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs">
												{row.secret_type}
											</span>
										</td>
										<td class="px-5 py-3 text-right tabular-nums font-semibold text-[var(--text-bright)]">
											{fmt(row.unique_finding_count)}
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				</div>
			{/if}
		{/if}
	</section>
</div>
