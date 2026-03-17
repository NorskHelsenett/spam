<script lang="ts">
	import { browser } from '$app/environment';
	import { onMount } from 'svelte';
	import { fly, slide } from 'svelte/transition';
	import { cubicOut, cubicIn } from 'svelte/easing';
	import { ArrowLeft, KeyRound, GitBranch, SlidersHorizontal, Search } from 'lucide-svelte';
	import DonutChart from '$lib/components/DonutChart.svelte';
	import MultiLineChart from '$lib/components/MultiLineChart.svelte';
	import type { MultiSeries, MultiPoint } from '$lib/components/MultiLineChart.svelte';
	import SecretsDrawer from '$lib/components/SecretsDrawer.svelte';
	import Toggle from '$lib/components/Toggle.svelte';
	import MultiSelect from '$lib/components/MultiSelect.svelte';
	import type { MultiSelectOption } from '$lib/components/MultiSelect.svelte';

	type TableRow = {
		repo: string;
		repo_id: string;
		provider: string;
		secret_type: string;
		unique_finding_count: number;
		last_scanned: string;
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

	let tableRows: TableRow[] = $state([]);
	let distribution: DistributionRow[] = $state([]);
	let trendRaw: TrendRaw[] = $state([]);
	let loading = $state(true);
	let error = $state('');

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

	const donutTotal = $derived(distribution.reduce((s, r) => s + r.finding_count, 0));

	const donutSegments = $derived(distribution.map((r, i) => ({
		label: r.secret_type,
		value: r.finding_count,
		color: COLORS[i % COLORS.length]
	})));

	// Pivot trend rows into per-date objects with dynamic keys
	const { trendData, trendSeries } = $derived.by(() => {
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
	});

	const groupedByRepo = $derived.by(() => {
		const map = new Map<string, TableRow[]>();
		for (const row of tableRows) {
			if (!map.has(row.repo)) map.set(row.repo, []);
			map.get(row.repo)!.push(row);
		}
		return Array.from(map.entries());
	});

	// ── Filter state ──────────────────────────────────────────────────
	let filterOpen = $state(false);
	let publicOnly = $state(false);
	let selectedSecretTypes: string[] = $state([]);
	let selectedProviders: string[] = $state([]);
	let searchQuery = $state('');

	// Derive available options from loaded data
	const secretTypeOptions: MultiSelectOption[] = $derived(
		[...new Set(tableRows.map((r) => r.secret_type))].sort().map((t) => ({ value: t, label: t }))
	);
	const providerOptions: MultiSelectOption[] = $derived(
		[...new Set(tableRows.map((r) => r.provider).filter(Boolean))].sort().map((p) => ({ value: p, label: p }))
	);

	const activeFilterCount = $derived(
		(publicOnly ? 1 : 0) + (selectedSecretTypes.length > 0 ? 1 : 0) + (selectedProviders.length > 0 ? 1 : 0) + (searchQuery.trim() ? 1 : 0)
	);

	// Filtered rows (before sorting)
	const filteredRows = $derived(
		tableRows.filter((row) => {
			if (selectedSecretTypes.length > 0 && !selectedSecretTypes.includes(row.secret_type)) return false;
			if (selectedProviders.length > 0 && !selectedProviders.includes(row.provider)) return false;
			if (searchQuery.trim()) {
				const q = searchQuery.trim().toLowerCase();
				if (
					!row.repo.toLowerCase().includes(q) &&
					!row.secret_type.toLowerCase().includes(q) &&
					!row.provider.toLowerCase().includes(q) &&
					!repoShortName(row.repo).toLowerCase().includes(q)
				) return false;
			}
			return true;
		})
	);

	const clearFilters = () => {
		publicOnly = false;
		selectedSecretTypes = [];
		selectedProviders = [];
		searchQuery = '';
	};

	const fmt = (n: number) => n.toLocaleString('en-US').replace(/,/g, ' ');

	const goBack = () => {
		if (browser) history.back();
	};

	type SortKey = 'repo' | 'secret_type' | 'unique_finding_count';
	let sortKey: SortKey = $state('repo');
	let sortAsc = $state(true);

	const sortedRows = $derived([...filteredRows].sort((a, b) => {
		let cmp = 0;
		if (sortKey === 'unique_finding_count') {
			cmp = a.unique_finding_count - b.unique_finding_count;
		} else {
			cmp = a[sortKey].localeCompare(b[sortKey]);
		}
		return sortAsc ? cmp : -cmp;
	}));

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

	const repoShortName = (url: string) => {
		try {
			return new URL(url).pathname.replace(/\.git$/, '').replace(/^\//, '');
		} catch {
			return url;
		}
	};

	const fmtRelative = (iso: string) => {
		const diff = Date.now() - new Date(iso).getTime();
		const days = Math.floor(diff / 86_400_000);
		if (days === 0) return 'today';
		if (days === 1) return 'yesterday';
		if (days < 30) return `${days}d ago`;
		return `${Math.floor(days / 30)}mo ago`;
	};

	let drawerOpen = $state(false);
	let drawerRow: TableRow | null = $state(null);

	const openDrawer = (row: TableRow) => {
		if (drawerOpen && drawerRow?.repo_id === row.repo_id) {
			drawerOpen = false;
			drawerRow = null;
		} else {
			drawerRow = row;
			drawerOpen = true;
		}
	};

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

<div class="space-y-4">
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

	<!-- Stats + charts panel -->
	<article class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<!-- Header -->
		<header class="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
			<div class="flex items-center gap-3">
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
		<header class="flex items-start justify-between gap-4">
			<div>
				<h2 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Findings</h2>
				<p class="text-sm text-[var(--text-tertiary)]">Per-repository secret findings from the latest scan.</p>
			</div>
			{#if !loading && !error && tableRows.length > 0}
				<button
					type="button"
					class="filter-toggle"
					class:active={filterOpen}
					onclick={() => (filterOpen = !filterOpen)}
					aria-expanded={filterOpen}
					aria-label="Toggle filters"
				>
					<SlidersHorizontal size={16} />
					<span>Filters</span>
					{#if activeFilterCount > 0}
						<span class="filter-badge">{activeFilterCount}</span>
					{/if}
				</button>
			{/if}
		</header>

		<!-- Animated filter bar -->
		{#if filterOpen && !loading && !error}
			<div
				transition:slide={{ duration: 220, easing: cubicOut }}
				class="filter-bar"
			>
				<div class="flex flex-wrap items-start gap-6">
					<div class="filter-field">
						<span class="filter-field-label">Visibility</span>
						<div class="flex items-center h-[28px]">
							<Toggle bind:checked={publicOnly} label="Public only" />
						</div>
					</div>

					<div class="filter-field">
						<span class="filter-field-label">Secret types</span>
						<MultiSelect
							bind:selected={selectedSecretTypes}
							options={secretTypeOptions}
							placeholder="All types"
							size="sm"
						/>
					</div>

					<div class="filter-field">
						<span class="filter-field-label">Providers</span>
						<MultiSelect
							bind:selected={selectedProviders}
							options={providerOptions}
							placeholder="All providers"
							size="sm"
						/>
					</div>

					<div class="filter-field filter-field-search w-[35em]">
						<span class="filter-field-label">Search</span>
						<div class="search-input-wrap">
							<Search size={13} class="search-icon" />
							<input
								type="text"
								class="search-input"
								placeholder="Repo, type, provider…"
								bind:value={searchQuery}
							/>
						</div>
					</div>

					{#if activeFilterCount > 0}
						<div class="filter-actions">
							<span class="text-xs text-[var(--text-muted)]">
								{filteredRows.length} of {tableRows.length}
							</span>
							<button
								type="button"
								class="clear-filters"
								onclick={clearFilters}
							>
								Clear all
							</button>
						</div>
					{/if}
				</div>
			</div>
		{/if}

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
									<th class="px-5 py-3 text-right">Last Scanned</th>
								</tr>
							</thead>
							<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
								{#each sortedRows as row}
									<tr
										class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)] {drawerOpen && drawerRow?.repo_id === row.repo_id ? 'bg-[var(--hover-bg-subtle)]' : ''}"
										onclick={() => openDrawer(row)}
									>
										<td class="px-5 py-3">
											<div class="flex items-center gap-2">
												<GitBranch class="h-4 w-4 shrink-0 text-[var(--accent)]" />
												<span class="font-semibold text-[var(--text-bright)]">{repoShortName(row.repo)}</span>
											</div>
											<p class="mt-0.5 truncate text-xs text-[var(--text-muted)]" title={row.repo}>{row.repo}</p>
										</td>
										<td class="px-5 py-3">
											<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs">
												{row.secret_type}
											</span>
										</td>
										<td class="px-5 py-3 text-right">
											<span class="inline-flex items-center rounded-full bg-[var(--accent)]/10 px-2.5 py-0.5 font-semibold tabular-nums text-xs text-[var(--accent)]">{fmt(row.unique_finding_count)}</span>
										</td>
										<td class="px-5 py-3 text-right text-xs text-[var(--text-muted)]" title={row.last_scanned}>
											{fmtRelative(row.last_scanned)}
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>

					{#if drawerOpen && drawerRow}
						<div
							class="absolute inset-y-0 right-0 z-10 w-[780px] border-l border-[var(--border-color)] rounded-l-[10px]"
							in:fly={{ x: 780, duration: 240, easing: cubicOut, opacity: 1 }}
							out:fly={{ x: 780, duration: 200, easing: cubicIn, opacity: 1 }}
						>
							<SecretsDrawer
								repoId={drawerRow.repo_id}
								repoName={repoShortName(drawerRow.repo)}
								initialFilters={selectedSecretTypes.length > 0 ? selectedSecretTypes : []}
								onClose={() => { drawerOpen = false; drawerRow = null; }}
							/>
						</div>
					{/if}
				</div>
			{/if}
		{/if}
	</section>
</div>

<style>
	.filter-toggle {
		display: inline-flex;
		align-items: center;
		gap: 0.4rem;
		padding: 0.4rem 0.85rem;
		border-radius: 999px;
		border: 1px solid var(--border-color);
		background: var(--card-bg);
		color: var(--text-secondary);
		font-size: 0.8rem;
		font-weight: 500;
		cursor: pointer;
		transition: border-color 150ms ease, color 150ms ease, background 150ms ease;
		white-space: nowrap;
		flex-shrink: 0;
	}

	.filter-toggle:hover {
		color: var(--text-bright);
		border-color: var(--text-tertiary);
	}

	.filter-toggle.active {
		background: color-mix(in srgb, var(--accent) 12%, transparent);
		border-color: color-mix(in srgb, var(--accent) 40%, transparent);
		color: var(--accent);
	}

	.filter-badge {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 18px;
		height: 18px;
		border-radius: 999px;
		background: var(--accent);
		color: var(--bg-hard);
		font-size: 0.65rem;
		font-weight: 700;
		line-height: 1;
		padding: 0 0.3rem;
	}

	.filter-bar {
		padding: 0.75rem 0;
	}

	.filter-field {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}

	.filter-field-label {
		font-size: 0.65rem;
		font-weight: 600;
		color: var(--text-tertiary);
		text-transform: uppercase;
		letter-spacing: 0.12em;
		white-space: nowrap;
		padding-left: 0.15rem;
	}

	.filter-field-search {
		min-width: 220px;
		max-width: 280px;
	}

	.search-input-wrap {
		position: relative;
		display: flex;
		align-items: center;
	}

	.search-input-wrap :global(.search-icon) {
		position: absolute;
		left: 0.55rem;
		color: var(--text-muted);
		pointer-events: none;
	}

	.search-input {
		height: 28px;
		width: 100%;
		border-radius: 999px;
		border: 1px solid var(--border-color);
		background: var(--card-bg);
		padding: 0 0.6rem 0 1.7rem;
		font-size: 0.75rem;
		color: var(--text-secondary);
		transition: border-color 150ms ease, box-shadow 150ms ease;
	}

	.search-input::placeholder {
		color: var(--text-muted);
	}

	.search-input:focus {
		outline: none;
		border-color: var(--accent);
		box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 30%, transparent);
	}

	.filter-actions {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		margin-left: auto;
		/* align with controls row: label line-height + gap */
		padding-top: calc(0.65rem * 1.2 + 0.35rem);
	}

	.clear-filters {
		padding: 0.3rem 0.75rem;
		border-radius: 999px;
		border: 1px solid color-mix(in srgb, var(--accent) 50%, transparent);
		background: transparent;
		color: var(--accent);
		font-size: 0.75rem;
		font-weight: 500;
		cursor: pointer;
		transition: background 150ms ease, color 150ms ease, border-color 150ms ease;
	}

	.clear-filters:hover {
		background: color-mix(in srgb, var(--red) 14%, transparent);
		border-color: color-mix(in srgb, var(--red) 50%, transparent);
		color: var(--red);
	}
</style>
