<script lang="ts">
	import { browser } from '$app/environment';
	import {
		Search,
		ShieldAlert,
		AlertTriangle,
		Eye,
		Container,
		GitBranch,
		ShieldCheck,
		Target
	} from 'lucide-svelte';
	import KubernetesIcon from '$lib/components/icons/KubernetesIcon.svelte';
	import EmptyVulns from '$lib/components/icons/EmptyVulns.svelte';
	import Loading from '$lib/components/Loading.svelte';
	import DonutChart from '$lib/components/DonutChart.svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';

	// DonutSegment is exported from DonutChart.svelte but svelte-check
	// fails to resolve type-only imports across the legacy export-let
	// boundary; inline the same shape here.
	type DonutSegment = { label: string; value: number; color: string };

	// --- Types mirror api/internal/assetrisk wire format ---
	type Reason = { id: string; fields?: Record<string, unknown> };
	type TriageRow = {
		asset_type: 'repo' | 'image' | 'cluster';
		asset_id: string;
		asset_slug: string;
		critical_count: number;
		high_count: number;
		kev_count: number;
		epss_max: number;
		has_fix_for_critical: boolean;
		active_secret_count: number;
		internet_exposed: boolean;
		signed_commits_pct: number;
		image_signed: boolean;
		scan_age_days: number;
		last_scan_at: string | null;
		has_sbom: boolean;
		threat_score: number;
		trust_score: number;
		trust_grade: string;
		tier: 'fix_now' | 'this_week' | 'watch';
		reasons: Reason[];
	};
	type Scope = {
		clusters: number;
		repos: number;
		images: number;
		needs_attention: number;
		view_refreshed_at: string | null;
	};
	type WatchCounts = { total: number; repo: number; image: number; cluster: number };
	type WatchSection = { counts: WatchCounts; limit: number; offset: number; rows: TriageRow[] };
	type TriageResponse = {
		scope: Scope;
		fix_now: TriageRow[];
		this_week: TriageRow[];
		watch: WatchSection;
	};

	let triage: TriageResponse | null = $state(null);
	let loading = $state(true);
	let error = $state('');
	let watchSearch = $state('');
	let watchOffset = $state(0);
	let activeTab = $state<'all' | 'repo' | 'image' | 'cluster'>('all');
	let searchTimer: ReturnType<typeof setTimeout> | null = null;

	const fetchTriage = async (search: string, offset: number) => {
		const params = new URLSearchParams();
		if (search.trim()) params.set('watch_q', search.trim());
		if (offset > 0) params.set('watch_offset', String(offset));
		const res = await fetch(`/api/triage?${params}`, { credentials: 'include' });
		if (!res.ok) throw new Error(`Failed to load triage (HTTP ${res.status})`);
		return (await res.json()) as TriageResponse;
	};

	const reload = async () => {
		try {
			triage = await fetchTriage(watchSearch, watchOffset);
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to load triage';
		} finally {
			loading = false;
		}
	};

	if (browser) {
		void reload();
	}

	const onSearchInput = () => {
		if (searchTimer) clearTimeout(searchTimer);
		searchTimer = setTimeout(() => {
			watchOffset = 0;
			void reload();
		}, 250);
	};

	const goNextPage = () => {
		if (!triage) return;
		const next = watchOffset + triage.watch.limit;
		if (next >= triage.watch.counts.total) return;
		watchOffset = next;
		void reload();
	};
	const goPrevPage = () => {
		if (!triage || watchOffset === 0) return;
		watchOffset = Math.max(0, watchOffset - triage.watch.limit);
		void reload();
	};

	const formatDate = (value: string | null) => {
		if (!value) return '—';
		return new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
	};

	const fmt = (n: number) => new Intl.NumberFormat('en-US').format(n);

	// Reason templates — pre-rendered for now; the API returns the
	// structured {id, fields} so a future LLM step can swap renderer
	// without touching the API.
	const renderReason = (r: Reason): string => {
		const f = r.fields ?? {};
		switch (r.id) {
			case 'active_secret_leak':
				return `${f.count} active secret${(f.count as number) === 1 ? '' : 's'}`;
			case 'kev_and_exposed':
				return `${f.kev_count} KEV on exposed workload`;
			case 'kev_present':
				return `${f.kev_count} KEV CVE${(f.kev_count as number) === 1 ? '' : 's'}`;
			case 'epss_very_high':
				return `EPSS ${(((f.epss_max as number) ?? 0) * 100).toFixed(0)}%`;
			case 'epss_elevated':
				return `EPSS ${(((f.epss_max as number) ?? 0) * 100).toFixed(0)}%`;
			case 'critical_severity':
				return `${f.critical} Critical${f.has_fix ? ' (fix avail.)' : ''}`;
			case 'scan_stale':
				return `Scan ${f.days}d old`;
			case 'low_commit_signing':
				return `${Math.round((f.signed_pct as number) ?? 0)}% commits signed`;
			case 'image_unsigned':
				return `Unsigned image`;
			case 'no_sbom':
				return `No SBOM`;
			case 'archived_deps':
				return `${f.count} archived dep${(f.count as number) === 1 ? '' : 's'}`;
			case 'deprecated_deps':
				return `${f.count} deprecated dep${(f.count as number) === 1 ? '' : 's'}`;
			case 'low_dep_health':
				return `Worst dep health ${Math.round((f.worst_score as number) ?? 0)}/100`;
			default:
				return r.id;
		}
	};

	const reasonPillClass = (id: string): string => {
		switch (id) {
			case 'active_secret_leak':
			case 'kev_and_exposed':
			case 'kev_present':
				return 'pill pill-error';
			case 'epss_very_high':
			case 'epss_elevated':
			case 'critical_severity':
			case 'scan_stale':
			case 'archived_deps':
			case 'deprecated_deps':
			case 'low_dep_health':
				return 'pill pill-warning';
			default:
				return 'pill pill-neutral';
		}
	};

	const rowHref = (r: TriageRow): string => {
		if (r.asset_type === 'repo') return `/app/providers/repo?repo_id=${encodeURIComponent(r.asset_id)}`;
		if (r.asset_type === 'image') return `/app/images/${encodeURIComponent(r.asset_id)}`;
		return `/app/clusters?cluster_id=${encodeURIComponent(r.asset_id)}`;
	};

	const rowIcon = (assetType: string) => {
		if (assetType === 'repo') return GitBranch;
		if (assetType === 'image') return Container;
		return KubernetesIcon;
	};

	const trustColor = (grade: string): string => {
		if (grade.startsWith('A')) return 'var(--success)';
		if (grade.startsWith('B')) return 'var(--accent)';
		if (grade === 'C') return 'var(--warning)';
		return 'var(--error)';
	};

	// Average trust score across all visible tiers — rough proxy for
	// the operator's overall posture. Excludes assets that fall below
	// the actionable threshold (the API drops those server-side).
	const avgTrust = $derived(() => {
		if (!triage) return null;
		const all = [...triage.fix_now, ...triage.this_week, ...triage.watch.rows];
		if (all.length === 0) return null;
		const sum = all.reduce((acc, r) => acc + r.trust_score, 0);
		return Math.round(sum / all.length);
	});

	// Asset-type distribution donut: how does the "needs attention"
	// population break down across repos / images / clusters? Helps
	// the operator orient on where to invest tooling.
	const distributionSegments = $derived((): DonutSegment[] => {
		if (!triage) return [];
		const counts = { repo: 0, image: 0, cluster: 0 };
		for (const r of [...triage.fix_now, ...triage.this_week]) {
			counts[r.asset_type]++;
		}
		// Watch counts already pre-bucketed in the response.
		counts.repo += triage.watch.counts.repo;
		counts.image += triage.watch.counts.image;
		counts.cluster += triage.watch.counts.cluster;
		const segs: DonutSegment[] = [];
		if (counts.repo > 0) segs.push({ label: 'Repos', value: counts.repo, color: 'var(--accent)' });
		if (counts.image > 0) segs.push({ label: 'Images', value: counts.image, color: 'var(--info)' });
		if (counts.cluster > 0) segs.push({ label: 'Clusters', value: counts.cluster, color: 'var(--warning)' });
		return segs;
	});

	const distributionTotal = $derived(() => {
		const segs = distributionSegments();
		return segs.reduce((a, b) => a + b.value, 0);
	});

	const tierSegments = $derived((): DonutSegment[] => {
		if (!triage) return [];
		const segs: DonutSegment[] = [];
		if (triage.fix_now.length > 0) segs.push({ label: 'Fix now', value: triage.fix_now.length, color: 'var(--error)' });
		if (triage.this_week.length > 0) segs.push({ label: 'This week', value: triage.this_week.length, color: 'var(--warning)' });
		if (triage.watch.counts.total > 0) segs.push({ label: 'Watch', value: triage.watch.counts.total, color: 'var(--text-muted)' });
		return segs;
	});

	const tierTotal = $derived(() => {
		if (!triage) return 0;
		return triage.fix_now.length + triage.this_week.length + triage.watch.counts.total;
	});

	// Tab filter applied client-side over already-fetched lists.
	// Watch is paginated server-side, so client-tab on watch is just
	// a visual filter on the current page; users searching for
	// "this image is in watch" should use the search field too.
	const filterByTab = (rows: TriageRow[]): TriageRow[] => {
		if (activeTab === 'all') return rows;
		return rows.filter((r) => r.asset_type === activeTab);
	};

	const fixNowFiltered = $derived(() => triage ? filterByTab(triage.fix_now) : []);
	const thisWeekFiltered = $derived(() => triage ? filterByTab(triage.this_week) : []);
	const watchFiltered = $derived(() => triage ? filterByTab(triage.watch.rows) : []);

	// Total count for the active tab — shown under the Findings header.
	// Includes server-side watch counts (which are pre-filtered by tab
	// using the .counts.{repo,image,cluster} buckets the API returns)
	// so the number is accurate even when the watch page on screen is
	// just a slice of the full set.
	const activeTabTotal = $derived(() => {
		if (!triage) return 0;
		if (activeTab === 'all') {
			return triage.fix_now.length + triage.this_week.length + triage.watch.counts.total;
		}
		const fix = triage.fix_now.filter((r) => r.asset_type === activeTab).length;
		const week = triage.this_week.filter((r) => r.asset_type === activeTab).length;
		const watch = triage.watch.counts[activeTab];
		return fix + week + watch;
	});

	const activeTabLabel = $derived(() => {
		if (activeTab === 'all') return 'asset';
		if (activeTab === 'repo') return 'repo';
		if (activeTab === 'image') return 'image';
		return 'cluster';
	});
</script>

<svelte:head>
	<title>Triage • Spam Monitor</title>
</svelte:head>

<div class="space-y-4">
	<!-- Stats + charts panel -->
	<article class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<div class="flex items-center justify-between gap-3">
				<div class="flex items-center gap-3">
					<Target class="h-10 w-10 flex-shrink-0 text-[var(--accent)]" />
					<div>
						<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Triage</h1>
						<p class="text-sm text-[var(--text-tertiary)]">Asset-centric "fix this now" view across repos, images, and clusters.</p>
					</div>
				</div>
				{#if triage?.scope.view_refreshed_at}
					<span class="hidden text-[0.7rem] uppercase tracking-[0.12em] text-[var(--text-muted)] sm:inline">
						Data as of {formatDate(triage.scope.view_refreshed_at)}
					</span>
				{/if}
			</div>
		</header>

		{#if loading}
			<div class="flex items-center justify-center py-20">
				<Loading message="Loading triage" size="lg" variant="spinner" />
			</div>
		{:else if error}
			<div class="rounded-2xl border border-[var(--error)]/30 bg-[var(--error)]/10 px-4 py-3 text-sm text-[var(--error)]">{error}</div>
		{:else if triage}
			<!-- Metric cards: tier counts + scope + posture -->
			<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Need attention</h3>
					<p class="text-3xl font-bold {triage.scope.needs_attention === 0 ? 'text-[var(--success)]' : 'text-[var(--text-bright)]'}">{fmt(triage.scope.needs_attention)}</p>
					<p class="text-xs text-[var(--text-muted)]">across {fmt(triage.scope.repos + triage.scope.images + triage.scope.clusters)} assets</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Fix now</h3>
					<p class="text-3xl font-bold text-[var(--error)]">{fmt(triage.fix_now.length)}</p>
					<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><ShieldAlert class="h-3 w-3 text-[var(--error)]" /> Acute, exposed, or leaking</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">This week</h3>
					<p class="text-3xl font-bold text-[var(--warning)]">{fmt(triage.this_week.length)}</p>
					<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><AlertTriangle class="h-3 w-3 text-[var(--warning)]" /> High-risk or stale</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Watch</h3>
					<p class="text-3xl font-bold text-[var(--text-secondary)]">{fmt(triage.watch.counts.total)}</p>
					<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><Eye class="h-3 w-3 text-[var(--text-muted)]" /> Warnings, not urgent</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Avg trust</h3>
					{#if avgTrust() === null}
						<p class="text-3xl font-bold text-[var(--text-secondary)]">—</p>
						<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><ShieldCheck class="h-3 w-3" /> No actionable assets</p>
					{:else}
						<p class="text-3xl font-bold" style="color: {trustColor((avgTrust() ?? 0) >= 90 ? 'A' : (avgTrust() ?? 0) >= 75 ? 'B' : (avgTrust() ?? 0) >= 60 ? 'C' : 'F')}">{avgTrust()}</p>
						<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><ShieldCheck class="h-3 w-3" /> Across actionable assets</p>
					{/if}
				</div>
			</div>

			<!-- Charts -->
			<div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
				<div class="metric-card rounded-2xl p-5">
					<DonutChart
						title="By tier"
						total={tierTotal()}
						segments={tierSegments()}
					/>
				</div>
				<div class="metric-card rounded-2xl p-5">
					<DonutChart
						title="By asset type"
						total={distributionTotal()}
						segments={distributionSegments()}
					/>
				</div>
			</div>

			<!-- Tab selector — filters the lists below by asset type. The
			     active-tab count is rendered in the Findings header
			     below rather than in the tab label so the tabs stay
			     scannable at a glance. -->
			<div class="pt-2">
				<TabSelector
					options={[
						{ value: 'all', label: 'All' },
						{ value: 'repo', label: 'Repos' },
						{ value: 'image', label: 'Images' },
						{ value: 'cluster', label: 'Clusters' }
					]}
					bind:value={activeTab}
				/>
			</div>
		{/if}
	</article>

	<!-- Tier list panel -->
	{#if !loading && !error && triage}
		<section class="panel-surface flex flex-col gap-6 px-6 py-8 sm:px-10 sm:py-10">
			<header class="flex items-start justify-between gap-4">
				<div>
					<h2 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Findings</h2>
					<p class="text-sm text-[var(--text-tertiary)]">
						{#if activeTabTotal() > 0}
							{fmt(activeTabTotal())} {activeTabLabel()}{activeTabTotal() === 1 ? '' : 's'} ranked by composite Threat × Trust
						{:else}
							No assets in this filter
						{/if}
					</p>
				</div>
			</header>

			{#if triage.fix_now.length === 0 && triage.this_week.length === 0 && triage.watch.counts.total === 0}
				<div class="flex flex-1 items-center justify-center py-16">
					<div class="flex flex-col items-center gap-3 text-center">
						<EmptyVulns size={64} class="text-[var(--success)]" />
						<div class="space-y-1">
							<h3 class="text-base font-semibold text-[var(--text-bright)]">All clear</h3>
							<p class="text-sm text-[var(--text-tertiary)]">Nothing in your scope needs attention right now.</p>
						</div>
					</div>
				</div>
			{:else if activeTabTotal() === 0}
				<div class="flex flex-1 items-center justify-center py-16">
					<div class="flex flex-col items-center gap-3 text-center">
						<EmptyVulns size={64} class="text-[var(--success)]" />
						<div class="space-y-1">
							<h3 class="text-base font-semibold text-[var(--text-bright)]">No {activeTabLabel()}s need attention</h3>
							<p class="text-sm text-[var(--text-tertiary)]">Switch tab or check back after the next scan.</p>
						</div>
					</div>
				</div>
			{:else}
				<!-- Fix now -->
				{#if fixNowFiltered().length > 0}
					<div class="tier" data-tier="fix-now">
						<div class="tier-head">
							<ShieldAlert size={18} class="text-[var(--error)]" />
							<h3 class="tier-title">Fix now</h3>
							<span class="badge">{fixNowFiltered().length}</span>
						</div>
						<div class="tier-rows">
							{#each fixNowFiltered() as row}
								{@const Icon = rowIcon(row.asset_type)}
								<a class="row" href={rowHref(row)}>
									<div class="row-asset">
										<Icon size={16} class="text-[var(--text-muted)]" />
										<span class="asset-slug">{row.asset_slug}</span>
										<span class="badge">{row.asset_type}</span>
									</div>
									<div class="row-scores">
										<span class="threat" data-level="critical">Threat {row.threat_score}</span>
										<span class="trust" style="color: {trustColor(row.trust_grade)}">Trust {row.trust_grade}</span>
									</div>
									<div class="row-reasons">
										{#each row.reasons.slice(0, 2) as reason}
											<span class={reasonPillClass(reason.id)}>{renderReason(reason)}</span>
										{/each}
									</div>
								</a>
							{/each}
						</div>
					</div>
				{/if}

				<!-- This week -->
				{#if thisWeekFiltered().length > 0}
					<div class="tier" data-tier="this-week">
						<div class="tier-head">
							<AlertTriangle size={18} class="text-[var(--warning)]" />
							<h3 class="tier-title">This week</h3>
							<span class="badge">{thisWeekFiltered().length}</span>
						</div>
						<div class="tier-rows">
							{#each thisWeekFiltered() as row}
								{@const Icon = rowIcon(row.asset_type)}
								<a class="row" href={rowHref(row)}>
									<div class="row-asset">
										<Icon size={16} class="text-[var(--text-muted)]" />
										<span class="asset-slug">{row.asset_slug}</span>
										<span class="badge">{row.asset_type}</span>
									</div>
									<div class="row-scores">
										<span class="threat" data-level="warning">Threat {row.threat_score}</span>
										<span class="trust" style="color: {trustColor(row.trust_grade)}">Trust {row.trust_grade}</span>
									</div>
									<div class="row-reasons">
										{#each row.reasons.slice(0, 2) as reason}
											<span class={reasonPillClass(reason.id)}>{renderReason(reason)}</span>
										{/each}
									</div>
								</a>
							{/each}
						</div>
					</div>
				{/if}

				<!-- Watch -->
				<div class="tier" data-tier="watch">
					<div class="tier-head">
						<Eye size={18} class="text-[var(--text-muted)]" />
						<h3 class="tier-title">Watch</h3>
						<span class="badge">{triage.watch.counts.total}</span>
						<div class="watch-search">
							<Search size={13} class="search-icon" />
							<input
								type="text"
								class="input"
								placeholder="Filter watch tier…"
								bind:value={watchSearch}
								oninput={onSearchInput}
							/>
						</div>
					</div>

					{#if watchFiltered().length === 0}
						<div class="watch-empty">
							{#if watchSearch.trim()}
								No watch-tier assets match "{watchSearch}".
							{:else if activeTab !== 'all'}
								No {activeTab} assets in the watch tier.
							{:else}
								No additional warnings beyond the urgent tiers.
							{/if}
						</div>
					{:else}
						<div class="tier-rows compact">
							{#each watchFiltered() as row}
								{@const Icon = rowIcon(row.asset_type)}
								<a class="row" href={rowHref(row)}>
									<div class="row-asset">
										<Icon size={14} class="text-[var(--text-muted)]" />
										<span class="asset-slug">{row.asset_slug}</span>
										<span class="badge">{row.asset_type}</span>
									</div>
									<div class="row-scores">
										<span class="threat" data-level="info">Threat {row.threat_score}</span>
										<span class="trust" style="color: {trustColor(row.trust_grade)}">Trust {row.trust_grade}</span>
									</div>
									<div class="row-reasons">
										{#if row.reasons.length > 0}
											<span class={reasonPillClass(row.reasons[0].id)}>{renderReason(row.reasons[0])}</span>
										{/if}
									</div>
								</a>
							{/each}
						</div>

						{#if triage.watch.counts.total > triage.watch.limit}
							<div class="pagination">
								<button type="button" class="btn btn-ghost" onclick={goPrevPage} disabled={watchOffset === 0}>← Prev</button>
								<span class="pagination-info">
									{watchOffset + 1}–{Math.min(watchOffset + triage.watch.limit, triage.watch.counts.total)} of {triage.watch.counts.total}
								</span>
								<button type="button" class="btn btn-ghost" onclick={goNextPage} disabled={watchOffset + triage.watch.limit >= triage.watch.counts.total}>Next →</button>
							</div>
						{/if}
					{/if}
				</div>
			{/if}
		</section>
	{/if}
</div>

<style>
	.tier {
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
	}
	.tier-head {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0 0.25rem;
	}
	.tier[data-tier='fix-now'] .tier-head {
		border-left: 3px solid var(--error);
		padding-left: 0.6rem;
	}
	.tier[data-tier='this-week'] .tier-head {
		border-left: 3px solid var(--warning);
		padding-left: 0.6rem;
	}
	.tier[data-tier='watch'] .tier-head {
		border-left: 3px solid var(--text-muted);
		padding-left: 0.6rem;
	}
	.tier-title {
		font-size: 0.95rem;
		font-weight: 600;
		color: var(--text-bright);
		letter-spacing: 0.02em;
	}

	.tier-rows {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}
	.row {
		display: grid;
		grid-template-columns: minmax(220px, 1fr) auto minmax(180px, 1.5fr);
		align-items: center;
		gap: 1rem;
		padding: 0.7rem 1rem;
		border: 1px solid var(--border-color);
		border-radius: 0.75rem;
		background: var(--card-bg);
		text-decoration: none;
		color: inherit;
		transition: border-color 120ms ease, background 120ms ease;
	}
	.row:hover {
		border-color: color-mix(in srgb, var(--accent) 50%, transparent);
		background: var(--hover-bg-subtle);
	}
	.tier-rows.compact .row {
		padding: 0.4rem 0.85rem;
		font-size: 0.85rem;
	}
	.tier[data-tier='fix-now'] .row {
		border-color: color-mix(in srgb, var(--error) 35%, var(--border-color));
	}
	.tier[data-tier='this-week'] .row {
		border-color: color-mix(in srgb, var(--warning) 28%, var(--border-color));
	}

	.row-asset {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		min-width: 0;
	}
	.asset-slug {
		font-weight: 600;
		color: var(--text-bright);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.row-scores {
		display: inline-flex;
		gap: 0.5rem;
		font-size: 0.75rem;
		font-weight: 600;
		white-space: nowrap;
	}
	.threat[data-level='critical'] {
		color: var(--error);
	}
	.threat[data-level='warning'] {
		color: var(--warning);
	}
	.threat[data-level='info'] {
		color: var(--text-secondary);
	}

	.row-reasons {
		display: flex;
		flex-wrap: wrap;
		gap: 0.35rem;
		justify-content: flex-end;
	}

	/* Inline search input — extends the global .input class with
	   tighter dimensions so it sits next to the tier badge rather
	   than dominating the section header. */
	.watch-search {
		margin-left: auto;
		position: relative;
		display: inline-flex;
		align-items: center;
	}
	.watch-search :global(.search-icon) {
		position: absolute;
		left: 0.7rem;
		color: var(--text-muted);
		pointer-events: none;
	}
	.watch-search input.input {
		min-width: 200px;
		padding: 0.4rem 0.85rem 0.4rem 1.85rem;
		font-size: 0.8rem;
	}

	.watch-empty {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		padding: 1.2rem;
		border-radius: 0.75rem;
		background: var(--card-bg);
		border: 1px solid var(--border-color);
		color: var(--text-secondary);
		font-size: 0.85rem;
	}

	.pagination {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 1rem;
		padding: 0.6rem 0;
		font-size: 0.8rem;
	}
	.pagination-info {
		color: var(--text-muted);
	}
</style>
