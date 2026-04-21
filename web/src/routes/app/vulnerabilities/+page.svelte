<script lang="ts">
	import { goto } from '$app/navigation';
	import { browser } from '$app/environment';
	import { onMount } from 'svelte';
	import { ArrowLeft, ShieldX, ShieldAlert, Shield, GitBranch, Container, SlidersHorizontal, Search } from 'lucide-svelte';
	import { slide } from 'svelte/transition';
	import { cubicOut } from 'svelte/easing';
	import DonutChart from '$lib/components/DonutChart.svelte';
	import LineChart from '$lib/components/LineChart.svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';
	import VulnBadges from '$lib/components/VulnBadges.svelte';
	import EmptyRepos from '$lib/components/icons/EmptyRepos.svelte';
	import EmptyVulns from '$lib/components/icons/EmptyVulns.svelte';
	import ImageDrawer from '$lib/components/ImageDrawer.svelte';
	import Toggle from '$lib/components/Toggle.svelte';

	type TrendPoint = {
		date: string;
		critical: number;
		high: number;
		medium: number;
		low: number;
	};

	type Summary = {
		total_vulns: number;
		total_critical: number;
		total_high: number;
		total_medium: number;
		total_low: number;
		total_unknown: number;
		scanned_sboms: number;
		last_scanned_at: string | null;
	};

	type RepoRow = {
		repo_id: string;
		repo_slug: string;
		critical_count: number;
		high_count: number;
		medium_count: number;
		low_count: number;
		unknown_count: number;
		last_scanned_at: string | null;
	};

	type ImageRow = {
		registry: string;
		image: string;
		digest: string;
		digest_id?: string;
		tags: string;
		cluster_count: number;
		namespace_count: number;
		container_count: number;
		last_seen: string;
		vuln_critical: number;
		vuln_high: number;
		vuln_medium: number;
		vuln_low: number;
		vuln_unknown: number;
	};

	type VulnRow = {
		repo_id: string;
		repo_slug: string;
		vuln_id: string;
		severity: string;
		pkg_name: string;
		installed_version: string;
		fixed_version: string;
		title: string;
		source: string;
	};

	type VulnGroup = {
		vuln_id: string;
		severity: string;
		pkg_name: string;
		installed_version: string;
		fixed_version: string;
		title: string;
		sources: Set<string>;
		repos: Array<{ repo_id: string; repo_slug: string }>;
	};

	let summary: Summary | null = null;
	let repos: RepoRow[] = [];
	let trend: TrendPoint[] = [];
	let vulns: VulnRow[] = [];
	let images: ImageRow[] = [];
	let hideClean = true;
	let loading = true;
	let vulnsLoading = false;
	let imagesLoading = false;
	let error = '';
	let activeTab = 'repositories';
	let imageDrawerOpen = false;
	let imageDrawerId = '';

	// --- Virtual scroll helpers for tables ---
	// ROW_HEIGHT = flat single-line rows (repos, images). VULN_ROW_HEIGHT
	// is taller because those rows stack title+pkg+fix inside one tr.
	// OVERSCAN keeps a handful of rows rendered above/below the viewport
	// so fast scrolls don't flash empty rows while the slice updates.
	const ROW_HEIGHT = 48;
	const VULN_ROW_HEIGHT = 96;
	const OVERSCAN = 10;

	type Virt = { start: number; end: number; topPad: number; bottomPad: number };
	function virtSlice(total: number, rowHeight: number, scrollTop: number, viewH: number): Virt {
		const start = Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN);
		const end = Math.min(total, Math.ceil((scrollTop + viewH) / rowHeight) + OVERSCAN);
		return {
			start,
			end,
			topPad: start * rowHeight,
			bottomPad: Math.max(0, (total - end) * rowHeight),
		};
	}

	let repoScrollEl: HTMLDivElement | undefined;
	let repoScrollTop = 0;
	let repoViewH = 600;
	let imageScrollEl: HTMLDivElement | undefined;
	let imageScrollTop = 0;
	let imageViewH = 600;
	let vulnScrollEl: HTMLDivElement | undefined;
	let vulnScrollTop = 0;
	let vulnViewH = 600;

	// Per-tab search state. Each tab owns its own filter-open toggle + query
	// so switching tabs doesn't clobber the other's filter.
	let repoFilterOpen = false;
	let repoSearch = '';
	let imageFilterOpen = false;
	let imageSearch = '';
	let vulnFilterOpen = false;
	let vulnSearch = '';

	const includesCI = (haystack: string | undefined | null, needle: string) =>
		(haystack ?? '').toLowerCase().includes(needle.toLowerCase());

	const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };

	$: groupedVulns = (() => {
		const map = new Map<string, VulnGroup>();
		for (const v of vulns.filter((v) => v.repo_slug !== v.repo_id && v.repo_slug)) {
			if (!map.has(v.vuln_id)) {
				map.set(v.vuln_id, {
					vuln_id: v.vuln_id,
					severity: v.severity,
					pkg_name: v.pkg_name,
					installed_version: v.installed_version,
					fixed_version: v.fixed_version,
					title: v.title,
					sources: new Set<string>(),
					repos: []
				});
			}
			const g = map.get(v.vuln_id)!;
			if (v.source) g.sources.add(v.source);
			if (!g.repos.find((r) => r.repo_id === v.repo_id)) {
				g.repos.push({ repo_id: v.repo_id, repo_slug: v.repo_slug });
			}
		}
		return Array.from(map.values()).sort(
			(a, b) =>
				(severityOrder[a.severity?.toUpperCase()] ?? 4) -
				(severityOrder[b.severity?.toUpperCase()] ?? 4)
		);
	})();

	const vulnUrl = (id: string) => {
		if (id.startsWith('CVE-')) return `https://www.cve.org/CVERecord?id=${id}`;
		return `https://osv.dev/vulnerability/${id}`;
	};

	const fmt = (n: number) => n.toLocaleString('en-US').replace(/,/g, ' ');

	const fmtRelative = (iso: string | null) => {
		if (!iso) return '—';
		const diff = Date.now() - new Date(iso).getTime();
		const days = Math.floor(diff / 86_400_000);
		if (days === 0) return 'today';
		if (days === 1) return 'yesterday';
		if (days < 30) return `${days}d ago`;
		return `${Math.floor(days / 30)}mo ago`;
	};

	const openRepo = (repoId: string) => {
		if (!repoId) return;
		goto(`/app/providers/repo?repo_id=${encodeURIComponent(repoId)}`);
	};

	const goBack = () => {
		if (browser) history.back();
	};

	const severityClass = (s: string) => {
		switch (s?.toUpperCase()) {
			case 'CRITICAL': return 'border-red-500/30 bg-red-500/5';
			case 'HIGH':     return 'border-orange-500/30 bg-orange-500/5';
			case 'MEDIUM':   return 'border-yellow-500/30 bg-yellow-500/5';
			case 'LOW':      return 'border-[var(--border-color)]/50 bg-transparent';
			default:         return 'border-[var(--border-color)]/40 bg-transparent';
		}
	};

	const severityIcon = (s: string) => {
		switch (s?.toUpperCase()) {
			case 'CRITICAL': return { color: 'text-red-400' };
			case 'HIGH':     return { color: 'text-orange-400' };
			case 'MEDIUM':   return { color: 'text-yellow-400' };
			default:         return { color: 'text-[var(--text-muted)]' };
		}
	};

	const loadVulns = async () => {
		if (vulns.length > 0) return;
		vulnsLoading = true;
		try {
			const res = await fetch('/api/vuln/list', { credentials: 'include' });
			if (res.ok) vulns = await res.json();
		} catch {
			// ignore
		} finally {
			vulnsLoading = false;
		}
	};

	const loadImages = async () => {
		if (images.length > 0) return;
		imagesLoading = true;
		try {
			const res = await fetch('/api/clusters/images/detail', { credentials: 'include' });
			if (res.ok) images = (await res.json()) ?? [];
		} catch {
			// ignore
		} finally {
			imagesLoading = false;
		}
	};

	$: if (activeTab === 'vulnerabilities') loadVulns();
	$: if (activeTab === 'images') loadImages();

	// Images filtered + sorted by severity weight (critical > high > medium > low).
	$: filteredImages = (() => {
		const w = (img: ImageRow) =>
			img.vuln_critical * 1e9 + img.vuln_high * 1e6 + img.vuln_medium * 1e3 + img.vuln_low;
		let list = hideClean ? images.filter((i) => w(i) > 0) : images.slice();
		const q = imageSearch.trim();
		if (q) list = list.filter((i) => includesCI(i.registry, q) || includesCI(i.image, q) || includesCI(i.digest, q) || includesCI(i.tags, q));
		return list.sort((a, b) => w(b) - w(a));
	})();

	// Repo table has an inline .filter(...) in the template; hoist it
	// so the virt slice math uses the same list the UI renders.
	$: filteredRepos = (() => {
		let list = repos.filter((r) => r.repo_slug !== r.repo_id && r.repo_slug);
		const q = repoSearch.trim();
		if (q) list = list.filter((r) => includesCI(r.repo_slug, q));
		return list;
	})();

	// Vuln table — search across ID, title, package name.
	$: filteredVulns = (() => {
		const q = vulnSearch.trim();
		if (!q) return groupedVulns;
		return groupedVulns.filter((g) =>
			includesCI(g.vuln_id, q) ||
			includesCI(g.title, q) ||
			includesCI(g.pkg_name, q) ||
			g.repos.some((r) => includesCI(r.repo_slug, q))
		);
	})();

	$: repoVirt = virtSlice(filteredRepos.length, ROW_HEIGHT, repoScrollTop, repoViewH);
	$: imageVirt = virtSlice(filteredImages.length, ROW_HEIGHT, imageScrollTop, imageViewH);
	$: vulnVirt = virtSlice(filteredVulns.length, VULN_ROW_HEIGHT, vulnScrollTop, vulnViewH);

	const shortDigest = (d: string) => (d && d.length > 14 ? d.slice(0, 14) + '…' : d ?? '');
	const parseTags = (t: string) => (t ? t.split(',').map((x) => x.trim()).filter(Boolean) : []);

	const openImageDrawer = (digestId: string | undefined) => {
		if (!digestId) return;
		if (imageDrawerOpen && imageDrawerId === digestId) {
			imageDrawerOpen = false;
			imageDrawerId = '';
		} else {
			imageDrawerId = digestId;
			imageDrawerOpen = true;
		}
	};

	onMount(async () => {
		try {
			const [sumRes, reposRes, trendRes] = await Promise.all([
				fetch('/api/vuln/summary', { credentials: 'include' }),
				fetch('/api/vuln/repos', { credentials: 'include' }),
				fetch('/api/vuln/trend?days=30', { credentials: 'include' })
			]);

			if (!sumRes.ok || !reposRes.ok || !trendRes.ok) {
				error = 'Failed to load vulnerability data';
				return;
			}

			summary = await sumRes.json();
			repos = await reposRes.json();
			trend = await trendRes.json();
		} catch (e) {
			error = 'Failed to fetch data';
		} finally {
			loading = false;
		}
	});
</script>

<svelte:head>
	<title>Vulnerabilities — Spam Monitor</title>
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
		<header>
			<div class="flex items-center gap-3">
				<ShieldX class="h-10 w-10 flex-shrink-0 text-[var(--accent)]" />
				<div>
					<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Vulnerabilities</h1>
					<p class="text-sm text-[var(--text-tertiary)]">Scan results across all SBOMs.</p>
				</div>
			</div>
		</header>

		{#if loading}
			<div class="flex items-center justify-center py-20">
				<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
			</div>
		{:else if error}
			<div class="rounded-2xl border border-[var(--red)]/30 bg-[var(--red)]/10 px-4 py-3 text-sm text-[var(--red)]">{error}</div>
		{:else}
			<!-- Metric cards -->
			<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Total</h3>
					<p class="text-3xl font-bold text-[var(--text-bright)]">{fmt(summary?.total_vulns ?? 0)}</p>
					<p class="text-xs text-[var(--text-muted)]">across {summary?.scanned_sboms ?? 0} SBOMs</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Critical</h3>
					<p class="text-3xl font-bold text-red-500">{fmt(summary?.total_critical ?? 0)}</p>
					<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><ShieldX class="h-3 w-3 text-red-500" /> Immediate action required</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">High</h3>
					<p class="text-3xl font-bold text-orange-500">{fmt(summary?.total_high ?? 0)}</p>
					<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><ShieldAlert class="h-3 w-3 text-orange-500" /> High severity</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Medium</h3>
					<p class="text-3xl font-bold text-yellow-500">{fmt(summary?.total_medium ?? 0)}</p>
					<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><Shield class="h-3 w-3 text-yellow-500" /> Needs scheduled remediation</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Low + Unknown</h3>
					<p class="text-3xl font-bold text-[var(--text-secondary)]">{fmt((summary?.total_low ?? 0) + (summary?.total_unknown ?? 0))}</p>
					<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><Shield class="h-3 w-3 text-[var(--text-secondary)]" /> Lower priority or unclassified</p>
				</div>
			</div>

			<!-- Charts -->
			<div class="grid grid-cols-1 gap-6 lg:grid-cols-3">
				<div class="metric-card rounded-2xl p-5">
					{#if summary}
						<DonutChart
							title="Severity distribution"
							total={summary.total_vulns}
							segments={[
								{ label: 'Critical', value: summary.total_critical, color: 'var(--red)' },
								{ label: 'High', value: summary.total_high, color: 'var(--orange)' },
								{ label: 'Medium', value: summary.total_medium, color: 'var(--yellow)' },
								{ label: 'Low', value: summary.total_low, color: 'var(--blue)' },
								{ label: 'Unknown', value: summary.total_unknown, color: 'var(--gray)' }
							]}
						/>
					{/if}
				</div>
				<div class="metric-card rounded-2xl p-5 lg:col-span-2">
					<LineChart title="30-day trend" data={trend} />
				</div>
			</div>

			<!-- Tab selector -->
			<div class="pt-2">
				<TabSelector
					options={[
						{ value: 'repositories', label: 'Repositories' },
						{ value: 'images', label: 'Images' },
						{ value: 'vulnerabilities', label: 'Vulnerabilities' }
					]}
					bind:value={activeTab}
				/>
			</div>
		{/if}
	</article>

	<!-- Table panel -->
	{#if !loading && !error}
		<section class="panel-surface flex flex-col gap-6 px-6 py-8 sm:px-10 sm:py-10 h-[calc(100vh-7rem)]">
			<header class="flex items-start justify-between gap-4">
				<div>
					<h2 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Findings</h2>
					<p class="text-sm text-[var(--text-tertiary)]">Vulnerability scan results from the latest scans.</p>
				</div>
				{#if activeTab === 'repositories' && repos.length > 0}
					<button
						type="button"
						class="filter-toggle"
						class:active={repoFilterOpen}
						onclick={() => (repoFilterOpen = !repoFilterOpen)}
						aria-expanded={repoFilterOpen}
						aria-label="Toggle filters"
					>
						<SlidersHorizontal size={14} />
						<span>Filters</span>
						{#if repoSearch.trim()}<span class="filter-badge">1</span>{/if}
					</button>
				{:else if activeTab === 'images' && images.length > 0}
					<button
						type="button"
						class="filter-toggle"
						class:active={imageFilterOpen}
						onclick={() => (imageFilterOpen = !imageFilterOpen)}
						aria-expanded={imageFilterOpen}
						aria-label="Toggle filters"
					>
						<SlidersHorizontal size={14} />
						<span>Filters</span>
						{#if imageSearch.trim()}<span class="filter-badge">1</span>{/if}
					</button>
				{:else if activeTab === 'vulnerabilities' && groupedVulns.length > 0}
					<button
						type="button"
						class="filter-toggle"
						class:active={vulnFilterOpen}
						onclick={() => (vulnFilterOpen = !vulnFilterOpen)}
						aria-expanded={vulnFilterOpen}
						aria-label="Toggle filters"
					>
						<SlidersHorizontal size={14} />
						<span>Filters</span>
						{#if vulnSearch.trim()}<span class="filter-badge">1</span>{/if}
					</button>
				{/if}
			</header>

			{#if activeTab === 'repositories' && repoFilterOpen}
				<div transition:slide={{ duration: 220, easing: cubicOut }}>
					<div class="relative flex items-center">
						<Search size={13} class="pointer-events-none absolute left-3 text-[var(--text-muted)]" />
						<input
							type="text"
							class="filter-search-input"
							placeholder="Search by repo slug…"
							bind:value={repoSearch}
						/>
					</div>
				</div>
			{:else if activeTab === 'images' && imageFilterOpen}
				<div transition:slide={{ duration: 220, easing: cubicOut }} class="space-y-3">
					<div class="relative flex items-center">
						<Search size={13} class="pointer-events-none absolute left-3 text-[var(--text-muted)]" />
						<input
							type="text"
							class="filter-search-input"
							placeholder="Search registry, image, digest, tag…"
							bind:value={imageSearch}
						/>
					</div>
					<div class="flex items-center justify-between gap-3">
						<p class="text-xs text-[var(--text-muted)]">Showing {filteredImages.length} of {images.length}</p>
						<Toggle bind:checked={hideClean} label="Hide clean images" />
					</div>
				</div>
			{:else if activeTab === 'vulnerabilities' && vulnFilterOpen}
				<div transition:slide={{ duration: 220, easing: cubicOut }}>
					<div class="relative flex items-center">
						<Search size={13} class="pointer-events-none absolute left-3 text-[var(--text-muted)]" />
						<input
							type="text"
							class="filter-search-input"
							placeholder="Search CVE id, title, package, repo…"
							bind:value={vulnSearch}
						/>
					</div>
				</div>
			{/if}

			{#if activeTab === 'repositories'}
				{#if repos.length === 0}
					<div class="flex flex-1 items-center justify-center">
						<div class="flex flex-col items-center gap-3 text-center">
							<EmptyRepos class="text-[var(--text-muted)]" />
							<p class="text-sm text-[var(--text-muted)]">No security scans executed.</p>
						</div>
					</div>
				{:else}
					<div class="relative flex flex-1 flex-col overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
						<div class="flex-1 overflow-y-auto [overflow-anchor:none]" bind:this={repoScrollEl} onscroll={() => { repoScrollTop = repoScrollEl?.scrollTop ?? 0; repoViewH = repoScrollEl?.clientHeight ?? 600; }}>
							<table class="min-w-full table-fixed divide-y divide-[var(--border-color)]/60 text-sm">
								<thead class="sticky top-0 z-[1] bg-[var(--card-bg)] text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
									<tr>
										<th class="w-[40%] px-5 py-3 text-left">Repository</th>
										<th class="w-[12%] px-5 py-3 text-right" style="color:var(--red)">Critical</th>
										<th class="w-[12%] px-5 py-3 text-right" style="color:var(--orange)">High</th>
										<th class="w-[12%] px-5 py-3 text-right" style="color:var(--yellow)">Medium</th>
										<th class="w-[12%] px-5 py-3 text-right" style="color:var(--blue)">Low</th>
										<th class="w-[12%] px-5 py-3 text-right">Last Scanned</th>
									</tr>
								</thead>
								<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
									{#if repoVirt.topPad > 0}<tr style="height:{repoVirt.topPad}px"><td colspan="6"></td></tr>{/if}
									{#each filteredRepos.slice(repoVirt.start, repoVirt.end) as repo}
										<tr
											class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)]"
											style="height:{ROW_HEIGHT}px"
											onclick={() => openRepo(repo.repo_id)}
										>
											<td class="px-5 py-3">
												<div class="flex items-center gap-2">
													<GitBranch class="h-4 w-4 shrink-0 text-[var(--accent)]" />
													<span class="font-semibold text-[var(--text-bright)]">{repo.repo_slug}</span>
												</div>
											</td>
											<td class="px-5 py-3 text-right tabular-nums">
												{#if repo.critical_count > 0}
													<span class="inline-flex items-center rounded-full bg-red-500/10 px-2.5 py-0.5 text-xs font-semibold tabular-nums text-red-400">{fmt(repo.critical_count)}</span>
												{:else}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right tabular-nums">
												{#if repo.high_count > 0}
													<span class="inline-flex items-center rounded-full bg-orange-500/10 px-2.5 py-0.5 text-xs font-semibold tabular-nums text-orange-400">{fmt(repo.high_count)}</span>
												{:else}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right tabular-nums">
												{#if repo.medium_count > 0}
													<span class="inline-flex items-center rounded-full bg-yellow-500/10 px-2.5 py-0.5 text-xs font-semibold tabular-nums text-yellow-400">{fmt(repo.medium_count)}</span>
												{:else}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right tabular-nums">
												{#if repo.low_count > 0}
													<span class="inline-flex items-center rounded-full bg-blue-500/10 px-2.5 py-0.5 text-xs font-semibold tabular-nums text-blue-400">{fmt(repo.low_count)}</span>
												{:else}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right text-xs text-[var(--text-muted)]" title={repo.last_scanned_at ?? ''}>
												{fmtRelative(repo.last_scanned_at)}
											</td>
										</tr>
									{/each}
									{#if repoVirt.bottomPad > 0}<tr style="height:{repoVirt.bottomPad}px"><td colspan="6"></td></tr>{/if}
								</tbody>
							</table>
						</div>
					</div>
				{/if}

			{:else if activeTab === 'images'}
				{#if imagesLoading}
					<div class="flex flex-1 items-center justify-center">
						<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
					</div>
				{:else if filteredImages.length === 0}
					<div class="flex flex-1 items-center justify-center">
						<div class="flex flex-col items-center gap-3 text-center">
							<Container class="h-10 w-10 text-[var(--text-muted)]" />
							<p class="text-sm text-[var(--text-muted)]">{hideClean ? 'No images with vulnerabilities.' : 'No images.'}</p>
							{#if hideClean && images.length > 0}
								<button type="button" class="text-xs text-[var(--accent)] hover:underline" onclick={() => (hideClean = false)}>Show clean images</button>
							{/if}
						</div>
					</div>
				{:else}
					<div class="relative flex flex-1 flex-col overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
						<div class="flex-1 overflow-y-auto [overflow-anchor:none]" bind:this={imageScrollEl} onscroll={() => { imageScrollTop = imageScrollEl?.scrollTop ?? 0; imageViewH = imageScrollEl?.clientHeight ?? 600; }}>
							<table class="min-w-full table-fixed divide-y divide-[var(--border-color)]/60 text-sm">
								<thead class="sticky top-0 z-[1] bg-[var(--card-bg)] text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
									<tr>
										<th class="w-[14%] px-5 py-3 text-left">Registry</th>
										<th class="w-[32%] px-5 py-3 text-left">Image</th>
										<th class="w-[14%] px-5 py-3 text-left">Digest</th>
										<th class="w-[7%] px-5 py-3 text-right" style="color:var(--red)">Critical</th>
										<th class="w-[7%] px-5 py-3 text-right" style="color:var(--orange)">High</th>
										<th class="w-[7%] px-5 py-3 text-right" style="color:var(--yellow)">Medium</th>
										<th class="w-[7%] px-5 py-3 text-right" style="color:var(--blue)">Low</th>
										<th class="w-[12%] px-5 py-3 text-right">Last seen</th>
									</tr>
								</thead>
								<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
									{#if imageVirt.topPad > 0}<tr style="height:{imageVirt.topPad}px"><td colspan="8"></td></tr>{/if}
									{#each filteredImages.slice(imageVirt.start, imageVirt.end) as img}
										<tr
											class="transition hover:bg-[var(--hover-bg-subtle)] {img.digest_id ? 'cursor-pointer' : ''} {imageDrawerOpen && imageDrawerId === img.digest_id ? 'bg-[var(--hover-bg-subtle)]' : ''}"
											style="height:{ROW_HEIGHT}px"
											onclick={() => openImageDrawer(img.digest_id)}
										>
											<td class="truncate px-5 py-3 text-xs text-[var(--text-tertiary)]" title={img.registry}>{img.registry}</td>
											<td class="truncate px-5 py-3 font-semibold text-[var(--text-bright)]" title={img.image}>{img.image}</td>
											<td class="px-5 py-3">
												{#if img.digest}
													<code class="rounded bg-[var(--hover-bg)] px-1.5 py-0.5 text-xs text-[var(--text-secondary)]">{shortDigest(img.digest)}</code>
												{:else}
													<span class="text-xs text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right tabular-nums">
												{#if img.vuln_critical > 0}
													<span class="inline-flex items-center rounded-full bg-red-500/10 px-2.5 py-0.5 text-xs font-semibold text-red-400">{fmt(img.vuln_critical)}</span>
												{:else}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right tabular-nums">
												{#if img.vuln_high > 0}
													<span class="inline-flex items-center rounded-full bg-orange-500/10 px-2.5 py-0.5 text-xs font-semibold text-orange-400">{fmt(img.vuln_high)}</span>
												{:else}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right tabular-nums">
												{#if img.vuln_medium > 0}
													<span class="inline-flex items-center rounded-full bg-yellow-500/10 px-2.5 py-0.5 text-xs font-semibold text-yellow-400">{fmt(img.vuln_medium)}</span>
												{:else}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right tabular-nums">
												{#if img.vuln_low > 0}
													<span class="inline-flex items-center rounded-full bg-blue-500/10 px-2.5 py-0.5 text-xs font-semibold text-blue-400">{fmt(img.vuln_low)}</span>
												{:else}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right text-xs text-[var(--text-muted)]" title={img.last_seen}>
												{fmtRelative(img.last_seen)}
											</td>
										</tr>
									{/each}
									{#if imageVirt.bottomPad > 0}<tr style="height:{imageVirt.bottomPad}px"><td colspan="8"></td></tr>{/if}
								</tbody>
							</table>
						</div>
					</div>

					{#if imageDrawerOpen && imageDrawerId}
						<div class="fixed top-2 bottom-2 right-2 z-50 flex w-[620px] flex-col overflow-hidden rounded-[10px] border border-[var(--border-color)] bg-[var(--bg-soft)] shadow-xl">
							<ImageDrawer imageId={imageDrawerId} onClose={() => { imageDrawerOpen = false; imageDrawerId = ''; }} />
						</div>
					{/if}
				{/if}

			{:else if activeTab === 'vulnerabilities'}
				{#if vulnsLoading}
					<div class="flex flex-1 items-center justify-center">
						<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
					</div>
				{:else if groupedVulns.length === 0}
					<div class="flex flex-1 items-center justify-center">
						<div class="flex flex-col items-center gap-3 text-center">
							<EmptyVulns class="text-[var(--text-muted)]" />
							<p class="text-sm text-[var(--text-muted)]">No vulnerabilities found.</p>
						</div>
					</div>
				{:else}
					<div class="relative flex flex-1 flex-col overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
						<div class="flex-1 overflow-y-auto [overflow-anchor:none]" bind:this={vulnScrollEl} onscroll={() => { vulnScrollTop = vulnScrollEl?.scrollTop ?? 0; vulnViewH = vulnScrollEl?.clientHeight ?? 600; }}>
							<table class="min-w-full table-fixed divide-y divide-[var(--border-color)]/60 text-sm">
								<thead class="sticky top-0 z-[1] bg-[var(--card-bg)] text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
									<tr>
										<th class="px-5 py-3 text-left w-[22%]">CVE / ID</th>
										<th class="px-5 py-3 text-left w-[10%]">Severity</th>
										<th class="px-5 py-3 text-left">Package &amp; Fix</th>
										<th class="px-5 py-3 text-left w-[28%]">Affected Repos</th>
									</tr>
								</thead>
								<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
									{#if vulnVirt.topPad > 0}<tr style="height:{vulnVirt.topPad}px"><td colspan="4"></td></tr>{/if}
									{#each filteredVulns.slice(vulnVirt.start, vulnVirt.end) as g}
										<tr class="align-top transition hover:bg-[var(--hover-bg-subtle)] overflow-hidden" style="height:{VULN_ROW_HEIGHT}px">
											<td class="px-5 py-3">
												<div class="flex flex-wrap items-center gap-2">
													<a
														href={vulnUrl(g.vuln_id)}
														target="_blank"
														rel="noopener noreferrer"
														class="font-mono font-semibold text-[var(--accent)] hover:underline break-all"
													>{g.vuln_id}</a>
													{#each [...g.sources] as src}
														<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-1.5 py-0.5 text-xs">{src}</span>
													{/each}
												</div>
												{#if g.title}
													<p class="mt-0.5 text-xs text-[var(--text-muted)] leading-snug">{g.title}</p>
												{/if}
											</td>
											<td class="px-5 py-3 whitespace-nowrap">
												<span class="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium {severityClass(g.severity)} {severityIcon(g.severity).color}">
													{#if g.severity?.toUpperCase() === 'CRITICAL' || g.severity?.toUpperCase() === 'HIGH'}
														<ShieldX class="h-3 w-3" />
													{:else}
														<ShieldAlert class="h-3 w-3" />
													{/if}
													{g.severity}
												</span>
											</td>
											<td class="px-5 py-3">
												<p class="font-mono text-xs text-[var(--text-muted)] break-all">{g.pkg_name}{g.installed_version ? `@${g.installed_version}` : ''}</p>
												{#if g.fixed_version}
													<p class="mt-0.5 font-mono text-xs text-green-400"><span class="font-sans text-[var(--text-muted)]">fix:</span> {g.fixed_version}</p>
												{:else}
													<p class="mt-0.5 text-xs text-[var(--text-muted)]/50">no fix available</p>
												{/if}
											</td>
											<td class="px-5 py-3">
												<div class="flex flex-col gap-1">
													{#each g.repos as repo}
														<button
															type="button"
															class="text-left text-xs text-[var(--accent)] hover:underline break-all"
															onclick={() => openRepo(repo.repo_id)}
														>{repo.repo_slug}</button>
													{/each}
												</div>
											</td>
										</tr>
									{/each}
									{#if vulnVirt.bottomPad > 0}<tr style="height:{vulnVirt.bottomPad}px"><td colspan="4"></td></tr>{/if}
								</tbody>
							</table>
						</div>
					</div>
				{/if}
			{/if}
		</section>
	{/if}
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
	.filter-toggle:hover { color: var(--text-bright); border-color: var(--text-tertiary); }
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
	.filter-search-input {
		width: 100%;
		padding: 0.5rem 0.75rem 0.5rem 2rem;
		border-radius: 8px;
		border: 1px solid var(--border-color);
		background: var(--card-bg);
		color: var(--text-primary);
		font-size: 0.85rem;
		outline: none;
		transition: border-color 150ms ease;
	}
	.filter-search-input:focus { border-color: var(--accent); }
</style>
