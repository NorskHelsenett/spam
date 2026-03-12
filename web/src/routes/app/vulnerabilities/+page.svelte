<script lang="ts">
	import { goto } from '$app/navigation';
	import { browser } from '$app/environment';
	import { onMount } from 'svelte';
	import { ArrowLeft, ShieldX, ShieldAlert, Shield } from 'lucide-svelte';
	import DonutChart from '$lib/components/DonutChart.svelte';
	import LineChart from '$lib/components/LineChart.svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';
	import VulnBadges from '$lib/components/VulnBadges.svelte';
	import EmptyRepos from '$lib/components/icons/EmptyRepos.svelte';
	import EmptyVulns from '$lib/components/icons/EmptyVulns.svelte';

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
	let loading = true;
	let vulnsLoading = false;
	let error = '';
	let activeTab = 'repositories';

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

	const fmtDate = (iso: string | null) => {
		if (!iso) return '—';
		return new Date(iso).toLocaleString(undefined, {
			year: 'numeric',
			month: 'short',
			day: 'numeric',
			hour: '2-digit',
			minute: '2-digit'
		});
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

	$: if (activeTab === 'vulnerabilities') loadVulns();

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
					<ShieldX class="h-6 w-6 flex-shrink-0 text-[var(--accent)]" />
					<h1 class="text-2xl font-semibold text-[var(--text-bright)]">Vulnerabilities</h1>
				</div>
				<p class="mt-1 text-sm text-[var(--text-muted)]">
					Scan results across all SBOMs
					{#if summary?.last_scanned_at}
						· last scan {fmtDate(summary.last_scanned_at)}
					{/if}
				</p>
			</div>

			<!-- Metric cards grid -->
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
						{ value: 'vulnerabilities', label: 'Vulnerabilities' }
					]}
					bind:value={activeTab}
				/>
			</div>
		</article>

		<!-- Tab content -->
		{#if activeTab === 'repositories'}
			<div class="rounded-2xl border border-[var(--border-color)] bg-[var(--card-bg)] overflow-hidden">
				{#if repos.length === 0}
					<div class="flex flex-col items-center justify-center py-16 text-center">
						<EmptyRepos class="mb-3 text-[var(--text-muted)]" />
						<p class="text-sm font-medium text-[var(--text-secondary)]">No security scans executed</p>
						<p class="mt-1 text-xs text-[var(--text-muted)]">No scan results yet — run a scan on a repository to see results here.</p>
					</div>
				{:else}
					<div class="overflow-x-auto">
						<table class="w-full text-xs">
							<thead>
								<tr class="border-b border-[var(--border-color)] text-[var(--text-muted)] uppercase tracking-wider">
									<th class="px-5 py-3 text-left font-medium">Repository</th>
									<th class="px-4 py-3 text-right font-medium" style="color:var(--red)">Critical</th>
									<th class="px-4 py-3 text-right font-medium" style="color:var(--orange)">High</th>
									<th class="px-4 py-3 text-right font-medium" style="color:var(--yellow)">Medium</th>
									<th class="px-4 py-3 text-right font-medium" style="color:var(--blue)">Low</th>
									<th class="px-4 py-3 text-right font-medium text-[var(--text-muted)]">Last Scanned</th>
								</tr>
							</thead>
							<tbody>
								{#each repos.filter(r => r.repo_slug !== r.repo_id && r.repo_slug) as repo, i}
									<tr
										class="cursor-pointer border-b border-[var(--border-color)]/50 transition-colors hover:bg-[var(--hover-bg-subtle)] {i % 2 === 0 ? '' : 'bg-[var(--card-bg)]/30'}"
										onclick={() => openRepo(repo.repo_id)}
									>
										<td class="px-5 py-3 font-medium text-[var(--accent)] max-w-xs truncate">
											{repo.repo_slug || repo.repo_id}
										</td>
										<td class="px-4 py-3 text-right tabular-nums" style="color:var(--red)">
											{#if repo.critical_count > 0}{fmt(repo.critical_count)}{:else}<span class="text-[var(--text-muted)]">—</span>{/if}
										</td>
										<td class="px-4 py-3 text-right tabular-nums" style="color:var(--orange)">
											{#if repo.high_count > 0}{fmt(repo.high_count)}{:else}<span class="text-[var(--text-muted)]">—</span>{/if}
										</td>
										<td class="px-4 py-3 text-right tabular-nums" style="color:var(--yellow)">
											{#if repo.medium_count > 0}{fmt(repo.medium_count)}{:else}<span class="text-[var(--text-muted)]">—</span>{/if}
										</td>
										<td class="px-4 py-3 text-right tabular-nums" style="color:var(--blue)">
											{#if repo.low_count > 0}{fmt(repo.low_count)}{:else}<span class="text-[var(--text-muted)]">—</span>{/if}
										</td>
										<td class="px-4 py-3 text-right text-[var(--text-tertiary)]">
											{fmtDate(repo.last_scanned_at)}
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{/if}
			</div>

		{:else if activeTab === 'vulnerabilities'}
			<div class="rounded-2xl border border-[var(--border-color)] bg-[var(--card-bg)] overflow-hidden max-w-[90vw]">
				{#if vulnsLoading}
					<div class="flex items-center justify-center py-20">
						<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
					</div>
				{:else if groupedVulns.length === 0}
					<div class="flex flex-col items-center justify-center py-16 text-center">
						<EmptyVulns class="mb-3 text-[var(--text-muted)]" />
						<p class="text-sm font-medium text-[var(--text-secondary)]">No vulnerabilities found</p>
						<p class="mt-1 text-xs text-[var(--text-muted)]">No scan results yet — run a scan to populate this view.</p>
					</div>
				{:else}
					<table class="w-full text-xs border-collapse">
						<thead>
							<tr class="border-b border-[var(--border-color)] text-[var(--text-muted)] uppercase tracking-wider">
								<th class="px-5 py-3 text-left font-medium w-[22%]">CVE / ID</th>
								<th class="px-4 py-3 text-left font-medium w-[10%]">Severity</th>
								<th class="px-4 py-3 text-left font-medium">Package &amp; Fix</th>
								<th class="px-4 py-3 text-left font-medium w-[28%]">Affected Repos</th>
							</tr>
						</thead>
						<tbody>
							{#each groupedVulns as g, i}
								<tr class="border-b border-[var(--border-color)]/50 align-top {i % 2 === 0 ? '' : 'bg-[var(--card-bg)]/30'}">
									<!-- CVE ID + title -->
									<td class="px-5 py-3">
										<div class="space-y-1">
											<div class="flex flex-wrap items-center gap-2">
												<a
													href={vulnUrl(g.vuln_id)}
													target="_blank"
													rel="noopener noreferrer"
													class="font-mono font-semibold text-[var(--accent)] hover:underline break-all"
												>{g.vuln_id}</a>
												{#each [...g.sources] as src}
													<span class="rounded-full border border-[var(--border-color)] px-1.5 py-0.5 text-[10px] text-[var(--text-muted)] uppercase tracking-wide">{src}</span>
												{/each}
											</div>
											{#if g.title}
												<p class="text-[var(--text-muted)] leading-snug">{g.title}</p>
											{/if}
										</div>
									</td>
									<!-- Severity pill -->
									<td class="px-4 py-3 whitespace-nowrap">
										<span class="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-medium {severityClass(g.severity)} {severityIcon(g.severity).color}">
											{#if g.severity?.toUpperCase() === 'CRITICAL' || g.severity?.toUpperCase() === 'HIGH'}
												<ShieldX class="h-3 w-3" />
											{:else}
												<ShieldAlert class="h-3 w-3" />
											{/if}
											{g.severity}
										</span>
									</td>
									<!-- Package + fix (two lines) -->
									<td class="px-4 py-3">
										<div class="space-y-1">
											<p class="font-mono text-[var(--text-muted)] break-all">{g.pkg_name}{g.installed_version ? `@${g.installed_version}` : ''}</p>
											{#if g.fixed_version}
												<p class="font-mono text-green-400"><span class="text-[var(--text-muted)] font-sans">fix:</span> {g.fixed_version}</p>
											{:else}
												<p class="text-[var(--text-muted)]/50">no fix available</p>
											{/if}
										</div>
									</td>
									<!-- Affected repos -->
									<td class="px-4 py-3">
										<div class="flex flex-col gap-1">
											{#each g.repos as repo}
												<button
													type="button"
													class="text-left text-[var(--accent)] hover:underline break-all"
													onclick={() => openRepo(repo.repo_id)}
												>{repo.repo_slug}</button>
											{/each}
										</div>
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				{/if}
			</div>
		{/if}
	{/if}
</div>
