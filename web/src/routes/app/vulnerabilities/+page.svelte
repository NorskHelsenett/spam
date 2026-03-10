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
	};

	let summary: Summary | null = null;
	let repos: RepoRow[] = [];
	let trend: TrendPoint[] = [];
	let vulns: VulnRow[] = [];
	let loading = true;
	let vulnsLoading = false;
	let error = '';
	let activeTab = 'repositories';

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
					Trivy scan results across all SBOMs
					{#if summary?.last_scanned_at}
						· last scan {fmtDate(summary.last_scanned_at)}
					{/if}
				</p>
			</div>

			<!-- Metric cards grid -->
			<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
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
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Medium + Low</h3>
					<p class="text-3xl font-bold text-yellow-500">{fmt((summary?.total_medium ?? 0) + (summary?.total_low ?? 0))}</p>
					<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><Shield class="h-3 w-3 text-yellow-500" /> Lower severity</p>
				</div>
			</div>

			<!-- Charts -->
			<div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
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
				<div class="metric-card rounded-2xl p-5">
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
			<div class="rounded-2xl border border-[var(--border-color)] bg-[var(--card-bg)] overflow-hidden">
				{#if vulnsLoading}
					<div class="flex items-center justify-center py-20">
						<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
					</div>
				{:else if vulns.length === 0}
					<div class="flex flex-col items-center justify-center py-16 text-center">
						<EmptyVulns class="mb-3 text-[var(--text-muted)]" />
						<p class="text-sm font-medium text-[var(--text-secondary)]">No vulnerabilities found</p>
						<p class="mt-1 text-xs text-[var(--text-muted)]">No scan results yet — run a scan to populate this view.</p>
					</div>
				{:else}
					{#each vulns.filter(v => v.repo_slug !== v.repo_id && v.repo_slug) as v}
						<article class="panel-surface px-6 py-4 sm:px-10">
							<div class="flex flex-wrap items-start gap-4">
								<!-- Severity icon + CVE ID -->
								<div class="flex items-start gap-3 min-w-0 flex-1">
									<div class="mt-0.5 shrink-0">
										{#if v.severity?.toUpperCase() === 'CRITICAL' || v.severity?.toUpperCase() === 'HIGH'}
											<ShieldX class="h-4 w-4 {severityIcon(v.severity).color}" />
										{:else}
											<ShieldAlert class="h-4 w-4 {severityIcon(v.severity).color}" />
										{/if}
									</div>
									<div class="min-w-0 flex-1 space-y-1">
										<div class="flex flex-wrap items-center gap-2">
											<span class="font-mono text-sm font-semibold text-[var(--text-bright)]">{v.vuln_id}</span>
											<span class="rounded-full px-2 py-0.5 text-xs font-medium border {severityClass(v.severity)} {severityIcon(v.severity).color}">
												{v.severity}
											</span>
											{#if v.fixed_version}
												<span class="rounded bg-green-500/10 px-1.5 py-0.5 text-xs text-green-400">
													fix: {v.fixed_version}
												</span>
											{/if}
										</div>
										{#if v.title}
											<p class="text-sm text-[var(--text-secondary)]">{v.title}</p>
										{/if}
										<div class="flex flex-wrap items-center gap-3 text-xs text-[var(--text-muted)]">
											<span class="font-mono">{v.pkg_name}{v.installed_version ? `@${v.installed_version}` : ''}</span>
											<button
												type="button"
												class="text-[var(--accent)] hover:underline"
												onclick={() => openRepo(v.repo_id)}
											>
												{v.repo_slug}
											</button>
										</div>
									</div>
								</div>
							</div>
						</article>
					{/each}
				{/if}
			</div>
		{/if}
	{/if}
</div>
