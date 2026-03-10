<script lang="ts">
	import { goto } from '$app/navigation';
	import { browser } from '$app/environment';
	import { onMount } from 'svelte';
	import { ArrowLeft, ShieldX, ShieldAlert, Shield, Clock } from 'lucide-svelte';
	import DonutChart from '$lib/components/DonutChart.svelte';
	import LineChart from '$lib/components/LineChart.svelte';

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

	let summary: Summary | null = null;
	let repos: RepoRow[] = [];
	let trend: TrendPoint[] = [];
	let loading = true;
	let error = '';

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

	const openRepo = (repo: RepoRow) => {
		if (!repo.repo_id) return;
		goto(`/app/providers/repo?repo_id=${encodeURIComponent(repo.repo_id)}`);
	};

	const goBack = () => {
		if (browser) history.back();
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
		</article>

		<!-- Repository list -->
		<div class="space-y-2">
			<h2 class="px-1 text-sm font-medium text-[var(--text-secondary)]">By Repository</h2>
			{#if repos.length === 0}
				<article class="panel-surface flex items-center justify-center py-12 text-xs text-[var(--text-tertiary)]">
					No scan results yet
				</article>
			{:else}
				<div class="space-y-2">
					{#each repos as repo}
						<button
							type="button"
							class="panel-surface w-full cursor-pointer px-6 py-4 sm:px-10 text-left transition hover:border-[var(--accent)]/40 hover:bg-[var(--hover-bg-subtle)]"
							onclick={() => openRepo(repo)}
						>
							<div class="flex flex-wrap items-center justify-between gap-3">
								<div class="min-w-0 space-y-1">
									<p class="truncate font-medium text-[var(--accent)]">{repo.repo_slug || repo.repo_id}</p>
									<div class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
										<Clock class="h-3 w-3" />
										{fmtDate(repo.last_scanned_at)}
									</div>
								</div>
								<div class="flex items-center gap-4 text-sm">
									{#if repo.critical_count > 0}
										<span class="flex items-center gap-1 font-semibold text-red-500">
											<ShieldX class="h-4 w-4" />{fmt(repo.critical_count)}
										</span>
									{/if}
									{#if repo.high_count > 0}
										<span class="flex items-center gap-1 font-semibold text-orange-500">
											<ShieldAlert class="h-4 w-4" />{fmt(repo.high_count)}
										</span>
									{/if}
									{#if repo.medium_count > 0}
										<span class="flex items-center gap-1 font-semibold text-yellow-500">
											<Shield class="h-4 w-4" />{fmt(repo.medium_count)}
										</span>
									{/if}
									{#if repo.low_count > 0}
										<span class="flex items-center gap-1 text-[var(--text-secondary)]">
											<Shield class="h-4 w-4" />{fmt(repo.low_count)}
										</span>
									{/if}
									{#if repo.critical_count === 0 && repo.high_count === 0 && repo.medium_count === 0 && repo.low_count === 0}
										<span class="text-xs text-[var(--text-muted)]">No vulnerabilities</span>
									{/if}
								</div>
							</div>
						</button>
					{/each}
				</div>
			{/if}
		</div>
	{/if}
</div>
