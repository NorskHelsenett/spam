<script lang="ts">
	import { onMount } from 'svelte';
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

	$: metricCards = [
		{ label: 'Total', value: summary?.total_vulns ?? 0, color: 'var(--text-bright)' },
		{ label: 'Critical', value: summary?.total_critical ?? 0, color: 'var(--red)' },
		{ label: 'High', value: summary?.total_high ?? 0, color: 'var(--orange)' },
		{ label: 'Medium + Low', value: (summary?.total_medium ?? 0) + (summary?.total_low ?? 0), color: 'var(--yellow)' }
	];

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

<div class="space-y-8">
	<div>
		<h1 class="text-xl font-semibold text-[var(--text-bright)]">Vulnerabilities</h1>
		<p class="mt-1 text-xs text-[var(--text-tertiary)]">
			Trivy scan results across all SBOMs
			{#if summary?.last_scanned_at}
				· last scan {fmtDate(summary.last_scanned_at)}
			{/if}
		</p>
	</div>

	{#if loading}
		<div class="flex items-center justify-center py-20 text-[var(--text-tertiary)] text-sm">
			Loading…
		</div>
	{:else if error}
		<div class="rounded-xl border border-[var(--red)]/30 bg-[var(--red)]/10 px-4 py-3 text-sm text-[var(--red)]">
			{error}
		</div>
	{:else}
		<!-- Metric cards -->
		<div class="grid grid-cols-2 gap-4 sm:grid-cols-4">
			{#each metricCards as card}
				<div class="metric-card rounded-2xl border border-[var(--border-color)] bg-[var(--card-bg)] px-5 py-4">
					<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">{card.label}</p>
					<p class="mt-2 text-2xl font-semibold" style="color:{card.color}">{fmt(card.value)}</p>
				</div>
			{/each}
		</div>

		<!-- Charts row -->
		<div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
			<div class="rounded-2xl border border-[var(--border-color)] bg-[var(--card-bg)] p-5">
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
			<div class="rounded-2xl border border-[var(--border-color)] bg-[var(--card-bg)] p-5">
				<LineChart title="30-day trend" data={trend} />
			</div>
		</div>

		<!-- Repos table -->
		<div class="rounded-2xl border border-[var(--border-color)] bg-[var(--card-bg)] overflow-hidden">
			<div class="px-5 py-4 border-b border-[var(--border-color)]">
				<h2 class="text-sm font-medium text-[var(--text-bright)]">By Repository</h2>
			</div>
			{#if repos.length === 0}
				<div class="flex items-center justify-center py-12 text-xs text-[var(--text-tertiary)]">
					No scan results yet
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
							{#each repos as repo, i}
								<tr
									class="border-b border-[var(--border-color)]/50 transition-colors hover:bg-[var(--hover-bg-subtle)] {i % 2 === 0 ? '' : 'bg-[var(--card-bg)]/30'}"
								>
									<td class="px-5 py-3 font-medium text-[var(--text-bright)] max-w-xs truncate">
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
	{/if}
</div>
