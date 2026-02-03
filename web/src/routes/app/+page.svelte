<script lang="ts">
	import { browser } from '$app/environment';
	import { goto } from '$app/navigation';
	import DonutChart, { type DonutSegment } from '$lib/components/DonutChart.svelte';
	import Loading from '$lib/components/Loading.svelte';

	type SummaryCounts = {
		sbom_count: number;
		repo_count: number;
		repo_with_sbom_count: number;
		image_count: number;
		component_count: number;
		component_version_count: number;
		license_count: number;
		missing_license_count: number;
	};

	type ScannerCount = {
		name: string;
		count: number;
	};

	type RecentSBOM = {
		sbom_id: string;
		created_at: string;
		scanner_name: string;
		scanner_version: string;
		asset_type: string;
		repo_name?: string;
		commit_sha?: string;
		image_registry?: string;
		image_repository?: string;
		image_digest?: string;
		component_count: number;
	};

	type TopComponent = {
		kind: string;
		package_name: string;
		sbom_count: number;
		version_count: number;
	};

	type TopLicense = {
		license: string;
		count: number;
	};

	type SummaryResponse = {
		counts: SummaryCounts;
		scanners: ScannerCount[];
		recent_sboms: RecentSBOM[];
		top_components: TopComponent[];
		top_licenses: TopLicense[];
	};

	let summary: SummaryResponse | null = null;
	let loading = true;
	let error = '';

	const licensePalette = [
		'var(--accent)',
		'var(--success)',
		'var(--warning)',
		'var(--info)',
		'var(--accent-dark)',
		'var(--success-dark)',
		'var(--warning-dark)',
		'var(--info-dark)'
	];

	const loadSummary = async () => {
		try {
			const res = await fetch('/api/app/summary');
			if (!res.ok) {
				throw new Error('Failed to load summary');
			}
			summary = (await res.json()) as SummaryResponse;
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to load summary';
		} finally {
			loading = false;
		}
	};

	if (browser) {
		loadSummary();
	}

	const formatDate = (value: string) => {
		if (!value) return '';
		const date = new Date(value);
		return new Intl.DateTimeFormat('en-US', {
			dateStyle: 'medium',
			timeStyle: 'short'
		}).format(date);
	};

	const shortSHA = (sha?: string) => (sha ? sha.slice(0, 7) : '');

	const metricCards = () => {
		if (!summary) return [];
		const c = summary.counts;
		return [
			{
				label: 'Repositories',
				value: c.repo_count,
				description: `${c.repo_with_sbom_count} with SBOMs`,
				accent: 'var(--accent)'
			},
			{
				label: 'SBOMs',
				value: c.sbom_count,
				description: `${c.image_count} images tracked`,
				accent: 'var(--text-bright)'
			},
			{
				label: 'Components',
				value: c.component_count,
				description: `${c.component_version_count} versions indexed`,
				accent: 'var(--info)'
			},
			{
				label: 'Licenses',
				value: c.license_count,
				description: `${c.missing_license_count} missing`,
				accent: c.missing_license_count > 0 ? 'var(--warning)' : 'var(--success)'
			}
		];
	};

	const sbomLabel = (sbom: RecentSBOM) => sbom.repo_name || sbom.image_repository || sbom.sbom_id.slice(0, 8);

	const licenseSegments = (): DonutSegment[] => {
		if (!summary) return [];
		const segments = summary.top_licenses.map((license, index) => ({
			label: license.license,
			value: license.count,
			color: licensePalette[index % licensePalette.length]
		}));
		if (summary.counts.missing_license_count > 0) {
			segments.push({
				label: 'Missing',
				value: summary.counts.missing_license_count,
				color: 'var(--error)'
			});
		}
		return segments;
	};

	const scannerPalette = [
		'var(--info)',
		'var(--accent)',
		'var(--success)',
		'var(--warning)',
		'var(--info-dark)',
		'var(--accent-dark)',
		'var(--success-dark)',
		'var(--warning-dark)'
	];

	const scannerSegments = (): DonutSegment[] => {
		if (!summary) return [];
		return summary.scanners.map((scanner, index) => ({
			label: scanner.name,
			value: scanner.count,
			color: scannerPalette[index % scannerPalette.length]
		}));
	};

	const totalScans = () => {
		if (!summary) return 0;
		return summary.scanners.reduce((sum, s) => sum + s.count, 0);
	};
</script>

<svelte:head>
	<title>SBOM Dashboard • Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:space-y-8 sm:px-10 sm:py-12">
		<div class="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
			<div class="space-y-3">
				<span class="inline-flex w-fit items-center gap-2 rounded-full border border-[var(--accent-dark)]/50 bg-[var(--accent-dark)]/15 px-3 py-1 text-[10px] font-medium uppercase tracking-[0.32em] text-[var(--accent)] sm:text-xs">
					SBOM Control Center
				</span>
				<div class="space-y-2">
					<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl md:text-4xl">
						Software Supply Chain Posture
					</h1>
					<p class="max-w-2xl text-sm text-[var(--text-tertiary)] sm:text-base">
						Unified snapshot of repository coverage, SBOM ingestion, dependency composition, and license signals.
					</p>
				</div>
			</div>
			<div class="flex flex-col items-start gap-2 text-xs text-[var(--text-muted)] sm:text-sm">
				<span class="inline-flex items-center gap-2 rounded-full border border-[var(--success-dark)] px-3 py-1 text-[var(--success)]">
					<span class="h-2 w-2 rounded-full bg-[var(--success)]"></span>
					Ingestion active
				</span>
				<span class="rounded-full border border-[var(--border-color)] px-3 py-1">
					{summary ? `Latest refresh ${formatDate(summary.recent_sboms?.[0]?.created_at ?? '')}` : 'Loading metrics'}
				</span>
			</div>
		</div>

		{#if loading}
			<div class="flex min-h-[300px] items-center justify-center">
				<Loading message="Loading metrics" size="lg" variant="spinner" />
			</div>
		{:else if error}
			<p class="text-sm text-[var(--error)]">{error}</p>
		{:else if summary}
			<div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
				{#each metricCards() as metric}
					<article class="metric-card rounded-2xl p-4 sm:p-6">
						<h2 class="text-sm uppercase tracking-[0.24em] text-[var(--text-muted)]">{metric.label}</h2>
						<p class="mt-3 text-2xl font-semibold text-[var(--text-bright)]">{metric.value}</p>
						<p class="mt-2 text-xs text-[var(--text-tertiary)]" style={`color: ${metric.accent}`}>{metric.description}</p>
					</article>
				{/each}
			</div>
		{/if}
	</section>

	{#if summary}
		<div class="grid gap-6 lg:grid-cols-3 lg:grid-rows-2">
			<section class="panel-surface rounded-2xl p-6 lg:row-span-2">
				<div class="flex items-center justify-between">
					<h2 class="text-lg font-semibold text-[var(--text-bright)]">SBOM activity</h2>
					<span class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">latest</span>
				</div>
				<div class="mt-4 max-h-[400px] overflow-auto rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
					<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
						<thead class="sticky top-0 bg-[var(--card-bg)] text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
							<tr>
								<th class="px-5 py-3 text-left">Asset</th>
								<th class="px-5 py-3 text-left">Scanner</th>
								<th class="px-5 py-3 text-left">Components</th>
								<th class="px-5 py-3 text-left">Timestamp</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
							{#each summary.recent_sboms as sbom}
								<tr
									class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]"
									on:click={() => goto(`/app/agents?sbom_id=${sbom.sbom_id}`)}
								>
									<td class="px-5 py-3">
										<p class="font-semibold text-[var(--text-bright)]">{sbomLabel(sbom)}</p>
										<p class="text-xs text-[var(--text-tertiary)]">
											{sbom.commit_sha ? `commit ${shortSHA(sbom.commit_sha)}` : sbom.asset_type}
										</p>
									</td>
									<td class="px-5 py-3 text-xs">
										{sbom.scanner_name} {sbom.scanner_version}
									</td>
									<td class="px-5 py-3">{sbom.component_count}</td>
									<td class="px-5 py-3 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">{formatDate(sbom.created_at)}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>

			<section class="panel-surface rounded-2xl p-6 lg:row-span-2">
				<div class="flex items-center justify-between">
					<h2 class="text-lg font-semibold text-[var(--text-bright)]">Top components</h2>
					<span class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">by SBOM coverage</span>
				</div>
				<div class="mt-4 max-h-[400px] overflow-auto rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
					<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
						<thead class="sticky top-0 bg-[var(--card-bg)] text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
							<tr>
								<th class="px-5 py-3 text-left">Component</th>
								<th class="px-5 py-3 text-left">Ecosystem</th>
								<th class="px-5 py-3 text-left">SBOMs</th>
								<th class="px-5 py-3 text-left">Versions</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
							{#each summary.top_components as comp}
								<tr
									class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]"
									on:click={() => goto(`/app/components?ecosystem=${comp.kind}&q=${encodeURIComponent(comp.package_name)}`)}
								>
									<td class="px-5 py-3 font-semibold text-[var(--text-bright)]">{comp.package_name}</td>
									<td class="px-5 py-3">{comp.kind}</td>
									<td class="px-5 py-3">{comp.sbom_count}</td>
									<td class="px-5 py-3">{comp.version_count}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>

			<section class="panel-surface rounded-2xl p-6">
				<DonutChart
					title="License distribution"
					total={summary.counts.component_count}
					segments={licenseSegments()}
				/>
			</section>

			<section class="panel-surface rounded-2xl p-6">
			<DonutChart
				title="Scanner mix"
				total={totalScans()}
				segments={scannerSegments()}
			/>
			</section>
		</div>
	{/if}
</div>
