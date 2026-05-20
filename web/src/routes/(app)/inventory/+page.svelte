<script lang="ts">
	import { browser } from '$app/environment';
	import { goto } from '$app/navigation';
	import { get } from 'svelte/store';
	import { session, hasOnlyClusters } from '$lib/stores/session';
	import DonutChart from '$lib/components/DonutChart.svelte';
	// DonutSegment is exported from DonutChart.svelte but svelte-check
	// fails to resolve type-only imports across the legacy `export let`
	// boundary; inline the same shape here to keep the file clean.
	type DonutSegment = { label: string; value: number; color: string };
	import Loading from '$lib/components/Loading.svelte';
	import { Container, GitBranch } from 'lucide-svelte';

	type SummaryCounts = {
		sbom_count: number;
		repo_count: number;
		repo_with_sbom_count: number;
		image_count: number;
		component_count: number;
		component_version_count: number;
		osv_purl_count: number;
		osv_sbom_purl_count: number;
		osv_manifest_purl_count: number;
		license_count: number;
		missing_license_count: number;
		secrets_count: number;
	};

	type ScannerCount = {
		name: string;
		version: string;
		count: number;
	};

	type RecentSBOM = {
		sbom_id: string;
		created_at: string;
		scanner_name: string;
		scanner_version: string;
		asset_type: string;
		repo_id?: string;
		repo_name?: string;
		commit_sha?: string;
		image_registry?: string;
		image_repository?: string;
		image_digest?: string;
		component_count: number;
		vuln_count: number;
		secret_count: number;
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

	// Cluster-only users have no repo grants; /api/app/summary 404s
	// for them via requireUnrestrictedRepos. Bounce them off this
	// page before firing the request rather than show a broken state.
	async function waitForSession(timeoutMs = 2000): Promise<void> {
		const start = Date.now();
		while (Date.now() - start < timeoutMs) {
			if (get(session).loaded) return;
			await new Promise((r) => setTimeout(r, 25));
		}
	}

	const loadSummary = async () => {
		await waitForSession();
		if (get(hasOnlyClusters)) {
			void goto('/');
			return;
		}
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
				label: 'SBOM components',
				value: c.component_count,
				description: `${c.component_version_count} SBOM versions indexed`,
				accent: 'var(--info)'
			},
			{
				label: 'Components',
				value: c.osv_purl_count,
				description: `${c.osv_sbom_purl_count} SBOM + ${c.osv_manifest_purl_count} manifest`,
				accent: 'var(--info)'
			},
			{
				label: 'Licenses',
				value: c.license_count,
				description: `${c.missing_license_count} missing`,
				accent: c.missing_license_count > 0 ? 'var(--warning)' : 'var(--success)'
			},
			{
				label: 'Secrets',
				value: c.secrets_count,
				description: 'Latest run per repo',
				accent: c.secrets_count > 0 ? 'var(--error)' : 'var(--success)'
			}
		];
	};

	// Build the best label we can from whatever identity fields exist.
	// Some image_digests rows have registry set but repository empty
	// (scanner resolved the registry part but didn't parse a repo out of
	// the ref) — don't let those collapse to the sbom_id prefix when we
	// still have a registry + digest to show.
	const imageName = (sbom: RecentSBOM) => {
		const registry = sbom.image_registry ?? '';
		const repository = sbom.image_repository ?? '';
		const digest = sbom.image_digest ?? '';
		const shortDigest = digest.startsWith('sha256:') ? digest.slice(7, 19) : digest.slice(0, 12);

		if (registry && repository) return `${registry}/${repository}`;
		if (registry && shortDigest) return `${registry}@${shortDigest}`;
		if (repository) return repository;
		if (shortDigest) return `sha256:${shortDigest}`;
		return '';
	};

	const sbomLabel = (sbom: RecentSBOM) =>
		sbom.repo_name || imageName(sbom) || sbom.sbom_id.slice(0, 8);

	const sbomClickTarget = (sbom: RecentSBOM): string => {
		if (sbom.asset_type === 'REPO_COMMIT' && sbom.repo_id) {
			return `/providers/repo?repo_id=${encodeURIComponent(sbom.repo_id)}`;
		}
		if (sbom.asset_type === 'IMAGE_DIGEST' && sbom.image_digest) return `/images/${encodeURIComponent(sbom.image_digest)}`;
		return '';
	};

	const licenseSegments = (): DonutSegment[] => {
		if (!summary) return [];
		const segments = (summary.top_licenses ?? []).map((license, index) => ({
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
		return (summary.scanners ?? []).map((scanner, index) => ({
			label: scanner.version ? `${scanner.name} ${scanner.version}` : scanner.name,
			value: scanner.count,
			color: scannerPalette[index % scannerPalette.length]
		}));
	};

	const totalScans = () => {
		if (!summary) return 0;
		return (summary.scanners ?? []).reduce((sum, s) => sum + s.count, 0);
	};
</script>

<svelte:head>
	<title>Inventory • Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:space-y-8 sm:px-10 sm:py-12">
		<div class="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
			<div class="space-y-3">
				<span class="inline-flex w-fit items-center gap-2 rounded-full border border-[var(--accent-dark)]/50 bg-[var(--accent-dark)]/15 px-3 py-1 text-[10px] font-medium uppercase tracking-[0.32em] text-[var(--accent)] sm:text-xs">
					SPAM Control Center
				</span>
				<div class="space-y-2">
					<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl md:text-4xl">
						Software Package Asset Management
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
			<div class="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
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
		<div class="grid gap-6 lg:grid-cols-3">
			<section class="panel-surface flex flex-col rounded-2xl p-6 lg:col-span-2">
				<div class="flex items-center justify-between">
					<h2 class="text-lg font-semibold text-[var(--text-bright)]">Latest activity</h2>
					<span class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">latest</span>
				</div>
				<div class="mt-4 min-h-0 flex-1 overflow-auto rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
					<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
						<thead class="sticky top-0 bg-[var(--card-bg)] text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
							<tr>
								<th class="px-5 py-3 text-left">Asset</th>
								<th class="px-5 py-3 text-left">Components</th>
								<th class="px-5 py-3 text-left">Vulns</th>
								<th class="px-5 py-3 text-left">Secrets</th>
								<th class="px-5 py-3 text-left">Timestamp</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
							{#each summary.recent_sboms ?? [] as sbom}
								{@const target = sbomClickTarget(sbom)}
								<tr
									class={`transition ${target ? 'cursor-pointer hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]' : ''}`}
									on:click={() => target && goto(target)}
								>
									<td class="px-5 py-3">
										<div class="flex items-center gap-3">
											<span class="flex-shrink-0 text-[var(--warning)]" aria-hidden="true">
												{#if sbom.asset_type === 'IMAGE_DIGEST'}
													<Container size={16} stroke-width={1.8} />
												{:else}
													<GitBranch size={16} stroke-width={1.8} />
												{/if}
											</span>
											<div class="min-w-0">
												<p class="truncate font-semibold text-[var(--text-bright)]">{sbomLabel(sbom)}</p>
												<p class="text-xs text-[var(--text-tertiary)]">
													{sbom.commit_sha ? `commit ${shortSHA(sbom.commit_sha)}` : sbom.asset_type}
												</p>
											</div>
										</div>
									</td>
									<td class="px-5 py-3">{sbom.component_count}</td>
									<td
										class="px-5 py-3 font-semibold"
										style={`color: ${sbom.vuln_count > 0 ? 'var(--error)' : 'var(--text-tertiary)'}`}
									>
										{sbom.vuln_count}
									</td>
									<td
										class="px-5 py-3 font-semibold"
										style={`color: ${sbom.secret_count > 0 ? 'var(--warning)' : 'var(--text-tertiary)'}`}
									>
										{sbom.secret_count}
									</td>
									<td class="px-5 py-3 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">{formatDate(sbom.created_at)}</td>
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

			<section class="panel-surface flex flex-col rounded-2xl p-6 lg:col-span-2">
				<div class="flex items-center justify-between">
					<h2 class="text-lg font-semibold text-[var(--text-bright)]">Top components</h2>
					<span class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">by SBOM coverage</span>
				</div>
				<div class="mt-4 max-h-[26em] flex-1 overflow-auto rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
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
							{#each summary.top_components ?? [] as comp}
								<tr
									class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]"
									on:click={() => goto(`/components?ecosystem=${comp.kind}&q=${encodeURIComponent(comp.package_name)}`)}
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
				title="Scanner mix"
				total={totalScans()}
				segments={scannerSegments()}
			/>
			</section>
		</div>
	{/if}
</div>
