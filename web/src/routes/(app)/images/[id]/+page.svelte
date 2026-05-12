<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import {
		ArrowLeft,
		Container,
		ExternalLink,
		CheckCircle,
		Clock,
		Server,
		History,
		GitBranch,
		Shield,
		ShieldAlert,
		ShieldX,
		Package,
		Copy,
		AlertCircle
	} from 'lucide-svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';
	import ImageScanDetail from '$lib/components/ImageScanDetail.svelte';
	import RunTable, { type RunTableItem } from '$lib/components/RunTable.svelte';
	import VulnerabilitiesDialog, { type VulnerabilityDialogItem } from '$lib/components/VulnerabilitiesDialog.svelte';

	type LinkedRepo = {
		repo_id: string;
		provider: string;
		org: string;
		slug: string;
		base_url?: string;
		provider_id?: string;
		source?: string;
		revision?: string;
	};

	type ScanHistoryRow = {
		job_id: string;
		status: string;
		created_at: string;
		finished_at?: string;
		vuln_count: number;
	};

	type ClusterUsageRow = {
		cluster: string;
		namespace: string;
		pod_count: number;
		first_seen: string;
		last_seen: string;
	};

	type VulnSeverity = {
		critical: number;
		high: number;
		medium: number;
		low: number;
		unknown: number;
		total: number;
	};

	type ImageDetail = {
		id: string;
		registry: string;
		repository: string;
		digest: string;
		created_at: string;
		linked_repo?: LinkedRepo;
		scan_history?: ScanHistoryRow[];
		latest_scan_id?: string;
		cluster_usage?: ClusterUsageRow[];
		vuln_severity?: VulnSeverity;
	};

	let image = $state<ImageDetail | null>(null);
	let latestScan = $state<any>(null);
	let loading = $state(true);
	let error = $state('');
	let activeTab = $state('scans');
	let copied = $state(false);
	let vulnDialogOpen = $state(false);
	let vulnDialogLoading = $state(false);
	let vulnDialogData = $state<VulnerabilityDialogItem[]>([]);

	const shortDigest = (digest: string) => {
		const i = digest.indexOf(':');
		if (i < 0) return digest.slice(0, 12);
		return digest.slice(0, i + 13);
	};

	const copyDigest = async () => {
		if (!image) return;
		try {
			await navigator.clipboard.writeText(image.digest);
			copied = true;
			setTimeout(() => (copied = false), 1200);
		} catch {
			/* ignore */
		}
	};

	const loadImage = async () => {
		const id = $page.params.id;
		if (!id) return;
		loading = true;
		error = '';
		try {
			const res = await fetch(`/api/images/${id}`, { credentials: 'include' });
			if (!res.ok) {
				error = res.status === 404 ? 'Image not found' : 'Failed to load image';
				return;
			}
			image = await res.json();
			latestScan = null;
			vulnDialogData = [];
			if (image?.latest_scan_id) {
				const scanRes = await fetch(`/api/runs/${image.latest_scan_id}`, { credentials: 'include' });
				if (scanRes.ok) latestScan = await scanRes.json();
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load image';
		} finally {
			loading = false;
		}
	};

	onMount(() => {
		if (browser) loadImage();
	});

	// Prefer history.back() so the referring page's scroll + state
	// restores; fall back to /app when this page was loaded directly
	// (image-detail routes are reached from several places — search,
	// secrets, providers/repo — so there's no single canonical parent).
	const goBack = () => {
		if (!browser) return;
		if (window.history.length > 1) {
			history.back();
		} else {
			goto('/');
		}
	};

	const formatDate = (iso: string) => {
		if (!iso) return '—';
		return new Date(iso).toLocaleString();
	};
	const formatShortDate = (iso: string) => {
		if (!iso) return '—';
		return new Date(iso).toLocaleDateString();
	};
	const clusterCount = $derived(
		new Set((image?.cluster_usage ?? []).map((c) => c.cluster)).size
	);
	const namespaceCount = $derived((image?.cluster_usage ?? []).length);
	const podCount = $derived(
		(image?.cluster_usage ?? []).reduce((sum, c) => sum + c.pod_count, 0)
	);
	const scanCount = $derived(image?.scan_history?.length ?? 0);
	const lastScanAt = $derived(image?.scan_history?.[0]?.created_at);
	const severity = $derived(
		image?.vuln_severity ?? { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: 0 }
	);
	const scanRunTableItems = $derived<RunTableItem[]>(
		(image?.scan_history ?? []).map((scan) => ({
			id: scan.job_id,
			href: `/runs/${scan.job_id}`,
			status: scan.status,
			started_at: scan.created_at,
			finished_at: scan.finished_at,
			badges: scan.vuln_count > 0
				? [{ label: `${scan.vuln_count} vuln${scan.vuln_count === 1 ? '' : 's'}`, tone: 'warning' }]
				: scan.status === 'SUCCEEDED'
					? [{ label: 'clean', tone: 'success' }]
					: []
		}))
	);

	const openVulnDialog = async () => {
		vulnDialogOpen = true;
		if (vulnDialogData.length > 0) return;
		vulnDialogLoading = true;
		try {
			const rows = latestScan?.image_vulns ?? [];
			const byID = new Map<string, VulnerabilityDialogItem>();
			for (const row of rows) {
				if (!row?.vuln_id || byID.has(row.vuln_id)) continue;
				byID.set(row.vuln_id, {
					vuln_id: row.vuln_id,
					severity: row.severity || 'UNKNOWN',
					pkg_name: row.pkg_name || '',
					installed_version: row.installed_version || '',
					fixed_version: row.fixed_version || '',
					title: row.title || '',
					description: '',
					sources: row.scanner ? [row.scanner] : []
				});
			}
			vulnDialogData = Array.from(byID.values());
		} finally {
			vulnDialogLoading = false;
		}
	};
</script>

<svelte:head>
	<title>{image ? `${image.registry}/${image.repository}` : 'Image'} • Spam</title>
</svelte:head>

<div class="space-y-6">
	<!-- Back button + linked repo -->
	<div class="flex items-center justify-between">
		<button
			type="button"
			class="inline-flex items-center gap-2 text-sm text-[var(--text-secondary)] transition hover:text-[var(--accent)]"
			onclick={goBack}
		>
			<ArrowLeft class="h-4 w-4" />
			Back
		</button>
		{#if image?.linked_repo}
			<a
				class="flex mr-[2em] pr-2 items-center gap-1.5 text-[11px] font-medium transition-opacity hover:opacity-70"
				style="color: var(--accent);"
				href={`/providers/repo?repo_id=${image.linked_repo.repo_id}${image.linked_repo.provider_id ? `&provider_id=${image.linked_repo.provider_id}` : ''}`}
			>
				<GitBranch class="h-3 w-3" />
				View {image.linked_repo.org}/{image.linked_repo.slug}
				<ExternalLink class="h-3 w-3" />
			</a>
		{/if}
	</div>

	{#if loading}
		<div class="flex items-center justify-center py-20">
			<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
		</div>
	{:else if error}
		<div class="panel-surface flex flex-col items-center gap-3 px-6 py-12 text-center">
			<AlertCircle class="h-10 w-10 text-[var(--error)]" />
			<p class="text-sm text-[var(--text-secondary)]">{error}</p>
		</div>
	{:else if image}
		<!-- Header + Stats -->
		<article class="panel-surface space-y-4 px-6 py-6 sm:px-10">
			<div class="flex items-start justify-between gap-4">
				<div class="min-w-0 flex-1">
					<div class="flex items-center gap-3">
						<Container class="h-6 w-6 flex-shrink-0 text-[var(--warning)]" />
						<h1 class="truncate text-2xl font-semibold text-[var(--text-bright)]">
							{image.repository}
						</h1>
						<span class="inline-flex items-center gap-1 rounded-full bg-[var(--accent)]/10 px-2 py-0.5 text-xs text-[var(--accent)]">
							<Package class="h-3 w-3" /> Container image
						</span>
						{#if image.linked_repo}
							<span class="inline-flex items-center gap-1 rounded-full bg-[var(--success)]/10 px-2 py-0.5 text-xs text-[var(--success)]">
								<GitBranch class="h-3 w-3" /> Source linked
							</span>
						{/if}
					</div>
					<p class="mt-1 text-sm text-[var(--text-muted)]">{image.registry}/{image.repository}</p>
					<div class="mt-3 flex flex-wrap items-center gap-2 text-xs">
						<code class="rounded bg-[var(--hover-bg-subtle)] px-2 py-0.5 font-mono text-[var(--text-secondary)]">
							{shortDigest(image.digest)}
						</code>
						<button
							type="button"
							class="inline-flex items-center gap-1 rounded-full border border-[var(--border-color)] px-2 py-0.5 text-[var(--text-tertiary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
							onclick={copyDigest}
							title="Copy full digest"
						>
							<Copy class="h-3 w-3" />
							{copied ? 'Copied' : 'Copy'}
						</button>
					</div>
				</div>
				{#if image.latest_scan_id}
					<a
						class="btn btn-primary"
						href={`/runs/${image.latest_scan_id}`}
					>
						View latest scan
					</a>
				{/if}
			</div>

			<!-- Quick stats row -->
			<div class="flex flex-wrap gap-4 pt-4 text-sm text-[var(--text-secondary)]">
				<span class="flex items-center gap-1.5">
					<Clock class="h-4 w-4" /> First seen {formatDate(image.created_at)}
				</span>
				{#if lastScanAt}
					<span class="flex items-center gap-1.5">
						<History class="h-4 w-4" /> Last scan {formatShortDate(lastScanAt)}
					</span>
				{/if}
				{#if clusterCount > 0}
					<span class="flex items-center gap-1.5">
						<Server class="h-4 w-4" />
						{clusterCount} cluster{clusterCount === 1 ? '' : 's'}
					</span>
				{/if}
				{#if podCount > 0}
					<span class="flex items-center gap-1.5">
						<Package class="h-4 w-4" />
						{podCount} pod{podCount === 1 ? '' : 's'}
					</span>
				{/if}
			</div>

			<!-- Stats grid -->
			<div class="grid gap-3 pt-4 sm:grid-cols-2 lg:grid-cols-4">
				<!-- Image -->
				<div class="space-y-3 metric-card rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Image</h3>
					<div class="grid grid-cols-2 gap-3">
						<div>
							<p class="text-2xl font-bold text-[var(--text-bright)]">{scanCount}</p>
							<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
								<History class="h-3 w-3" /> Scans
							</p>
						</div>
						<div>
							<p class="text-2xl font-bold text-[var(--text-bright)]">
								{image.scan_history?.filter((s) => s.status === 'SUCCEEDED').length ?? 0}
							</p>
							<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
								<CheckCircle class="h-3 w-3" /> Succeeded
							</p>
						</div>
					</div>
				</div>

				<!-- Vulnerabilities -->
				<button
					type="button"
					class="space-y-3 metric-card w-full rounded-2xl p-4 text-left transition-colors hover:border-[var(--accent)]/50"
					onclick={openVulnDialog}
				>
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Vulnerabilities</h3>
					<div class="grid grid-cols-2 gap-3">
						<div>
							<p class="text-2xl font-bold text-red-500">{severity.critical}</p>
							<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
								<ShieldX class="h-3 w-3 text-red-500" /> Critical
							</p>
						</div>
						<div>
							<p class="text-2xl font-bold text-orange-500">{severity.high}</p>
							<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
								<ShieldAlert class="h-3 w-3 text-orange-500" /> High
							</p>
						</div>
						<div>
							<p class="text-2xl font-bold text-yellow-500">{severity.medium}</p>
							<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
								<Shield class="h-3 w-3 text-yellow-500" /> Medium
							</p>
						</div>
						<div>
							<p class="text-2xl font-bold text-[var(--text-secondary)]">{severity.low}</p>
							<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
								<Shield class="h-3 w-3" /> Low
							</p>
						</div>
					</div>
				</button>

				<!-- Clusters -->
				<div class="space-y-3 metric-card rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Workloads</h3>
					<div class="grid grid-cols-2 gap-3">
						<div>
							<p class="text-2xl font-bold text-[var(--text-bright)]">{clusterCount}</p>
							<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
								<Server class="h-3 w-3" /> Clusters
							</p>
						</div>
						<div>
							<p class="text-2xl font-bold text-[var(--text-bright)]">{namespaceCount}</p>
							<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
								<Package class="h-3 w-3" /> Namespaces
							</p>
						</div>
						<div>
							<p class="text-2xl font-bold text-[var(--text-bright)]">{podCount}</p>
							<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
								<Container class="h-3 w-3" /> Pods
							</p>
						</div>
					</div>
				</div>

				<!-- Source / Registry -->
				<div class="space-y-3 metric-card rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Registry</h3>
					<div class="space-y-2">
						<div>
							<p class="truncate text-sm font-semibold text-[var(--text-bright)]" title={image.registry}>
								{image.registry}
							</p>
							<p class="text-xs text-[var(--text-muted)]">Host</p>
						</div>
						<div>
							<p class="truncate text-sm font-semibold text-[var(--text-bright)]" title={image.repository}>
								{image.repository}
							</p>
							<p class="text-xs text-[var(--text-muted)]">Repository</p>
						</div>
						{#if image.linked_repo}
							<a
								class="block truncate text-xs text-[var(--accent)] hover:underline"
								href={`/providers/repo?repo_id=${image.linked_repo.repo_id}${image.linked_repo.provider_id ? `&provider_id=${image.linked_repo.provider_id}` : ''}`}
							>
								{image.linked_repo.org}/{image.linked_repo.slug}
							</a>
						{/if}
					</div>
				</div>
			</div>

			<!-- Activity Tabs -->
			<div class="pt-4">
				<TabSelector
					options={[
						{ value: 'scans', label: 'Scans' },
						{ value: 'clusters', label: 'Clusters' },
						{ value: 'findings', label: 'Latest findings' }
					]}
					bind:value={activeTab}
				/>

				<div class="mt-[2em]">
					{#if activeTab === 'scans'}
						{#if (image.scan_history?.length ?? 0) === 0}
							<div class="flex flex-col items-center justify-center py-8 text-center">
								<History class="mb-3 h-8 w-8 text-[var(--text-muted)]" />
								<p class="text-sm font-medium text-[var(--text-secondary)]">No scans yet</p>
								<p class="mt-1 text-xs text-[var(--text-muted)]">
									Scans will appear here once the reconciler picks up this digest.
								</p>
							</div>
						{:else}
							<RunTable runs={scanRunTableItems} />
						{/if}
					{:else if activeTab === 'clusters'}
						{#if (image.cluster_usage?.length ?? 0) === 0}
							<div class="flex flex-col items-center justify-center py-8 text-center">
								<Server class="mb-3 h-8 w-8 text-[var(--text-muted)]" />
								<p class="text-sm font-medium text-[var(--text-secondary)]">
									Not observed in any cluster yet
								</p>
								<p class="mt-1 text-xs text-[var(--text-muted)]">
									Running pods on tracked clusters will appear here once the agent reports them.
								</p>
							</div>
						{:else}
							<div class="overflow-hidden rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
								<table class="min-w-full divide-y divide-[var(--border-color)]/40 text-sm">
									<thead class="text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
										<tr>
											<th class="px-4 py-2.5 text-left">Cluster</th>
											<th class="px-4 py-2.5 text-left">Namespace</th>
											<th class="px-4 py-2.5 text-right">Pods</th>
											<th class="px-4 py-2.5 text-left">First seen</th>
											<th class="px-4 py-2.5 text-left">Last seen</th>
										</tr>
									</thead>
									<tbody class="divide-y divide-[var(--border-color)]/20 text-[var(--text-secondary)]">
										{#each image.cluster_usage ?? [] as u}
											<tr class="transition hover:bg-[var(--hover-bg-subtle)]">
												<td class="px-4 py-2 font-mono text-[var(--text-bright)]">{u.cluster || '—'}</td>
												<td class="px-4 py-2 font-mono">{u.namespace || '—'}</td>
												<td class="px-4 py-2 text-right font-semibold">{u.pod_count}</td>
												<td class="px-4 py-2 text-xs text-[var(--text-tertiary)]">{formatDate(u.first_seen)}</td>
												<td class="px-4 py-2 text-xs text-[var(--text-tertiary)]">{formatDate(u.last_seen)}</td>
											</tr>
										{/each}
									</tbody>
								</table>
							</div>
						{/if}
					{:else if activeTab === 'findings'}
						{#if latestScan}
							<div class="space-y-3">
								<p class="text-xs text-[var(--text-muted)]">
									Latest scan · <a
										class="text-[var(--accent)] hover:underline"
										href={`/runs/${latestScan.id}`}>open run</a
									>
								</p>
								<ImageScanDetail run={latestScan} />
							</div>
						{:else}
							<div class="flex flex-col items-center justify-center py-8 text-center">
								<Shield class="mb-3 h-8 w-8 text-[var(--text-muted)]" />
								<p class="text-sm font-medium text-[var(--text-secondary)]">No successful scan yet</p>
								<p class="mt-1 text-xs text-[var(--text-muted)]">
									Findings will appear here once a scan completes.
								</p>
							</div>
						{/if}
					{/if}
				</div>
			</div>
		</article>
	{/if}
</div>

<VulnerabilitiesDialog bind:open={vulnDialogOpen} loading={vulnDialogLoading} data={vulnDialogData} />
