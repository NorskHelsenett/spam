<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import {
		ArrowLeft,
		Container,
		ExternalLink,
		Clock,
		Server,
		GitBranch,
		Shield,
		ShieldCheck,
		ShieldAlert,
		ShieldX,
		Package,
		Copy,
		AlertCircle,
		KeyRound,
		Tag,
		FileBox,
		ChevronDown,
		ChevronRight
	} from 'lucide-svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';

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

	type OCIMetadata = {
		created?: string;
		architecture?: string;
		os?: string;
		author?: string;
	};

	type SignatureInfo = {
		signed: boolean;
		verified: boolean;
		error?: string;
	};

	type SecretRow = {
		rule_id: string;
		description?: string;
		file?: string;
		start_line?: number;
		match?: string;
	};

	type ImageDetail = {
		id: string;
		registry: string;
		repository: string;
		digest: string;
		created_at: string;
		linked_repo?: LinkedRepo;
		latest_scan_at?: string;
		cluster_usage?: ClusterUsageRow[];
		vuln_severity?: VulnSeverity;
		secret_count: number;
		image_secrets?: SecretRow[];
		image_labels?: Record<string, string>;
		image_oci_metadata?: OCIMetadata;
		image_signature?: SignatureInfo;
		sbom_id?: string;
		sbom_component_count?: number;
	};

	type VulnGroup = {
		vuln_id: string;
		severity: string;
		pkg_name: string;
		installed_version: string;
		fixed_version: string;
		title: string;
		description: string;
		sources: string[];
		aliases?: string[];
		kev_known?: boolean;
		epss_score?: number;
	};

	type VulnListResponse = {
		total: number;
		limit: number;
		offset: number;
		items: VulnGroup[];
	};

	type VulnDetail = {
		vuln_id: string;
		title: string;
		description: string;
		severity: string;
		sources: string[];
		enrichment_loading?: boolean;
		kev_known?: boolean;
		kev_known_ransomware?: boolean;
		kev_date_added?: string;
		epss_score?: number;
		epss_percentile?: number;
	};

	type VulnDetailState =
		| { status: 'loading' }
		| { status: 'ready'; data: VulnDetail }
		| { status: 'error'; message: string };

	let image = $state<ImageDetail | null>(null);
	let loading = $state(true);
	let error = $state('');
	let activeTab = $state('vulnerabilities');
	let copied = $state(false);

	let vulns = $state<VulnGroup[]>([]);
	let vulnTotal = $state(0);
	let vulnLoading = $state(false);
	let vulnError = $state('');
	let vulnSeverityFilter = $state<string>('ALL');
	let expandedVuln = $state<string>('');
	let vulnDetails = $state<Record<string, VulnDetailState>>({});

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
			const res = await fetch(`/api/images/${encodeURIComponent(id)}`, { credentials: 'include' });
			if (!res.ok) {
				error = res.status === 404 ? 'Image not found' : 'Failed to load image';
				return;
			}
			image = await res.json();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load image';
		} finally {
			loading = false;
		}
	};

	const loadVulns = async () => {
		const id = $page.params.id;
		if (!id) return;
		vulnLoading = true;
		vulnError = '';
		try {
			const params = new URLSearchParams({ limit: '100', offset: '0' });
			if (vulnSeverityFilter !== 'ALL') params.set('severity', vulnSeverityFilter);
			const res = await fetch(
				`/api/images/${encodeURIComponent(id)}/vulnerabilities?${params.toString()}`,
				{ credentials: 'include' }
			);
			if (!res.ok) {
				vulnError = res.status === 404 ? 'No vulnerability data' : 'Failed to load vulnerabilities';
				vulns = [];
				vulnTotal = 0;
				return;
			}
			const data: VulnListResponse = await res.json();
			vulns = data.items ?? [];
			vulnTotal = data.total ?? 0;
		} catch (e) {
			vulnError = e instanceof Error ? e.message : 'Failed to load vulnerabilities';
			vulns = [];
			vulnTotal = 0;
		} finally {
			vulnLoading = false;
		}
	};

	onMount(() => {
		if (browser) {
			loadImage();
			loadVulns();
		}
	});

	$effect(() => {
		// Re-fetch when severity filter changes.
		vulnSeverityFilter;
		if (browser && image) loadVulns();
	});

	// Prefer history.back() so the referring page's scroll + state
	// restores; fall back to /app when this page was loaded directly.
	const goBack = () => {
		if (!browser) return;
		if (window.history.length > 1) history.back();
		else goto('/');
	};

	const formatDate = (iso: string | undefined) => {
		if (!iso) return '—';
		return new Date(iso).toLocaleString();
	};
	const formatShortDate = (iso: string | undefined) => {
		if (!iso) return '—';
		return new Date(iso).toLocaleDateString();
	};
	const relativeTime = (iso: string | undefined) => {
		if (!iso) return '—';
		const diff = Date.now() - new Date(iso).getTime();
		const m = Math.floor(diff / 60000);
		if (m < 1) return 'just now';
		if (m < 60) return `${m}m ago`;
		const h = Math.floor(m / 60);
		if (h < 24) return `${h}h ago`;
		const d = Math.floor(h / 24);
		if (d < 30) return `${d}d ago`;
		const mo = Math.floor(d / 30);
		return `${mo}mo ago`;
	};

	const clusterCount = $derived(
		new Set((image?.cluster_usage ?? []).map((c) => c.cluster)).size
	);
	const namespaceCount = $derived((image?.cluster_usage ?? []).length);
	const podCount = $derived(
		(image?.cluster_usage ?? []).reduce((sum, c) => sum + c.pod_count, 0)
	);
	const severity = $derived(
		image?.vuln_severity ?? { critical: 0, high: 0, medium: 0, low: 0, unknown: 0, total: 0 }
	);
	const componentCount = $derived(image?.sbom_component_count ?? 0);
	const secretCount = $derived(image?.secret_count ?? 0);
	const ociMeta = $derived(image?.image_oci_metadata);
	const sig = $derived(image?.image_signature);
	const labels = $derived(image?.image_labels ?? {});
	const labelEntries = $derived(
		Object.entries(labels).sort(([a], [b]) => a.localeCompare(b))
	);

	const severityClass = (s: string) => {
		switch (s?.toUpperCase()) {
			case 'CRITICAL': return 'text-red-400 border-red-500/40 bg-red-500/10';
			case 'HIGH':     return 'text-orange-400 border-orange-500/40 bg-orange-500/10';
			case 'MEDIUM':   return 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10';
			case 'LOW':      return 'text-blue-400 border-blue-500/40 bg-blue-500/10';
			default:         return 'text-[var(--text-muted)] border-[var(--border-color)] bg-transparent';
		}
	};

	const vulnUrl = (id: string) => `/vuln/${encodeURIComponent(id)}`;

	// Canonical external advisory link for the given vuln id. CVE-* → NVD
	// gets users the CVSS vector + CWE; GHSA / BIT / GO / PYSEC / OSV-* go
	// to the authority that publishes them. Anything we don't recognise
	// falls back to OSV.dev which aggregates most ecosystems.
	const advisoryLink = (id: string): { href: string; label: string } => {
		const u = id.toUpperCase();
		if (u.startsWith('CVE-')) return { href: `https://nvd.nist.gov/vuln/detail/${id}`, label: 'NVD' };
		if (u.startsWith('GHSA-')) return { href: `https://github.com/advisories/${id}`, label: 'GitHub Advisory' };
		if (u.startsWith('GO-')) return { href: `https://pkg.go.dev/vuln/${id}`, label: 'Go vuln DB' };
		if (u.startsWith('PYSEC-')) return { href: `https://osv.dev/vulnerability/${id}`, label: 'OSV.dev' };
		if (u.startsWith('RUSTSEC-')) return { href: `https://rustsec.org/advisories/${id}`, label: 'RustSec' };
		if (u.startsWith('BIT-')) return { href: `https://github.com/bitnami/vulndb`, label: 'Bitnami VulnDB' };
		return { href: `https://osv.dev/vulnerability/${id}`, label: 'OSV.dev' };
	};

	const fetchVulnDetail = async (id: string) => {
		// Hit the same endpoint /vulnerabilities uses. Backend enqueues a
		// VULN_META_FETCH on miss; we re-poll once on enrichment_loading
		// to pick up the freshly fetched description without forcing the
		// user to click again.
		try {
			const res = await fetch(`/api/vulnerabilities/${encodeURIComponent(id)}`, {
				credentials: 'include'
			});
			if (!res.ok) {
				vulnDetails = {
					...vulnDetails,
					[id]: { status: 'error', message: `Failed (${res.status})` }
				};
				return;
			}
			const data: VulnDetail = await res.json();
			vulnDetails = { ...vulnDetails, [id]: { status: 'ready', data } };
			if (data.enrichment_loading) {
				// Best-effort: give the worker ~3s to populate vuln_metadata,
				// then refetch once. Avoid a tight poll loop — the user can
				// always click again.
				setTimeout(async () => {
					try {
						const r2 = await fetch(`/api/vulnerabilities/${encodeURIComponent(id)}`, {
							credentials: 'include'
						});
						if (r2.ok) {
							const d2: VulnDetail = await r2.json();
							if (!d2.enrichment_loading || d2.description) {
								vulnDetails = { ...vulnDetails, [id]: { status: 'ready', data: d2 } };
							}
						}
					} catch {
						/* ignore re-poll errors */
					}
				}, 3000);
			}
		} catch (e) {
			vulnDetails = {
				...vulnDetails,
				[id]: { status: 'error', message: e instanceof Error ? e.message : 'Failed' }
			};
		}
	};

	const toggleVuln = (id: string) => {
		const opening = expandedVuln !== id;
		expandedVuln = opening ? id : '';
		if (opening && !vulnDetails[id]) {
			vulnDetails = { ...vulnDetails, [id]: { status: 'loading' } };
			fetchVulnDetail(id);
		}
	};

	// Warm /api/vulnerabilities/{id} in the background for every visible
	// row right after the list loads. The backend enqueues a
	// VULN_META_FETCH on miss, so this also kicks off enrichment for
	// CVEs we haven't seen yet — by the time the user expands a row the
	// description / CVSS / EPSS / KEV are already cached client-side.
	// Concurrency=4 keeps the request fan-out reasonable on big images.
	const prefetchAll = async (ids: string[]) => {
		const queue = ids.filter((id) => !vulnDetails[id]);
		if (queue.length === 0) return;
		for (const id of queue) {
			if (!vulnDetails[id]) vulnDetails = { ...vulnDetails, [id]: { status: 'loading' } };
		}
		const concurrency = 4;
		const next = () => queue.shift();
		const worker = async () => {
			let id: string | undefined;
			while ((id = next())) {
				await fetchVulnDetail(id);
			}
		};
		await Promise.all(Array.from({ length: concurrency }, worker));
	};

	let prefetchedFor = $state<string>('');
	$effect(() => {
		// Fire whenever the vulns list changes (new severity filter, fresh
		// load). Skip retriggering for the same set of ids we already
		// prefetched for.
		if (!browser || vulns.length === 0) return;
		const key = vulns.map((v) => v.vuln_id).join(',');
		if (key === prefetchedFor) return;
		prefetchedFor = key;
		prefetchAll(vulns.map((v) => v.vuln_id));
	});
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
					<div class="flex flex-wrap items-center gap-3">
						<Container class="h-6 w-6 flex-shrink-0 text-[var(--warning)]" />
						<h1 class="truncate text-2xl font-semibold text-[var(--text-bright)]">
							{image.repository}
						</h1>
						<span class="inline-flex items-center gap-1 rounded-full bg-[var(--accent)]/10 px-2 py-0.5 text-xs text-[var(--accent)]">
							<Package class="h-3 w-3" /> Container image
						</span>
						{#if sig?.verified}
							<span class="inline-flex items-center gap-1 rounded-full bg-[var(--success)]/10 px-2 py-0.5 text-xs text-[var(--success)]" title={sig.error || 'cosign verification succeeded'}>
								<ShieldCheck class="h-3 w-3" /> Signed & verified
							</span>
						{:else if sig?.signed}
							<span class="inline-flex items-center gap-1 rounded-full bg-yellow-500/10 px-2 py-0.5 text-xs text-yellow-400" title={sig.error || 'signature present but not verified'}>
								<Shield class="h-3 w-3" /> Signed (unverified)
							</span>
						{/if}
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
			</div>

			<!-- Quick stats row -->
			<div class="flex flex-wrap gap-4 pt-4 text-sm text-[var(--text-secondary)]">
				<span class="flex items-center gap-1.5">
					<Clock class="h-4 w-4" /> First seen {formatShortDate(image.created_at)}
				</span>
				{#if image.latest_scan_at}
					<span class="flex items-center gap-1.5" title={formatDate(image.latest_scan_at)}>
						<Shield class="h-4 w-4" /> Scanned {relativeTime(image.latest_scan_at)}
					</span>
				{/if}
				{#if ociMeta?.architecture || ociMeta?.os}
					<span class="flex items-center gap-1.5">
						<FileBox class="h-4 w-4" /> {[ociMeta?.os, ociMeta?.architecture].filter(Boolean).join('/')}
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
				<!-- Vulnerabilities -->
				<div class="space-y-3 metric-card rounded-2xl p-4">
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
				</div>

				<!-- Workloads -->
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

				<!-- Components / SBOM -->
				<div class="space-y-3 metric-card rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Components</h3>
					<div>
						<p class="text-2xl font-bold text-[var(--text-bright)]">{componentCount.toLocaleString()}</p>
						<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
							<FileBox class="h-3 w-3" /> Packages in SBOM
						</p>
					</div>
					{#if image.sbom_id}
						<a
							class="block truncate text-xs text-[var(--accent)] hover:underline"
							href={`/sboms/${encodeURIComponent(image.sbom_id)}`}
						>
							View SBOM →
						</a>
					{/if}
					<div>
						<p class="text-lg font-bold {secretCount > 0 ? 'text-orange-400' : 'text-[var(--text-secondary)]'}">
							{secretCount.toLocaleString()}
						</p>
						<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
							<KeyRound class="h-3 w-3" /> Secrets found
						</p>
					</div>
				</div>

				<!-- Image meta -->
				<div class="space-y-2 metric-card rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Image</h3>
					<div>
						<p class="truncate text-sm font-semibold text-[var(--text-bright)]" title={image.registry}>
							{image.registry}
						</p>
						<p class="text-xs text-[var(--text-muted)]">Registry</p>
					</div>
					{#if ociMeta?.architecture || ociMeta?.os}
						<div>
							<p class="text-sm font-semibold text-[var(--text-bright)]">
								{[ociMeta?.os, ociMeta?.architecture].filter(Boolean).join('/')}
							</p>
							<p class="text-xs text-[var(--text-muted)]">Platform</p>
						</div>
					{/if}
					{#if ociMeta?.created}
						<div>
							<p class="text-sm font-semibold text-[var(--text-bright)]">
								{formatShortDate(ociMeta.created)}
							</p>
							<p class="text-xs text-[var(--text-muted)]">Built</p>
						</div>
					{/if}
				</div>
			</div>

			<!-- Activity Tabs -->
			<div class="pt-4">
				<TabSelector
					options={[
						{ value: 'vulnerabilities', label: `Vulnerabilities${vulnTotal ? ` (${vulnTotal})` : ''}` },
						{ value: 'clusters', label: `Clusters${clusterCount ? ` (${clusterCount})` : ''}` },
						{ value: 'secrets', label: `Secrets${secretCount ? ` (${secretCount})` : ''}` },
						{ value: 'labels', label: 'Labels' }
					]}
					bind:value={activeTab}
				/>

				<div class="mt-[2em]">
					{#if activeTab === 'vulnerabilities'}
						<div class="mb-3 flex flex-wrap items-center gap-2">
							{#each ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as sev}
								<button
									type="button"
									class="rounded-full border px-3 py-1 text-xs font-medium transition {vulnSeverityFilter === sev ? 'border-[var(--accent)] bg-[var(--accent)]/10 text-[var(--accent)]' : 'border-[var(--border-color)] text-[var(--text-secondary)] hover:bg-[var(--hover-bg-subtle)]'}"
									onclick={() => (vulnSeverityFilter = sev)}
								>
									{sev === 'ALL' ? 'All' : sev.charAt(0) + sev.slice(1).toLowerCase()}
								</button>
							{/each}
							<span class="ml-auto text-xs text-[var(--text-tertiary)]">
								Sourced from latest SBOM revuln
							</span>
						</div>
						{#if vulnLoading}
							<div class="flex items-center justify-center py-12">
								<div class="h-5 w-5 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
							</div>
						{:else if vulnError}
							<div class="flex flex-col items-center justify-center py-8 text-center">
								<AlertCircle class="mb-3 h-8 w-8 text-[var(--error)]" />
								<p class="text-sm text-[var(--text-secondary)]">{vulnError}</p>
							</div>
						{:else if vulns.length === 0}
							<div class="flex flex-col items-center justify-center py-8 text-center">
								<ShieldCheck class="mb-3 h-8 w-8 text-[var(--success)]" />
								<p class="text-sm font-medium text-[var(--text-secondary)]">No vulnerabilities found</p>
								<p class="mt-1 text-xs text-[var(--text-muted)]">
									This image is clean against the current advisory feeds.
								</p>
							</div>
						{:else}
							<div class="overflow-hidden rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
								<table class="min-w-full divide-y divide-[var(--border-color)]/40 text-sm">
									<thead class="text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
										<tr>
											<th class="w-8 px-2 py-2.5"></th>
											<th class="px-4 py-2.5 text-left">CVE</th>
											<th class="px-4 py-2.5 text-left">Severity</th>
											<th class="px-4 py-2.5 text-left">Package</th>
											<th class="px-4 py-2.5 text-left">Installed</th>
											<th class="px-4 py-2.5 text-left">Fixed in</th>
											<th class="px-4 py-2.5 text-left">Signals</th>
										</tr>
									</thead>
									<tbody class="divide-y divide-[var(--border-color)]/20 text-[var(--text-secondary)]">
										{#each vulns as v (v.vuln_id)}
											{@const isOpen = expandedVuln === v.vuln_id}
											<tr
												class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)]"
												onclick={() => toggleVuln(v.vuln_id)}
											>
												<td class="px-2 py-2 text-[var(--text-tertiary)]">
													{#if isOpen}
														<ChevronDown class="h-4 w-4" />
													{:else}
														<ChevronRight class="h-4 w-4" />
													{/if}
												</td>
												<td class="px-4 py-2 font-mono text-xs">
													<a
														class="text-[var(--accent)] hover:underline"
														href={vulnUrl(v.vuln_id)}
														onclick={(e) => e.stopPropagation()}
													>
														{v.vuln_id}
													</a>
												</td>
												<td class="px-4 py-2">
													<span class="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-semibold {severityClass(v.severity)}">
														{v.severity || 'UNKNOWN'}
													</span>
												</td>
												<td class="px-4 py-2 font-mono text-xs text-[var(--text-bright)]">{v.pkg_name || '—'}</td>
												<td class="px-4 py-2 font-mono text-xs">{v.installed_version || '—'}</td>
												<td class="px-4 py-2 font-mono text-xs {v.fixed_version ? 'text-[var(--success)]' : ''}">
													{v.fixed_version || '—'}
												</td>
												<td class="px-4 py-2">
													<div class="flex flex-wrap gap-1">
														{#if v.kev_known}
															<span class="rounded-full bg-red-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-red-400" title="In CISA KEV — actively exploited">KEV</span>
														{/if}
														{#if v.epss_score && v.epss_score >= 0.5}
															<span class="rounded-full bg-orange-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-orange-400" title="EPSS exploit-prediction score">
																EPSS {(v.epss_score * 100).toFixed(0)}%
															</span>
														{/if}
														{#each v.sources ?? [] as src}
															<span class="rounded-full bg-[var(--hover-bg-subtle)] px-1.5 py-0.5 text-[10px] text-[var(--text-tertiary)]">{src}</span>
														{/each}
													</div>
												</td>
											</tr>
											{#if isOpen}
												{@const det = vulnDetails[v.vuln_id]}
												{@const ready = det && det.status === 'ready' ? det.data : null}
												{@const title = ready?.title || v.title}
												{@const description = ready?.description || v.description}
												{@const sources = ready?.sources ?? v.sources}
												{@const enriching = ready?.enrichment_loading}
												{@const kev = ready?.kev_known ?? v.kev_known}
												{@const kevRansom = ready?.kev_known_ransomware ?? false}
												{@const kevAdded = ready?.kev_date_added}
												{@const epss = ready?.epss_score ?? v.epss_score}
												{@const epssPct = ready?.epss_percentile}
												{@const adv = advisoryLink(v.vuln_id)}
												<tr class="bg-[var(--bg-soft)]/40">
													<td colspan="7" class="px-4 py-4">
														{#if det?.status === 'loading'}
															<div class="flex items-center gap-2 text-xs text-[var(--text-tertiary)]">
																<div class="h-3 w-3 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
																Loading advisory details…
															</div>
														{:else}
															<div class="grid gap-4 lg:grid-cols-3">
																<!-- Left: description + aliases -->
																<div class="lg:col-span-2 space-y-3">
																	{#if title}
																		<p class="text-sm font-semibold text-[var(--text-bright)]">{title}</p>
																	{/if}
																	{#if description}
																		<p class="whitespace-pre-line text-sm leading-relaxed text-[var(--text-secondary)]">{description}</p>
																	{:else if enriching}
																		<div class="flex items-center gap-2 text-xs italic text-[var(--text-muted)]">
																			<div class="h-3 w-3 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
																			Enriching from upstream feeds — re-open in a moment.
																		</div>
																	{:else if det?.status === 'error'}
																		<p class="text-xs italic text-[var(--error)]">Failed to load advisory: {det.message}</p>
																	{:else}
																		<p class="text-xs italic text-[var(--text-muted)]">No description available — open the advisory link for full details.</p>
																	{/if}

																	{#if v.aliases && v.aliases.length > 0}
																		<div class="flex flex-wrap items-center gap-1">
																			<span class="text-xs text-[var(--text-tertiary)]">Aliases:</span>
																			{#each v.aliases as a}
																				<a
																					class="font-mono text-xs text-[var(--accent)] hover:underline"
																					href={vulnUrl(a)}
																				>
																					{a}
																				</a>
																			{/each}
																		</div>
																	{/if}

																	{#if sources && sources.length > 0}
																		<div class="flex flex-wrap items-center gap-1">
																			<span class="text-xs text-[var(--text-tertiary)]">Sources:</span>
																			{#each sources as src}
																				<span class="rounded-full bg-[var(--hover-bg-subtle)] px-2 py-0.5 text-xs text-[var(--text-tertiary)]">{src}</span>
																			{/each}
																		</div>
																	{/if}
																</div>

																<!-- Right: signal cards -->
																<div class="space-y-2">
																	{#if kev}
																		<div class="rounded-xl border border-red-500/30 bg-red-500/5 px-3 py-2.5">
																			<div class="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-red-400">
																				<ShieldX class="h-3.5 w-3.5" /> CISA KEV
																			</div>
																			<p class="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
																				Listed in CISA's <strong>Known Exploited Vulnerabilities</strong> catalog — confirmed in-the-wild exploitation. Patch on KEV-mandated timelines.
																			</p>
																			<div class="mt-1.5 flex flex-wrap items-center gap-2 text-[11px]">
																				{#if kevAdded}
																					<span class="text-[var(--text-tertiary)]">Added {formatShortDate(kevAdded)}</span>
																				{/if}
																				{#if kevRansom}
																					<span class="rounded-full bg-red-500/20 px-1.5 py-0.5 font-semibold text-red-300">ransomware</span>
																				{/if}
																			</div>
																			<a
																				class="mt-1.5 inline-flex items-center gap-1 text-[11px] text-[var(--accent)] hover:underline"
																				href={`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(v.vuln_id)}`}
																				target="_blank"
																				rel="noopener noreferrer"
																			>
																				CISA catalog entry
																				<ExternalLink class="h-3 w-3" />
																			</a>
																		</div>
																	{/if}

																	{#if epss !== undefined && epss !== null && epss > 0}
																		<div class="rounded-xl border border-orange-500/30 bg-orange-500/5 px-3 py-2.5">
																			<div class="flex items-center justify-between gap-2">
																				<div class="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-orange-400">
																					EPSS
																				</div>
																				<span class="text-lg font-bold text-orange-300">
																					{(epss * 100).toFixed(1)}%
																				</span>
																			</div>
																			<p class="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
																				FIRST.org's <strong>Exploit Prediction Scoring System</strong>: daily-updated probability this CVE is exploited within 30 days.
																				{#if epssPct !== undefined}
																					Ranks above {(epssPct * 100).toFixed(0)}% of every CVE in the global EPSS feed.
																				{/if}
																			</p>
																			<a
																				class="mt-1.5 inline-flex items-center gap-1 text-[11px] text-[var(--accent)] hover:underline"
																				href={`https://www.first.org/epss/`}
																				target="_blank"
																				rel="noopener noreferrer"
																			>
																				About EPSS
																				<ExternalLink class="h-3 w-3" />
																			</a>
																		</div>
																	{/if}

																	<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-3 py-2.5">
																		<div class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">
																			Advisory
																		</div>
																		<p class="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
																			Canonical entry on <strong>{adv.label}</strong> — CVSS vector, CWE, references, affected ranges.
																		</p>
																		<a
																			class="mt-1.5 inline-flex items-center gap-1 text-xs font-medium text-[var(--accent)] hover:underline"
																			href={adv.href}
																			target="_blank"
																			rel="noopener noreferrer"
																		>
																			Open {v.vuln_id} on {adv.label}
																			<ExternalLink class="h-3 w-3" />
																		</a>
																	</div>
																</div>
															</div>
														{/if}
													</td>
												</tr>
											{/if}
										{/each}
									</tbody>
								</table>
							</div>
							{#if vulnTotal > vulns.length}
								<p class="mt-2 text-xs text-[var(--text-tertiary)]">
									Showing {vulns.length} of {vulnTotal}.
								</p>
							{/if}
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
					{:else if activeTab === 'secrets'}
						{#if (image.image_secrets?.length ?? 0) === 0}
							<div class="flex flex-col items-center justify-center py-8 text-center">
								<ShieldCheck class="mb-3 h-8 w-8 text-[var(--success)]" />
								<p class="text-sm font-medium text-[var(--text-secondary)]">No secrets detected</p>
								<p class="mt-1 text-xs text-[var(--text-muted)]">
									betterleaks found no leaked credentials in the latest scan.
								</p>
							</div>
						{:else}
							<div class="overflow-hidden rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
								<table class="min-w-full divide-y divide-[var(--border-color)]/40 text-sm">
									<thead class="text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
										<tr>
											<th class="px-4 py-2.5 text-left">Rule</th>
											<th class="px-4 py-2.5 text-left">File</th>
											<th class="px-4 py-2.5 text-left">Match</th>
										</tr>
									</thead>
									<tbody class="divide-y divide-[var(--border-color)]/20 text-[var(--text-secondary)]">
										{#each image.image_secrets ?? [] as s, i (s.rule_id + '@' + (s.file ?? '') + ':' + (s.start_line ?? i))}
											<tr class="transition hover:bg-[var(--hover-bg-subtle)]">
												<td class="px-4 py-2">
													<p class="font-mono text-xs text-[var(--text-bright)]">{s.rule_id}</p>
													{#if s.description}
														<p class="text-xs text-[var(--text-muted)]">{s.description}</p>
													{/if}
												</td>
												<td class="px-4 py-2 font-mono text-xs">
													{s.file ?? '—'}{s.start_line ? `:${s.start_line}` : ''}
												</td>
												<td class="px-4 py-2 font-mono text-xs text-[var(--text-tertiary)]">{s.match ?? '—'}</td>
											</tr>
										{/each}
									</tbody>
								</table>
							</div>
							{#if secretCount > (image.image_secrets?.length ?? 0)}
								<p class="mt-2 text-xs text-[var(--text-tertiary)]">
									Showing first {(image.image_secrets ?? []).length} of {secretCount}; download the artifact for the full report.
								</p>
							{/if}
						{/if}
					{:else if activeTab === 'labels'}
						{#if labelEntries.length === 0 && !ociMeta}
							<div class="flex flex-col items-center justify-center py-8 text-center">
								<Tag class="mb-3 h-8 w-8 text-[var(--text-muted)]" />
								<p class="text-sm font-medium text-[var(--text-secondary)]">No labels found</p>
								<p class="mt-1 text-xs text-[var(--text-muted)]">
									The image config did not declare any OCI labels.
								</p>
							</div>
						{:else}
							<div class="space-y-4">
								{#if ociMeta}
									<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
										{#if ociMeta.created}
											<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-4 py-3">
												<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">Created</p>
												<p class="mt-1 text-sm font-semibold text-[var(--text-bright)]">{formatDate(ociMeta.created)}</p>
											</div>
										{/if}
										{#if ociMeta.architecture}
											<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-4 py-3">
												<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">Architecture</p>
												<p class="mt-1 text-sm font-semibold text-[var(--text-bright)]">{ociMeta.architecture}</p>
											</div>
										{/if}
										{#if ociMeta.os}
											<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-4 py-3">
												<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">OS</p>
												<p class="mt-1 text-sm font-semibold text-[var(--text-bright)]">{ociMeta.os}</p>
											</div>
										{/if}
										{#if ociMeta.author}
											<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-4 py-3">
												<p class="text-xs uppercase tracking-wider text-[var(--text-tertiary)]">Author</p>
												<p class="mt-1 text-sm font-semibold text-[var(--text-bright)]">{ociMeta.author}</p>
											</div>
										{/if}
									</div>
								{/if}
								{#if labelEntries.length > 0}
									<div class="overflow-hidden rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
										<table class="min-w-full divide-y divide-[var(--border-color)]/40 text-sm">
											<thead class="text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
												<tr>
													<th class="px-4 py-2.5 text-left">Label</th>
													<th class="px-4 py-2.5 text-left">Value</th>
												</tr>
											</thead>
											<tbody class="divide-y divide-[var(--border-color)]/20 text-[var(--text-secondary)]">
												{#each labelEntries as [k, val]}
													<tr class="transition hover:bg-[var(--hover-bg-subtle)]">
														<td class="px-4 py-2 font-mono text-xs text-[var(--text-bright)]">{k}</td>
														<td class="px-4 py-2 font-mono text-xs break-all">{val}</td>
													</tr>
												{/each}
											</tbody>
										</table>
									</div>
								{/if}
							</div>
						{/if}
					{/if}
				</div>
			</div>
		</article>
	{/if}
</div>
