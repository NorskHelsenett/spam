<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { Server, Container, Globe, ChevronDown, ExternalLink, SlidersHorizontal, Search } from 'lucide-svelte';
	import { slide, fly } from 'svelte/transition';
	import { cubicOut, cubicIn } from 'svelte/easing';
	import HostChainDrawer from '$lib/components/HostChainDrawer.svelte';
	import ClusterChainDrawer from '$lib/components/ClusterChainDrawer.svelte';
	import DonutChart from '$lib/components/DonutChart.svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';
	import MultiSelect from '$lib/components/MultiSelect.svelte';
	import type { MultiSelectOption } from '$lib/components/MultiSelect.svelte';
	import Toggle from '$lib/components/Toggle.svelte';

	type ClusterRow = {
		cluster: string;
		cluster_id: string;
		environment: string;
		containers: number;
		images: number;
		namespaces: number;
		ingress_count: number;
		last_seen: string;
	};

	type RegistryDist = {
		registry: string;
		image_count: number;
	};

	type ImageDetail = {
		registry: string;
		image: string;
		digest: string;
		tags: string;
		cluster_count: number;
		namespace_count: number;
		container_count: number;
		last_seen: string;
	};

	type HostRow = {
		host: string;
		kind: string;
		name: string;
		namespace: string;
		cluster: string;
		cluster_id: string;
		environment: string;
		tls: boolean;
		lb_ips: string;
		ingress_class: string;
		backends: string;
		workload_count: number;
		last_seen: string;
	};

	type HostResolve = {
		ips: string[];
		is_local: boolean;
		error?: string;
	};

	type HostMeta = {
		title: string;
		has_favicon: boolean;
	};

	let clusters: ClusterRow[] = $state([]);
	let registryDist: RegistryDist[] = $state([]);
	let imageDetails: ImageDetail[] = $state([]);
	let hosts: HostRow[] = $state([]);
	let hostResolutions = $state<Record<string, HostResolve>>({});
	let hostMetas = $state<Record<string, HostMeta>>({});
	let loading = $state(true);
	let error = $state('');
	let activeTab = $state('clusters');
	let imagesFetched = $state(false);
	let hostsFetched = $state(false);
	let tick = $state(0);
	let chainDrawerOpen = $state(false);
	let chainDrawerRow: HostRow | null = $state(null);
	let clusterDrawerOpen = $state(false);
	let clusterDrawerRow: ClusterRow | null = $state(null);

	function openClusterDrawer(row: ClusterRow) {
		if (clusterDrawerOpen && clusterDrawerRow?.cluster_id === row.cluster_id) {
			clusterDrawerOpen = false;
			clusterDrawerRow = null;
		} else {
			clusterDrawerRow = row;
			clusterDrawerOpen = true;
		}
	}

	function openChainDrawer(row: HostRow) {
		if (chainDrawerOpen && chainDrawerRow?.host === row.host && chainDrawerRow?.cluster_id === row.cluster_id && chainDrawerRow?.namespace === row.namespace) {
			chainDrawerOpen = false;
			chainDrawerRow = null;
		} else {
			chainDrawerRow = row;
			chainDrawerOpen = true;
		}
	}

	const palette = [
		'var(--accent)', 'var(--blue)', 'var(--green)',
		'var(--yellow)', 'var(--orange)', 'var(--purple)', 'var(--aqua)'
	];

	const loadMain = async () => {
		try {
			const [clusterRes, regRes] = await Promise.all([
				fetch('/api/clusters/summary', { credentials: 'include' }),
				fetch('/api/clusters/registry-distribution', { credentials: 'include' })
			]);
			if (clusterRes.ok) clusters = await clusterRes.json();
			if (regRes.ok) registryDist = await regRes.json();
			loadHosts();
		} catch {
			error = 'Failed to load cluster data';
		} finally {
			loading = false;
		}
	};

	const loadImages = async () => {
		if (imagesFetched) return;
		try {
			const res = await fetch('/api/clusters/images/detail', { credentials: 'include' });
			if (res.ok) imageDetails = await res.json();
			imagesFetched = true;
		} catch { /* silent */ }
	};

	const loadHosts = async () => {
		if (hostsFetched) return;
		try {
			const res = await fetch('/api/clusters/hosts', { credentials: 'include' });
			if (res.ok) {
				hosts = await res.json();
				const unique = [...new Set(hosts.map((h) => h.host))];
				for (const host of unique) {
					fetchHostResolve(host);
					fetchHostMeta(host);
				}
			}
			hostsFetched = true;
		} catch { /* silent */ }
	};

	const fetchHostResolve = (host: string) => {
		if (hostResolutions[host]) return;
		fetch(`/api/clusters/hosts/resolve?host=${encodeURIComponent(host)}`, { credentials: 'include' })
			.then((r) => r.json())
			.then((data: HostResolve) => {
				hostResolutions = { ...hostResolutions, [host]: data };
			})
			.catch(() => {
				hostResolutions = { ...hostResolutions, [host]: { ips: [], is_local: false, error: 'failed' } };
			});
	};

	const fetchHostMeta = (host: string) => {
		if (hostMetas[host]) return;
		fetch(`/api/clusters/hosts/meta?host=${encodeURIComponent(host)}`, { credentials: 'include' })
			.then((r) => r.json())
			.then((data: HostMeta) => {
				hostMetas = { ...hostMetas, [host]: data };
			})
			.catch(() => {
				hostMetas = { ...hostMetas, [host]: { title: '', has_favicon: false } };
			});
	};

	const hostUrl = (host: string, tls: boolean) => `${tls ? 'https' : 'http'}://${host}`;
	const faviconProxyUrl = (host: string) => `/api/clusters/hosts/favicon?host=${encodeURIComponent(host)}`;

	onMount(() => {
		if (!browser) return;
		loadMain();

		const interval = setInterval(() => tick++, 60_000);

		const es = new EventSource('/api/app/stream');
		es.addEventListener('scam_ingest', () => {
			loadMain();
			if (imagesFetched) { imagesFetched = false; loadImages(); }
			if (hostsFetched) { hostsFetched = false; loadHosts(); }
		});

		return () => {
			clearInterval(interval);
			es.close();
		};
	});

	$effect(() => {
		if (activeTab === 'images') loadImages();
	});

	const totalImages = $derived(clusters.reduce((s, c) => s + c.images, 0));
	const totalContainers = $derived(clusters.reduce((s, c) => s + c.containers, 0));
	const uniqueHosts = $derived(new Set(hosts.map((h) => h.host)).size);

	const registrySegments = $derived(
		registryDist.map((r, i) => ({
			label: r.registry,
			value: r.image_count,
			color: palette[i % palette.length]
		}))
	);
	const registryTotal = $derived(registryDist.reduce((s, r) => s + r.image_count, 0));

	const isPrivateIP = (ip: string): boolean => {
		const parts = ip.split('.').map(Number);
		if (parts.length !== 4) return false;
		if (parts[0] === 10) return true;
		if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
		if (parts[0] === 192 && parts[1] === 168) return true;
		if (parts[0] === 127) return true;
		return false;
	};

	const exposureCounts = $derived.by(() => {
		const seen = new Map<string, HostRow>();
		for (const h of hosts) {
			if (!seen.has(h.host)) seen.set(h.host, h);
		}
		let external = 0;
		let internal = 0;
		let pending = 0;
		for (const [host, h] of seen) {
			const r = hostResolutions[host];
			if (!r) { pending++; continue; }
			// DNS resolved — use that
			if (!r.error) {
				if (r.is_local) internal++; else external++;
				continue;
			}
			// DNS unresolvable — fall back to LB IP
			const firstLB = h.lb_ips?.split(',')[0]?.trim();
			if (firstLB && isPrivateIP(firstLB)) { internal++; continue; }
			if (firstLB) { external++; continue; }
			// No DNS, no LB — unknown, count as external
			external++;
		}
		return { external, internal, pending };
	});
	const exposureSegments = $derived([
		{ label: 'External', value: exposureCounts.external, color: 'var(--red)' },
		{ label: 'Internal', value: exposureCounts.internal, color: 'var(--green)' }
	]);
	const exposureTotal = $derived(exposureCounts.external + exposureCounts.internal + exposureCounts.pending);

	const timeAgo = (iso: string, _tick: number) => {
		if (!iso) return '';
		const diff = Date.now() - new Date(iso).getTime();
		const mins = Math.floor(diff / 60000);
		if (mins < 1) return 'just now';
		if (mins < 60) return `${mins}m ago`;
		const hours = Math.floor(mins / 60);
		if (hours < 24) return `${hours}h ago`;
		return `${Math.floor(hours / 24)}d ago`;
	};

	const shortDigest = (d: string) => {
		if (!d) return '';
		const hash = d.startsWith('sha256:') ? d.slice(7) : d;
		return hash.slice(0, 12);
	};

	const parseTags = (t: string) => t ? t.split(',').filter(Boolean) : [];

	// --- Cluster filters ---
	let clusterFilterOpen = $state(false);
	let clusterSearch = $state('');
	let clusterRecentOnly = $state(false);

	const clusterActiveFilterCount = $derived(
		(clusterSearch.trim() ? 1 : 0) + (clusterRecentOnly ? 1 : 0)
	);

	const filteredClusters = $derived(
		clusters.filter((c) => {
			if (clusterRecentOnly && c.last_seen) {
				const age = Date.now() - new Date(c.last_seen).getTime();
				if (age > 24 * 60 * 60 * 1000) return false;
			}
			if (clusterSearch.trim()) {
				const q = clusterSearch.trim().toLowerCase();
				if (
					!(c.cluster || '').toLowerCase().includes(q) &&
					!(c.cluster_id || '').toLowerCase().includes(q) &&
					!(c.environment || '').toLowerCase().includes(q)
				) return false;
			}
			return true;
		})
	);

	const clearClusterFilters = () => {
		clusterSearch = '';
		clusterRecentOnly = false;
	};

	// --- Image filters ---
	let imageFilterOpen = $state(false);
	let imageSearch = $state('');
	let imageSelectedRegistries: string[] = $state([]);

	const imageRegistryOptions: MultiSelectOption[] = $derived(
		[...new Set(imageDetails.map((i) => i.registry))].sort().map((r) => ({ value: r, label: r }))
	);

	const imageActiveFilterCount = $derived(
		(imageSearch.trim() ? 1 : 0) + (imageSelectedRegistries.length > 0 ? 1 : 0)
	);

	const filteredImages = $derived(
		imageDetails.filter((img) => {
			if (imageSelectedRegistries.length > 0 && !imageSelectedRegistries.includes(img.registry)) return false;
			if (imageSearch.trim()) {
				const q = imageSearch.trim().toLowerCase();
				if (
					!img.image.toLowerCase().includes(q) &&
					!img.registry.toLowerCase().includes(q) &&
					!(img.tags || '').toLowerCase().includes(q) &&
					!(img.digest || '').toLowerCase().includes(q)
				) return false;
			}
			return true;
		})
	);

	const clearImageFilters = () => {
		imageSearch = '';
		imageSelectedRegistries = [];
	};

	// --- Host filters ---
	let hostFilterOpen = $state(false);
	let hostSearch = $state('');
	let hostSelectedClusters: string[] = $state([]);
	let hostSelectedNamespaces: string[] = $state([]);
	let hostSelectedKinds: string[] = $state([]);
	let hostActiveWorkloadsOnly = $state(false);

	const hostClusterOptions: MultiSelectOption[] = $derived(
		[...new Set(hosts.map((h) => h.cluster || h.cluster_id))].sort().map((c) => ({ value: c, label: c }))
	);
	const hostNamespaceOptions: MultiSelectOption[] = $derived(
		[...new Set(hosts.map((h) => h.namespace))].sort().map((n) => ({ value: n, label: n }))
	);
	const hostKindOptions: MultiSelectOption[] = $derived(
		[...new Set(hosts.map((h) => h.kind))].sort().map((k) => ({ value: k, label: k }))
	);

	const hostActiveFilterCount = $derived(
		(hostSearch.trim() ? 1 : 0) +
		(hostSelectedClusters.length > 0 ? 1 : 0) +
		(hostSelectedNamespaces.length > 0 ? 1 : 0) +
		(hostSelectedKinds.length > 0 ? 1 : 0) +
		(hostActiveWorkloadsOnly ? 1 : 0)
	);

	const filteredHosts = $derived(
		hosts.filter((h) => {
			if (hostActiveWorkloadsOnly && h.workload_count === 0) return false;
			if (hostSelectedClusters.length > 0 && !hostSelectedClusters.includes(h.cluster || h.cluster_id)) return false;
			if (hostSelectedNamespaces.length > 0 && !hostSelectedNamespaces.includes(h.namespace)) return false;
			if (hostSelectedKinds.length > 0 && !hostSelectedKinds.includes(h.kind)) return false;
			if (hostSearch.trim()) {
				const q = hostSearch.trim().toLowerCase();
				const fields = [
					h.host, h.namespace, h.name,
					h.cluster, h.cluster_id, h.environment,
					h.kind, h.ingress_class, h.backends, h.lb_ips
				];
				if (!fields.some((f) => f && f.toLowerCase().includes(q))) return false;
			}
			return true;
		})
	);

	const clearHostFilters = () => {
		hostSearch = '';
		hostSelectedClusters = [];
		hostSelectedNamespaces = [];
		hostSelectedKinds = [];
		hostActiveWorkloadsOnly = false;
	};

	// --- Sorting ---
	type SortDir = 'asc' | 'desc';
	let clusterSortKey = $state<keyof ClusterRow>('cluster');
	let clusterSortDir = $state<SortDir>('asc');
	let imageSortKey = $state<keyof ImageDetail>('container_count');
	let imageSortDir = $state<SortDir>('desc');
	let hostSortKey = $state<keyof HostRow>('cluster');
	let hostSortDir = $state<SortDir>('asc');

	const cmp = (a: any, b: any, dir: SortDir): number => {
		if (a == null && b == null) return 0;
		if (a == null) return 1;
		if (b == null) return -1;
		const result = typeof a === 'string' ? a.localeCompare(b) : (a as number) - (b as number);
		return dir === 'asc' ? result : -result;
	};

	const sc = (k: keyof ClusterRow) => () => {
		if (clusterSortKey === k) { clusterSortDir = clusterSortDir === 'asc' ? 'desc' : 'asc'; }
		else { clusterSortKey = k; clusterSortDir = 'desc'; }
	};

	const si = (k: keyof ImageDetail) => () => {
		if (imageSortKey === k) { imageSortDir = imageSortDir === 'asc' ? 'desc' : 'asc'; }
		else { imageSortKey = k; imageSortDir = 'desc'; }
	};

	const sh = (k: keyof HostRow) => () => {
		if (hostSortKey === k) { hostSortDir = hostSortDir === 'asc' ? 'desc' : 'asc'; }
		else { hostSortKey = k; hostSortDir = 'asc'; }
	};

	const sortedClusters = $derived(
		[...filteredClusters].sort((a, b) => cmp(a[clusterSortKey], b[clusterSortKey], clusterSortDir))
	);

	const sortedImages = $derived(
		[...filteredImages].sort((a, b) => cmp(a[imageSortKey], b[imageSortKey], imageSortDir))
	);

	const sortedHosts = $derived(
		[...filteredHosts].sort((a, b) => {
			const primary = cmp(a[hostSortKey], b[hostSortKey], hostSortDir);
			if (primary !== 0) return primary;
			return hostSortKey === 'cluster'
				? (a.host ?? '').localeCompare(b.host ?? '')
				: (a.cluster ?? '').localeCompare(b.cluster ?? '');
		})
	);
</script>

<svelte:head>
	<title>Clusters &middot; Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Clusters</h1>
			<p class="text-sm text-[var(--text-tertiary)]">Live container image inventory from SCAM agents.</p>
		</header>

		{#if loading}
			<div class="flex flex-col items-center justify-center gap-5 py-24">
				<Server class="h-12 w-12 text-[var(--yellow)]" />
				<div class="w-48 overflow-hidden rounded-full bg-[var(--bg2)]/30">
					<div class="loading-bar h-1 rounded-full bg-[var(--yellow)]"></div>
				</div>
				<!-- <p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Waiting for first probe</p> -->
			</div>
		{:else if error}
			<div class="flex flex-col items-center justify-center py-24">
				<Server class="h-12 w-12 text-[var(--error)]" />
				<p class="mt-5 text-base font-medium text-[var(--text-secondary)]">{error}</p>
			</div>
		{:else if clusters.length === 0}
			<div class="flex flex-col items-center justify-center gap-5 py-24">
				<Server class="h-12 w-12 text-[var(--yellow)]" />
				<p class="text-base font-medium text-[var(--text-secondary)]">No cluster data yet</p>
				<p class="text-sm text-[var(--text-muted)]">Deploy a SCAM agent to start collecting container inventory.</p>
				<div class="w-48 overflow-hidden rounded-full bg-[var(--bg2)]/30">
					<div class="loading-bar h-1 rounded-full bg-[var(--yellow)]"></div>
				</div>
			</div>
		{:else}
			<!-- Metric cards -->
			<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
				<article class="metric-card p-4">
					<div class="flex items-center gap-2">
						<Server class="h-4 w-4 text-[var(--accent)]" />
						<h2 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Clusters</h2>
					</div>
					<p class="mt-2 text-2xl font-bold text-[var(--text-bright)]">{clusters.length}</p>
					<p class="mt-1 text-xs text-[var(--text-muted)]">Reporting agents</p>
				</article>
				<article class="metric-card p-4">
					<div class="flex items-center gap-2">
						<Container class="h-4 w-4 text-[var(--blue)]" />
						<h2 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Images</h2>
					</div>
					<p class="mt-2 text-2xl font-bold text-[var(--text-bright)]">{totalImages}</p>
					<p class="mt-1 text-xs text-[var(--text-muted)]">Unique by digest</p>
				</article>
				<article class="metric-card p-4">
					<div class="flex items-center gap-2">
						<Container class="h-4 w-4 text-[var(--green)]" />
						<h2 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Containers</h2>
					</div>
					<p class="mt-2 text-2xl font-bold text-[var(--text-bright)]">{totalContainers}</p>
					<p class="mt-1 text-xs text-[var(--text-muted)]">Running instances</p>
				</article>
				<article class="metric-card p-4">
					<div class="flex items-center gap-2">
						<Globe class="h-4 w-4 text-[var(--red)]" />
						<h2 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Hosts</h2>
					</div>
					<p class="mt-2 text-2xl font-bold text-[var(--text-bright)]">{uniqueHosts}</p>
					<p class="mt-1 text-xs text-[var(--text-muted)]">Unique hostnames</p>
				</article>
			</div>

			<!-- Charts -->
			<div class="grid gap-6 lg:grid-cols-2">
				{#if registryTotal > 0}
					<div class="metric-card rounded-2xl p-5">
						<DonutChart title="Registry distribution" total={registryTotal} segments={registrySegments} />
					</div>
				{/if}
				{#if exposureTotal > 0}
					<div class="metric-card rounded-2xl p-5">
						<DonutChart title="Network exposure" total={exposureTotal} segments={exposureSegments} />
					</div>
				{/if}
			</div>

			<!-- Tab selector -->
			<TabSelector
				bind:value={activeTab}
				options={[
					{ value: 'clusters', label: 'Clusters' },
					{ value: 'images', label: 'Images' },
					{ value: 'hosts', label: 'Hosts' }
				]}
			/>
		{/if}
	</section>

	<!-- Tables -->
	{#if !loading && !error && clusters.length > 0}
		{#if activeTab === 'clusters'}
			<section class="panel-surface relative space-y-4 overflow-hidden px-6 py-6 sm:px-10 sm:py-8" style:min-height={clusterDrawerOpen ? '600px' : undefined}>
				<header class="flex items-start justify-between gap-4">
					<div>
						<h2 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Clusters</h2>
						<p class="text-sm text-[var(--text-tertiary)]">
							Reporting SCAM agents and their inventory.
							{#if clusterActiveFilterCount > 0}
								<span class="text-[var(--text-muted)]">&middot; showing {filteredClusters.length} of {clusters.length}</span>
							{/if}
						</p>
					</div>
					<button
						type="button"
						class="host-filter-toggle"
						class:active={clusterFilterOpen}
						onclick={() => (clusterFilterOpen = !clusterFilterOpen)}
						aria-expanded={clusterFilterOpen}
						aria-label="Toggle filters"
					>
						<SlidersHorizontal size={14} />
						<span>Filters</span>
						{#if clusterActiveFilterCount > 0}
							<span class="host-filter-badge">{clusterActiveFilterCount}</span>
						{/if}
					</button>
				</header>

				{#if clusterFilterOpen}
					<div transition:slide={{ duration: 220, easing: cubicOut }} class="pb-2">
						<div class="flex flex-wrap items-start gap-6">
							<div class="flex flex-col gap-1">
								<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Search</span>
								<div class="relative flex items-center">
									<Search size={13} class="pointer-events-none absolute left-2.5 text-[var(--text-muted)]" />
									<input
										type="text"
										class="host-search-input"
										placeholder="Cluster name, environment…"
										bind:value={clusterSearch}
									/>
								</div>
							</div>

							<div class="flex flex-col gap-1">
								<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Seen recently</span>
								<div class="flex items-center h-[28px]">
									<Toggle bind:checked={clusterRecentOnly} label="Last 24h" />
								</div>
							</div>

							{#if clusterActiveFilterCount > 0}
								<div class="flex items-center gap-3 ml-auto" style="padding-top: calc(0.65rem * 1.2 + 0.25rem);">
									<button type="button" class="host-clear-filters" onclick={clearClusterFilters}>Clear all</button>
								</div>
							{/if}
						</div>
					</div>
				{/if}

				<div class="overflow-x-auto">
					<table class="min-w-full divide-y divide-[var(--border-color)]/30 text-sm">
						<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
							<tr>
								<th class="sortable-th px-5 py-3 text-left" onclick={sc('cluster')}>Cluster <ChevronDown class="sort-icon {clusterSortKey === 'cluster' ? 'active' : ''} {clusterSortKey === 'cluster' && clusterSortDir === 'asc' ? 'flipped' : ''}" /></th>
								<th class="sortable-th px-5 py-3 text-left" onclick={sc('environment')}>Environment <ChevronDown class="sort-icon {clusterSortKey === 'environment' ? 'active' : ''} {clusterSortKey === 'environment' && clusterSortDir === 'asc' ? 'flipped' : ''}" /></th>
								<th class="sortable-th px-5 py-3 text-right" onclick={sc('images')}>Images <ChevronDown class="sort-icon {clusterSortKey === 'images' ? 'active' : ''} {clusterSortKey === 'images' && clusterSortDir === 'asc' ? 'flipped' : ''}" /></th>
								<th class="sortable-th px-5 py-3 text-right" onclick={sc('containers')}>Containers <ChevronDown class="sort-icon {clusterSortKey === 'containers' ? 'active' : ''} {clusterSortKey === 'containers' && clusterSortDir === 'asc' ? 'flipped' : ''}" /></th>
								<th class="sortable-th px-5 py-3 text-right" onclick={sc('namespaces')}>Namespaces <ChevronDown class="sort-icon {clusterSortKey === 'namespaces' ? 'active' : ''} {clusterSortKey === 'namespaces' && clusterSortDir === 'asc' ? 'flipped' : ''}" /></th>
								<th class="sortable-th px-5 py-3 text-right" onclick={sc('ingress_count')}>Routes <ChevronDown class="sort-icon {clusterSortKey === 'ingress_count' ? 'active' : ''} {clusterSortKey === 'ingress_count' && clusterSortDir === 'asc' ? 'flipped' : ''}" /></th>
								<th class="sortable-th px-5 py-3 text-left" onclick={sc('last_seen')}>Last seen <ChevronDown class="sort-icon {clusterSortKey === 'last_seen' ? 'active' : ''} {clusterSortKey === 'last_seen' && clusterSortDir === 'asc' ? 'flipped' : ''}" /></th>
							</tr>
						</thead>
						<tbody class="divide-y divide-[var(--border-color)]/15 text-[var(--text-secondary)]">
							{#each sortedClusters as c}
								<tr class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)] {clusterDrawerOpen && clusterDrawerRow?.cluster_id === c.cluster_id ? 'bg-[var(--hover-bg-subtle)]' : ''}" onclick={() => openClusterDrawer(c)}>
									<td class="px-5 py-3 font-semibold text-[var(--text-bright)]">{c.cluster || c.cluster_id}</td>
									<td class="px-5 py-3">
										{#if c.environment}
											<span class="rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs">{c.environment}</span>
										{:else}
											<span class="text-[var(--text-muted)]">&mdash;</span>
										{/if}
									</td>
									<td class="px-5 py-3 text-right font-semibold">{c.images}</td>
									<td class="px-5 py-3 text-right">{c.containers}</td>
									<td class="px-5 py-3 text-right">{c.namespaces}</td>
									<td class="px-5 py-3 text-right">{c.ingress_count}</td>
									<td class="px-5 py-3 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">{timeAgo(c.last_seen, tick)}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>

				{#if clusterDrawerOpen && clusterDrawerRow}
					<div
						class="absolute inset-y-0 right-0 z-10 w-[780px] rounded-l-[10px] border-l border-[var(--border-color)] shadow-xl"
						in:fly={{ x: 780, duration: 240, easing: cubicOut, opacity: 1 }}
						out:fly={{ x: 780, duration: 200, easing: cubicIn, opacity: 1 }}
					>
						<ClusterChainDrawer
							cluster={clusterDrawerRow.cluster}
							clusterId={clusterDrawerRow.cluster_id}
							onClose={() => { clusterDrawerOpen = false; clusterDrawerRow = null; }}
						/>
					</div>
				{/if}
			</section>
		{:else if activeTab === 'images'}
			<section class="panel-surface space-y-4 px-6 py-6 sm:px-10 sm:py-8">
				{#if imageDetails.length === 0}
					<div class="flex flex-col items-center justify-center gap-3 py-16">
						<Container class="h-10 w-10 text-[var(--yellow)]" />
						<p class="text-base font-medium text-[var(--text-secondary)]">No images</p>
						<p class="text-sm text-[var(--text-muted)]">No container images with resolved digests yet.</p>
					</div>
				{:else}
					<header class="flex items-start justify-between gap-4">
						<div>
							<h2 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Images</h2>
							<p class="text-sm text-[var(--text-tertiary)]">
								Container images across all clusters.
								{#if imageActiveFilterCount > 0}
									<span class="text-[var(--text-muted)]">&middot; showing {filteredImages.length} of {imageDetails.length}</span>
								{/if}
							</p>
						</div>
						<button
							type="button"
							class="host-filter-toggle"
							class:active={imageFilterOpen}
							onclick={() => (imageFilterOpen = !imageFilterOpen)}
							aria-expanded={imageFilterOpen}
							aria-label="Toggle filters"
						>
							<SlidersHorizontal size={14} />
							<span>Filters</span>
							{#if imageActiveFilterCount > 0}
								<span class="host-filter-badge">{imageActiveFilterCount}</span>
							{/if}
						</button>
					</header>

					{#if imageFilterOpen}
						<div transition:slide={{ duration: 220, easing: cubicOut }} class="pb-2">
							<div class="flex flex-wrap items-start gap-6">
								<div class="flex flex-col gap-1">
									<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Search</span>
									<div class="relative flex items-center">
										<Search size={13} class="pointer-events-none absolute left-2.5 text-[var(--text-muted)]" />
										<input
											type="text"
											class="host-search-input"
											placeholder="Image name, tag, digest…"
											bind:value={imageSearch}
										/>
									</div>
								</div>

								<div class="flex flex-col gap-1">
									<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Registry</span>
									<MultiSelect bind:selected={imageSelectedRegistries} options={imageRegistryOptions} placeholder="All registries" size="sm" />
								</div>

								{#if imageActiveFilterCount > 0}
									<div class="flex items-center gap-3 ml-auto" style="padding-top: calc(0.65rem * 1.2 + 0.25rem);">
										<button type="button" class="host-clear-filters" onclick={clearImageFilters}>Clear all</button>
									</div>
								{/if}
							</div>
						</div>
					{/if}

					<div class="overflow-x-auto">
					<table class="min-w-full divide-y divide-[var(--border-color)]/30 text-sm">
							<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
								<tr>
									<th class="sortable-th px-5 py-3 text-left" onclick={si('registry')}>Registry <ChevronDown class="sort-icon {imageSortKey === 'registry' ? 'active' : ''} {imageSortKey === 'registry' && imageSortDir === 'asc' ? 'flipped' : ''}" /></th>
									<th class="sortable-th px-5 py-3 text-left" onclick={si('image')}>Image <ChevronDown class="sort-icon {imageSortKey === 'image' ? 'active' : ''} {imageSortKey === 'image' && imageSortDir === 'asc' ? 'flipped' : ''}" /></th>
									<th class="px-5 py-3 text-left">Digest</th>
									<th class="px-5 py-3 text-left">Tags</th>
									<th class="sortable-th px-5 py-3 text-right" onclick={si('cluster_count')}>Clusters <ChevronDown class="sort-icon {imageSortKey === 'cluster_count' ? 'active' : ''} {imageSortKey === 'cluster_count' && imageSortDir === 'asc' ? 'flipped' : ''}" /></th>
									<th class="sortable-th px-5 py-3 text-right" onclick={si('container_count')}>Containers <ChevronDown class="sort-icon {imageSortKey === 'container_count' ? 'active' : ''} {imageSortKey === 'container_count' && imageSortDir === 'asc' ? 'flipped' : ''}" /></th>
									<th class="sortable-th px-5 py-3 text-left" onclick={si('last_seen')}>Last seen <ChevronDown class="sort-icon {imageSortKey === 'last_seen' ? 'active' : ''} {imageSortKey === 'last_seen' && imageSortDir === 'asc' ? 'flipped' : ''}" /></th>
								</tr>
							</thead>
							<tbody class="divide-y divide-[var(--border-color)]/15 text-[var(--text-secondary)]">
								{#each sortedImages as img}
									<tr class="transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]">
										<td class="px-5 py-3 text-xs text-[var(--text-tertiary)]">{img.registry}</td>
										<td class="px-5 py-3 font-semibold text-[var(--text-bright)]">{img.image}</td>
										<td class="px-5 py-3">
											{#if img.digest}
												<code class="rounded bg-[var(--hover-bg)] px-1.5 py-0.5 text-xs text-[var(--text-secondary)]">{shortDigest(img.digest)}</code>
											{:else}
												<span class="text-xs text-[var(--text-muted)]" title="The kubelet has not resolved a digest for this image. This typically happens when the image was pulled from a local cache (imagePullPolicy: IfNotPresent) or the container hasn't started yet.">unresolved</span>
											{/if}
										</td>
										<td class="px-5 py-3">
											<div class="flex flex-wrap gap-1">
												{#each parseTags(img.tags) as tag}
													<span class="rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs text-[var(--text-secondary)]">{tag}</span>
												{/each}
											</div>
										</td>
										<td class="px-5 py-3 text-right">{img.cluster_count}</td>
										<td class="px-5 py-3 text-right font-semibold">{img.container_count}</td>
										<td class="px-5 py-3 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">{timeAgo(img.last_seen, tick)}</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{/if}
			</section>
		{:else if activeTab === 'hosts'}
			<section class="panel-surface relative space-y-4 overflow-hidden px-6 py-6 sm:px-10 sm:py-8" style:min-height={chainDrawerOpen ? '600px' : undefined}>
				{#if hosts.length > 0}
					<header class="flex items-start justify-between gap-4">
						<div>
							<h2 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Hosts</h2>
							<p class="text-sm text-[var(--text-tertiary)]">
								Hostnames exposed via Ingress and route resources.
								{#if hostActiveFilterCount > 0}
									<span class="text-[var(--text-muted)]">&middot; showing {filteredHosts.length} of {hosts.length}</span>
								{/if}
							</p>
						</div>
						<button
							type="button"
							class="host-filter-toggle"
							class:active={hostFilterOpen}
							onclick={() => (hostFilterOpen = !hostFilterOpen)}
							aria-expanded={hostFilterOpen}
							aria-label="Toggle filters"
						>
							<SlidersHorizontal size={14} />
							<span>Filters</span>
							{#if hostActiveFilterCount > 0}
								<span class="host-filter-badge">{hostActiveFilterCount}</span>
							{/if}
						</button>
					</header>

					{#if hostFilterOpen}
						<div transition:slide={{ duration: 220, easing: cubicOut }} class="pb-2">
							<div class="flex flex-wrap items-start gap-6">
								<div class="flex flex-col gap-1">
									<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Search</span>
									<div class="relative flex items-center">
										<Search size={13} class="pointer-events-none absolute left-2.5 text-[var(--text-muted)]" />
										<input
											type="text"
											class="host-search-input"
											placeholder="Host, cluster, backend, namespace…"
											bind:value={hostSearch}
										/>
									</div>
								</div>

								<div class="flex flex-col gap-1">
									<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Cluster</span>
									<MultiSelect bind:selected={hostSelectedClusters} options={hostClusterOptions} placeholder="All clusters" size="sm" />
								</div>

								<div class="flex flex-col gap-1">
									<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Namespace</span>
									<MultiSelect bind:selected={hostSelectedNamespaces} options={hostNamespaceOptions} placeholder="All namespaces" size="sm" />
								</div>

								<div class="flex flex-col gap-1">
									<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Kind</span>
									<MultiSelect bind:selected={hostSelectedKinds} options={hostKindOptions} placeholder="All kinds" size="sm" />
								</div>

								<div class="flex flex-col gap-1">
									<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Workloads</span>
									<div class="flex items-center h-[28px]">
										<Toggle bind:checked={hostActiveWorkloadsOnly} label="Active only" />
									</div>
								</div>

								{#if hostActiveFilterCount > 0}
									<div class="flex items-center gap-3 ml-auto" style="padding-top: calc(0.65rem * 1.2 + 0.25rem);">
										<button
											type="button"
											class="host-clear-filters"
											onclick={clearHostFilters}
										>
											Clear all
										</button>
									</div>
								{/if}
							</div>
						</div>
					{/if}
				{/if}

				{#if hosts.length === 0}
					<div class="flex flex-col items-center justify-center gap-3 py-16">
						<Globe class="h-10 w-10 text-[var(--yellow)]" />
						<p class="text-base font-medium text-[var(--text-secondary)]">No hosts</p>
						<p class="text-sm text-[var(--text-muted)]">No exposed FQDNs found from Ingress or route resources.</p>
					</div>
				{:else}
					<div class="overflow-x-auto">
						<table class="min-w-full divide-y divide-[var(--border-color)]/30 text-sm">
							<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
								<tr>
									<th class="w-12 py-3 pl-5 pr-0"></th>
									<th class="sortable-th px-5 py-3 text-left" onclick={sh('host')}>Host <ChevronDown class="sort-icon {hostSortKey === 'host' ? 'active' : ''} {hostSortKey === 'host' && hostSortDir === 'asc' ? 'flipped' : ''}" /></th>
									<th class="px-5 py-3 text-left">IP</th>
									<th class="sortable-th px-5 py-3 text-left" onclick={sh('namespace')}>Namespace <ChevronDown class="sort-icon {hostSortKey === 'namespace' ? 'active' : ''} {hostSortKey === 'namespace' && hostSortDir === 'asc' ? 'flipped' : ''}" /></th>
									<th class="sortable-th px-5 py-3 text-left" onclick={sh('name')}>Name <ChevronDown class="sort-icon {hostSortKey === 'name' ? 'active' : ''} {hostSortKey === 'name' && hostSortDir === 'asc' ? 'flipped' : ''}" /></th>
									<th class="sortable-th px-5 py-3 text-left" onclick={sh('cluster')}>Cluster <ChevronDown class="sort-icon {hostSortKey === 'cluster' ? 'active' : ''} {hostSortKey === 'cluster' && hostSortDir === 'asc' ? 'flipped' : ''}" /></th>
								</tr>
							</thead>
							<tbody class="divide-y divide-[var(--border-color)]/15 text-[var(--text-secondary)]">
								{#each sortedHosts as h}
									{@const resolved = hostResolutions[h.host]}
									{@const meta = hostMetas[h.host]}
									<tr class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)] {chainDrawerOpen && chainDrawerRow?.host === h.host && chainDrawerRow?.cluster_id === h.cluster_id ? 'bg-[var(--hover-bg-subtle)]' : ''}" style="border: none;{h.backends && h.workload_count === 0 ? ' opacity: 0.4;' : ''}" onclick={() => openChainDrawer(h)}>
										<td class="w-12 py-3 pl-5 pr-0">
											<div class="flex h-7 w-7 items-center justify-center">
												{#if meta?.has_favicon}
													<img
														src={faviconProxyUrl(h.host)}
														alt=""
														class="h-6 w-6 rounded"
													/>
												{/if}
											</div>
										</td>
										<td class="px-5 py-3">
											<div class="min-w-0">
												<span class="inline-flex items-center gap-1.5">
													<span class="font-semibold text-[var(--text-bright)]">{h.host}</span>
													<a
														href={hostUrl(h.host, h.tls)}
														target="_blank"
														rel="noopener noreferrer"
														class="text-[var(--text-muted)] transition-colors hover:text-[var(--accent)]"
													><ExternalLink class="h-3 w-3" /></a>
												</span>
												{#if meta?.title}
													<div class="mt-0.5 truncate text-xs text-[var(--text-tertiary)]">{meta.title}</div>
												{/if}
											</div>
										</td>
										<td class="px-5 py-3 text-xs">
											<div class="flex items-center gap-3">
												<span class="w-6 text-[10px] uppercase tracking-wider text-[var(--text-tertiary)]">lb</span>
												{#if h.lb_ips}
													<code class="text-[var(--text-secondary)]">{h.lb_ips}</code>
													{#if !(resolved && !resolved.error)}
														{#if isPrivateIP(h.lb_ips.split(',')[0].trim())}
															<span class="rounded-full bg-[var(--blue)]/15 px-1.5 py-0.5 text-[10px] font-medium text-[var(--blue)]">local</span>
														{:else}
															<span class="rounded-full bg-[var(--green)]/15 px-1.5 py-0.5 text-[10px] font-medium text-[var(--green)]">external</span>
														{/if}
													{/if}
												{:else}
													<span class="text-[var(--text-tertiary)]">&mdash;</span>
												{/if}
											</div>
											<div class="mt-1 flex items-center gap-3">
												<span class="w-6 text-[10px] uppercase tracking-wider text-[var(--text-tertiary)]">dns</span>
												{#if resolved}
													{#if resolved.error}
														<span class="text-[var(--text-tertiary)]">unresolvable</span>
													{:else}
														<code class="text-[var(--text-secondary)]">{resolved.ips[0]}</code>
														{#if resolved.is_local}
															<span class="rounded-full bg-[var(--blue)]/15 px-1.5 py-0.5 text-[10px] font-medium text-[var(--blue)]">local</span>
														{:else}
															<span class="rounded-full bg-[var(--green)]/15 px-1.5 py-0.5 text-[10px] font-medium text-[var(--green)]">external</span>
														{/if}
													{/if}
												{:else}
													<span class="inline-block h-3 w-16 animate-pulse rounded bg-[var(--bg3)]/40"></span>
												{/if}
											</div>
										</td>
										<td class="px-5 py-3">{h.namespace}</td>
										<td class="px-5 py-3">{h.name}</td>
										<td class="px-5 py-3">{h.cluster || h.cluster_id}</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>
				{/if}

				{#if chainDrawerOpen && chainDrawerRow}
					<div
						class="absolute inset-y-0 right-0 z-10 w-[780px] rounded-l-[10px] border-l border-[var(--border-color)] shadow-xl"
						in:fly={{ x: 780, duration: 240, easing: cubicOut, opacity: 1 }}
						out:fly={{ x: 780, duration: 200, easing: cubicIn, opacity: 1 }}
					>
						<HostChainDrawer
							host={chainDrawerRow.host}
							clusterId={chainDrawerRow.cluster_id}
							namespace={chainDrawerRow.namespace}
							kind={chainDrawerRow.kind}
							name={chainDrawerRow.name}
							onClose={() => { chainDrawerOpen = false; chainDrawerRow = null; }}
						/>
					</div>
				{/if}
			</section>
		{/if}
	{/if}
</div>

<style>
	.sortable-th {
		cursor: pointer;
		user-select: none;
		white-space: nowrap;
		transition: color 150ms ease;
	}

	.sortable-th:hover {
		color: var(--text-bright);
	}

	:global(.sort-icon) {
		display: inline-block;
		width: 12px;
		height: 12px;
		vertical-align: middle;
		visibility: hidden;
		transition: transform 150ms ease;
	}

	:global(.sort-icon.active) {
		visibility: visible;
	}

	:global(.sort-icon.flipped) {
		transform: rotate(180deg);
	}

	.host-filter-toggle {
		display: inline-flex;
		align-items: center;
		gap: 0.4rem;
		padding: 0.35rem 0.75rem;
		border-radius: 999px;
		border: 1px solid var(--border-color);
		background: transparent;
		color: var(--text-secondary);
		font-size: 0.75rem;
		font-weight: 500;
		cursor: pointer;
		transition: border-color 150ms ease, color 150ms ease, background 150ms ease;
		white-space: nowrap;
	}

	.host-filter-toggle:hover {
		color: var(--text-bright);
		border-color: var(--text-tertiary);
	}

	.host-filter-toggle.active {
		background: color-mix(in srgb, var(--accent) 12%, transparent);
		border-color: color-mix(in srgb, var(--accent) 40%, transparent);
		color: var(--accent);
	}

	.host-filter-badge {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 16px;
		height: 16px;
		border-radius: 999px;
		background: var(--accent);
		color: var(--bg-hard);
		font-size: 0.6rem;
		font-weight: 700;
		line-height: 1;
		padding: 0 0.25rem;
	}

	.host-search-input {
		height: 28px;
		width: 100%;
		min-width: 320px;
		border-radius: 999px;
		border: 1px solid var(--border-color);
		background: var(--card-bg);
		padding: 0 0.6rem 0 1.7rem;
		font-size: 0.75rem;
		color: var(--text-secondary);
		transition: border-color 150ms ease, box-shadow 150ms ease;
	}

	.host-search-input::placeholder {
		color: var(--text-muted);
	}

	.host-search-input:focus {
		outline: none;
		border-color: var(--accent);
		box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 30%, transparent);
	}

	.host-clear-filters {
		padding: 0.3rem 0.75rem;
		border-radius: 999px;
		border: 1px solid color-mix(in srgb, var(--accent) 50%, transparent);
		background: transparent;
		color: var(--accent);
		font-size: 0.75rem;
		font-weight: 500;
		cursor: pointer;
		transition: background 150ms ease, color 150ms ease, border-color 150ms ease;
	}

	.host-clear-filters:hover {
		background: color-mix(in srgb, var(--red) 14%, transparent);
		border-color: color-mix(in srgb, var(--red) 50%, transparent);
		color: var(--red);
	}

	.loading-bar {
		position: relative;
		width: 35%;
		animation: slide 2s linear infinite alternate;
	}

	@keyframes slide {
		0% {
			left: 0%;
			transform: translateX(-95%);
		}
		100% {
			left: 100%;
			transform: translateX(-5%);
		}
	}
</style>
