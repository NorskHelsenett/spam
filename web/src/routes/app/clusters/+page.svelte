<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { Server, Container, Globe, ChevronDown, ExternalLink } from 'lucide-svelte';
	import DonutChart from '$lib/components/DonutChart.svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';

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

	type Exposure = {
		internet_exposed: number;
		internal_services: number;
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
	let exposure: Exposure = $state({ internet_exposed: 0, internal_services: 0 });
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

	const palette = [
		'var(--accent)', 'var(--blue)', 'var(--green)',
		'var(--yellow)', 'var(--orange)', 'var(--purple)', 'var(--aqua)'
	];

	const loadMain = async () => {
		try {
			const [clusterRes, regRes, expRes] = await Promise.all([
				fetch('/api/clusters/summary', { credentials: 'include' }),
				fetch('/api/clusters/registry-distribution', { credentials: 'include' }),
				fetch('/api/clusters/exposure', { credentials: 'include' })
			]);
			if (clusterRes.ok) clusters = await clusterRes.json();
			if (regRes.ok) registryDist = await regRes.json();
			if (expRes.ok) exposure = await expRes.json();
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
		if (activeTab === 'hosts') loadHosts();
	});

	const totalImages = $derived(clusters.reduce((s, c) => s + c.images, 0));
	const totalContainers = $derived(clusters.reduce((s, c) => s + c.containers, 0));
	const totalExposed = $derived(clusters.reduce((s, c) => s + c.ingress_count, 0));

	const registrySegments = $derived(
		registryDist.map((r, i) => ({
			label: r.registry,
			value: r.image_count,
			color: palette[i % palette.length]
		}))
	);
	const registryTotal = $derived(registryDist.reduce((s, r) => s + r.image_count, 0));

	const exposureSegments = $derived([
		{ label: 'Internet', value: exposure.internet_exposed, color: 'var(--red)' },
		{ label: 'Internal', value: exposure.internal_services, color: 'var(--green)' }
	]);
	const exposureTotal = $derived(exposure.internet_exposed + exposure.internal_services);

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
		[...clusters].sort((a, b) => cmp(a[clusterSortKey], b[clusterSortKey], clusterSortDir))
	);

	const sortedImages = $derived(
		[...imageDetails].sort((a, b) => cmp(a[imageSortKey], b[imageSortKey], imageSortDir))
	);

	const sortedHosts = $derived(
		[...hosts].sort((a, b) => {
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
						<h2 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Exposed</h2>
					</div>
					<p class="mt-2 text-2xl font-bold text-[var(--text-bright)]">{totalExposed}</p>
					<p class="mt-1 text-xs text-[var(--text-muted)]">Internet-facing routes</p>
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
			<section class="panel-surface space-y-4 px-6 py-6 sm:px-10 sm:py-8">
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
								<tr class="transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]">
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
			<section class="panel-surface space-y-4 px-6 py-6 sm:px-10 sm:py-8">
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
									<tr class="transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]">
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
