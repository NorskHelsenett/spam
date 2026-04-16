<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { Server, Container, Globe, ChevronDown } from 'lucide-svelte';
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

	let clusters: ClusterRow[] = $state([]);
	let registryDist: RegistryDist[] = $state([]);
	let exposure: Exposure = $state({ internet_exposed: 0, internal_services: 0 });
	let imageDetails: ImageDetail[] = $state([]);
	let loading = $state(true);
	let error = $state('');
	let activeTab = $state('clusters');
	let imagesFetched = $state(false);
	let tick = $state(0);

	const palette = [
		'var(--accent)', 'var(--blue)', 'var(--green)',
		'var(--yellow)', 'var(--orange)', 'var(--purple)', 'var(--aqua)'
	];

	const loadMain = async () => {
		try {
			const [clusterRes, regRes, expRes] = await Promise.all([
				fetch('/api/scam/clusters', { credentials: 'include' }),
				fetch('/api/scam/registry-distribution', { credentials: 'include' }),
				fetch('/api/scam/exposure', { credentials: 'include' })
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
			const res = await fetch('/api/scam/images/detail', { credentials: 'include' });
			if (res.ok) imageDetails = await res.json();
			imagesFetched = true;
		} catch { /* silent */ }
	};

	onMount(() => {
		if (!browser) return;
		loadMain();

		const interval = setInterval(() => tick++, 60_000);

		const es = new EventSource('/api/app/stream');
		es.addEventListener('scam_ingest', () => {
			loadMain();
			if (imagesFetched) {
				imagesFetched = false;
				loadImages();
			}
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
	let clusterSortKey = $state<keyof ClusterRow>('last_seen');
	let clusterSortDir = $state<SortDir>('desc');
	let imageSortKey = $state<keyof ImageDetail>('container_count');
	let imageSortDir = $state<SortDir>('desc');

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

	const sortedClusters = $derived(
		[...clusters].sort((a, b) => cmp(a[clusterSortKey], b[clusterSortKey], clusterSortDir))
	);

	const sortedImages = $derived(
		[...imageDetails].sort((a, b) => cmp(a[imageSortKey], b[imageSortKey], imageSortDir))
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
				<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Waiting for first probe</p>
			</div>
		{:else if error}
			<div class="flex flex-col items-center justify-center py-24">
				<Server class="h-12 w-12 text-[var(--error)]" />
				<p class="mt-5 text-base font-medium text-[var(--text-secondary)]">{error}</p>
			</div>
		{:else if clusters.length === 0}
			<div class="flex flex-col items-center justify-center py-24">
				<Server class="h-12 w-12 text-[var(--text-muted)]" />
				<p class="mt-5 text-base font-medium text-[var(--text-secondary)]">No cluster data yet</p>
				<p class="mt-1 text-sm text-[var(--text-muted)]">Deploy a SCAM agent to start collecting container inventory.</p>
				<p class="mt-4 text-xs text-[var(--text-muted)]">Agents POST to <code class="rounded bg-[var(--hover-bg)] px-1.5 py-0.5">/api/scam/callcenter</code></p>
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
					{ value: 'images', label: 'Images' }
				]}
			/>
		{/if}
	</section>

	<!-- Tables -->
	{#if !loading && !error && clusters.length > 0}
		{#if activeTab === 'clusters'}
			<section class="panel-surface space-y-4 px-6 py-6 sm:px-10 sm:py-8">
				<div class="overflow-x-auto">
					<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
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
						<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
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
		{:else}
			<section class="panel-surface space-y-4 px-6 py-6 sm:px-10 sm:py-8">
				{#if imageDetails.length === 0}
					<div class="flex flex-col items-center justify-center gap-5 py-12">
						<Container class="h-10 w-10 text-[var(--text-muted)]" />
						<p class="text-sm text-[var(--text-secondary)]">No image data with resolved digests yet.</p>
					</div>
				{:else}
					<div class="overflow-x-auto">
					<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
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
							<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
								{#each sortedImages as img}
									<tr class="transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]">
										<td class="px-5 py-3 text-xs text-[var(--text-tertiary)]">{img.registry}</td>
										<td class="px-5 py-3 font-semibold text-[var(--text-bright)]">{img.image}</td>
										<td class="px-5 py-3">
											<code class="rounded bg-[var(--hover-bg)] px-1.5 py-0.5 text-xs text-[var(--text-secondary)]">{shortDigest(img.digest)}</code>
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
