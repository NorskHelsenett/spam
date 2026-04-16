<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { Server, Container } from 'lucide-svelte';

	type ClusterRow = {
		cluster: string;
		cluster_id: string;
		environment: string;
		containers: number;
		images: number;
		namespaces: number;
		last_seen: string;
	};

	type ImageRow = {
		cluster: string;
		cluster_id: string;
		environment: string;
		registry: string;
		image_count: number;
	};

	let clusters: ClusterRow[] = $state([]);
	let images: ImageRow[] = $state([]);
	let loading = $state(true);
	let error = $state('');

	const load = async () => {
		try {
			const [clusterRes, imageRes] = await Promise.all([
				fetch('/api/scam/clusters', { credentials: 'include' }),
				fetch('/api/scam/images', { credentials: 'include' })
			]);
			if (clusterRes.ok) clusters = await clusterRes.json();
			if (imageRes.ok) images = await imageRes.json();
		} catch {
			error = 'Failed to load cluster data';
		} finally {
			loading = false;
		}
	};

	onMount(() => {
		if (!browser) return;
		load();

		const es = new EventSource('/api/app/stream');
		es.addEventListener('scam_ingest', () => load());
		return () => es.close();
	});

	const totalImages = $derived(
		clusters.reduce((sum, c) => sum + c.images, 0)
	);
	const totalContainers = $derived(
		clusters.reduce((sum, c) => sum + c.containers, 0)
	);

	const timeAgo = (iso: string) => {
		if (!iso) return '';
		const diff = Date.now() - new Date(iso).getTime();
		const mins = Math.floor(diff / 60000);
		if (mins < 1) return 'just now';
		if (mins < 60) return `${mins}m ago`;
		const hours = Math.floor(mins / 60);
		if (hours < 24) return `${hours}h ago`;
		return `${Math.floor(hours / 24)}d ago`;
	};
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
			<div class="grid gap-4 sm:grid-cols-3">
				<article class="metric-card p-5 sm:p-6">
					<div class="flex items-center gap-2">
						<Server class="h-5 w-5 text-[var(--accent)]" />
						<h2 class="text-sm font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Clusters</h2>
					</div>
					<p class="mt-3 text-3xl font-bold text-[var(--text-bright)]">{clusters.length}</p>
					<p class="mt-1 text-xs text-[var(--text-muted)]">Reporting agents</p>
				</article>
				<article class="metric-card p-5 sm:p-6">
					<div class="flex items-center gap-2">
						<Container class="h-5 w-5 text-[var(--info)]" />
						<h2 class="text-sm font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Images</h2>
					</div>
					<p class="mt-3 text-3xl font-bold text-[var(--text-bright)]">{totalImages}</p>
					<p class="mt-1 text-xs text-[var(--text-muted)]">Unique across all clusters</p>
				</article>
				<article class="metric-card p-5 sm:p-6">
					<div class="flex items-center gap-2">
						<Container class="h-5 w-5 text-[var(--success)]" />
						<h2 class="text-sm font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Containers</h2>
					</div>
					<p class="mt-3 text-3xl font-bold text-[var(--text-bright)]">{totalContainers}</p>
					<p class="mt-1 text-xs text-[var(--text-muted)]">Running instances</p>
				</article>
			</div>

			<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
				<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
					<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
						<tr>
							<th class="px-5 py-3 text-left">Cluster</th>
							<th class="px-5 py-3 text-left">Environment</th>
							<th class="px-5 py-3 text-right">Images</th>
							<th class="px-5 py-3 text-right">Containers</th>
							<th class="px-5 py-3 text-right">Namespaces</th>
							<th class="px-5 py-3 text-left">Last seen</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
						{#each clusters as c}
							<tr class="transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]">
								<td class="px-5 py-3">
									<span class="font-semibold text-[var(--text-bright)]">{c.cluster || c.cluster_id}</span>
								</td>
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
								<td class="px-5 py-3 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">{timeAgo(c.last_seen)}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>

			{#if images.length > 0}
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">Images by registry</h2>
				<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
					<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
						<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
							<tr>
								<th class="px-5 py-3 text-left">Cluster</th>
								<th class="px-5 py-3 text-left">Registry</th>
								<th class="px-5 py-3 text-right">Images</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
							{#each images as row}
								<tr class="transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]">
									<td class="px-5 py-3 font-semibold text-[var(--text-bright)]">{row.cluster || row.cluster_id}</td>
									<td class="px-5 py-3">
										{#if row.registry}
											{row.registry}
										{:else}
											<span class="text-[var(--text-muted)]">Docker Hub</span>
										{/if}
									</td>
									<td class="px-5 py-3 text-right font-semibold">{row.image_count}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		{/if}
	</section>
</div>

<style>
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
