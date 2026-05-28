<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { page } from '$app/stores';
	import { ArrowLeft, Server, Container, Globe, Boxes, Clock } from 'lucide-svelte';
	import HostChainDiagram from '$lib/components/HostChainDiagram.svelte';
	import type { ChainData } from '$lib/components/HostChainDiagram.svelte';
	import Loading from '$lib/components/Loading.svelte';

	type ClusterRow = {
		cluster_id: string;
		// Env-var label from the SCAM agent (SPAM_CLUSTER). Absent when
		// the operator didn't set it.
		cluster_name?: string;
		// ROR binding, present when the cluster has resolved its ROR
		// identity. Absent for clusters not registered in ROR yet.
		ror_metadata?: {
			slug?: string;
			cluster_name?: string;
			env?: string;
		};
		environment: string;
		containers: number;
		images: number;
		namespaces: number;
		ingress_count: number;
		last_seen: string;
	};

	function displayClusterName(c: {
		cluster_id: string;
		cluster_name?: string;
		ror_metadata?: { slug?: string; cluster_name?: string };
	}): string {
		return c.ror_metadata?.cluster_name || c.cluster_name || c.ror_metadata?.slug || c.cluster_id;
	}

	type NsChain = {
		namespace: string;
		ingresses: { host: string; kind: string; name: string; ingress_class: string; tls: boolean; backends: string }[];
		services: { name: string; service_type: string; ports: any[]; selector: Record<string, string> }[];
		pods: { owner: string; owner_kind: string; pod_count: number; phase: string; containers: { name: string; image: string; tag: string; digest?: string; registry: string }[]; service_names?: string[]; transient?: boolean; last_seen?: string }[];
	};

	type ClusterChain = {
		cluster: string;
		cluster_id: string;
		namespaces: NsChain[];
	};

	let summary = $state<ClusterRow | null>(null);
	let chain = $state<ClusterChain | null>(null);
	let loading = $state(true);
	let error = $state('');

	// Convert a namespace slice into the ChainData shape HostChainDiagram
	// renders. Mirrors ClusterChainDrawer.toChainData so the visual is
	// consistent with the drawer.
	function toChainData(ns: NsChain, clusterName: string, clId: string): ChainData {
		return {
			host: ns.ingresses?.[0]?.host ?? '',
			cluster: clusterName,
			cluster_id: clId,
			namespace: ns.namespace,
			ingress: null,
			ingresses: (ns.ingresses ?? []).map(ing => ({
				kind: ing.kind,
				name: ing.name,
				namespace: ns.namespace,
				ingress_class: ing.ingress_class,
				tls: ing.tls,
				lb_ips: '',
				paths: [],
				backends: ing.backends,
				host: ing.host
			})),
			services: ns.services?.map(s => ({
				...s,
				namespace: ns.namespace,
				pod_count: 0
			})) ?? [],
			pods: ns.pods?.map(p => ({
				...p,
				service_names: p.service_names ?? [],
				transient: p.transient ?? false,
				last_seen: p.last_seen
			})) ?? []
		};
	}

	const load = async () => {
		const id = $page.params.id;
		if (!id) {
			error = 'No cluster id in URL';
			loading = false;
			return;
		}
		loading = true;
		error = '';
		try {
			// Summary: pull the cluster row out of the list endpoint
			// (?q= matches cluster_id via ILIKE, so a full UUID returns
			// at most one row). Falls back to a sparse stub if the row
			// is filtered out by ACL or liveness — we still want to
			// render the chain section if the user has chain access.
			const sumRes = await fetch(
				`/api/clusters/summary?q=${encodeURIComponent(id)}&include_inactive=true`,
				{ credentials: 'include' }
			);
			if (sumRes.ok) {
				const rows = (await sumRes.json()) as ClusterRow[];
				summary = rows.find((r) => r.cluster_id === id) ?? null;
			}
			const chainRes = await fetch(
				`/api/clusters/chain?cluster_id=${encodeURIComponent(id)}`,
				{ credentials: 'include' }
			);
			if (chainRes.ok) {
				chain = (await chainRes.json()) as ClusterChain;
			} else if (chainRes.status === 404) {
				error = 'Cluster not found';
			} else if (!summary) {
				error = 'Failed to load cluster data';
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load cluster data';
		} finally {
			loading = false;
		}
	};

	onMount(() => {
		if (browser) load();
	});

	const fmt = (n: number | null | undefined) => (n ?? 0).toLocaleString('en-US').replace(/,/g, ' ');

	const timeAgo = (iso: string | undefined) => {
		if (!iso) return '';
		const diff = Date.now() - new Date(iso).getTime();
		const mins = Math.floor(diff / 60000);
		if (mins < 1) return 'just now';
		if (mins < 60) return `${mins}m ago`;
		const hours = Math.floor(mins / 60);
		if (hours < 24) return `${hours}h ago`;
		return `${Math.floor(hours / 24)}d ago`;
	};

	const clusterName = $derived(
		(summary ? displayClusterName(summary) : null) || chain?.cluster || $page.params.id
	);
	const namespaceCount = $derived(chain?.namespaces?.length ?? summary?.namespaces ?? 0);
</script>

<svelte:head>
	<title>{clusterName} &middot; Spam Monitor</title>
</svelte:head>

<div class="space-y-6 sm:space-y-8">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
			<div class="min-w-0">
				<a
					href="/clusters"
					class="inline-flex items-center gap-1.5 text-xs text-[var(--text-muted)] transition-colors hover:text-[var(--text-secondary)]"
				>
					<ArrowLeft size={12} /> Clusters
				</a>
				<h1 class="mt-2 flex items-center gap-3 text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">
					<Server size={22} class="text-[var(--accent)]" />
					<span class="truncate">{clusterName}</span>
				</h1>
				{#if summary?.environment}
					<p class="mt-1 text-sm text-[var(--text-tertiary)]">Environment: <span class="text-[var(--text-secondary)]">{summary.environment}</span></p>
				{/if}
				<p class="mt-1 font-mono text-[10px] text-[var(--text-muted)]" title="cluster_id">{$page.params.id}</p>
			</div>
		</header>

		{#if loading}
			<Loading message="Loading cluster" variant="spinner" size="md" />
		{:else if error}
			<div class="flex flex-col items-center justify-center gap-2 py-12">
				<p class="text-base font-medium text-[var(--text-secondary)]">{error}</p>
				<a href="/clusters" class="mt-2 text-sm text-[var(--accent)] hover:underline">Back to clusters</a>
			</div>
		{:else}
			<div class="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-5">
				<div class="rounded-xl border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40 px-4 py-3">
					<div class="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
						<Container size={11} /> Containers
					</div>
					<p class="mt-1 text-xl font-semibold text-[var(--text-bright)]">{fmt(summary?.containers)}</p>
				</div>
				<div class="rounded-xl border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40 px-4 py-3">
					<div class="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
						<Boxes size={11} /> Images
					</div>
					<p class="mt-1 text-xl font-semibold text-[var(--text-bright)]">{fmt(summary?.images)}</p>
				</div>
				<div class="rounded-xl border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40 px-4 py-3">
					<div class="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
						<Server size={11} /> Namespaces
					</div>
					<p class="mt-1 text-xl font-semibold text-[var(--text-bright)]">{fmt(namespaceCount)}</p>
				</div>
				<div class="rounded-xl border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40 px-4 py-3">
					<div class="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
						<Globe size={11} /> Ingresses
					</div>
					<p class="mt-1 text-xl font-semibold text-[var(--text-bright)]">{fmt(summary?.ingress_count)}</p>
				</div>
				{#if summary?.last_seen}
					<div class="rounded-xl border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40 px-4 py-3">
						<div class="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
							<Clock size={11} /> Last seen
						</div>
						<p class="mt-1 text-sm font-medium text-[var(--text-secondary)]">{timeAgo(summary.last_seen)}</p>
					</div>
				{/if}
			</div>
		{/if}
	</section>

	{#if !loading && !error && chain}
		<section class="panel-surface px-4 py-6 sm:px-8 sm:py-8">
			<header class="mb-4 px-2">
				<h2 class="text-lg font-semibold text-[var(--text-bright)]">Namespaces</h2>
				<p class="mt-0.5 text-xs text-[var(--text-tertiary)]">Workloads grouped by namespace.</p>
			</header>

			{#if chain.namespaces.length === 0}
				<div class="flex flex-col items-center justify-center gap-2 py-12">
					<p class="text-sm text-[var(--text-tertiary)]">No workloads found for this cluster.</p>
				</div>
			{:else}
				{#each chain.namespaces as ns}
					<div class="mt-4 first:mt-0">
						<h3 class="mb-2 flex items-center gap-2 px-2 text-xs font-semibold uppercase tracking-[0.2em] text-[var(--text-muted)]">
							<span class="inline-block h-px flex-1 bg-[var(--border-color)]/40"></span>
							{ns.namespace}
							<span class="inline-block h-px flex-1 bg-[var(--border-color)]/40"></span>
						</h3>
						{#if ns.ingresses?.length || ns.services?.length || ns.pods?.length}
							<div class="overflow-x-auto rounded-xl border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40 p-3">
								<HostChainDiagram chain={toChainData(ns, chain.cluster, chain.cluster_id)} />
							</div>
						{/if}
					</div>
				{/each}
			{/if}
		</section>
	{/if}
</div>
