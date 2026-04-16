<script lang="ts">
	import { X, Server } from 'lucide-svelte';
	import HostChainDiagram from './HostChainDiagram.svelte';
	import type { ChainData } from './HostChainDiagram.svelte';

	let {
		cluster,
		clusterId,
		onClose = () => {}
	}: {
		cluster: string;
		clusterId: string;
		onClose?: () => void;
	} = $props();

	type NsChain = {
		namespace: string;
		ingresses: { host: string; kind: string; name: string; ingress_class: string; tls: boolean; backends: string }[];
		services: { name: string; service_type: string; ports: any[]; selector: Record<string, string> }[];
		pods: { owner: string; owner_kind: string; pod_count: number; phase: string; containers: { name: string; image: string; tag: string; digest?: string; registry: string }[]; service_names?: string[] }[];
	};

	type ClusterChainData = {
		cluster: string;
		cluster_id: string;
		namespaces: NsChain[];
	};

	let data: ClusterChainData | null = $state(null);
	let loading = $state(true);
	let error = $state('');

	// Convert a NsChain into a ChainData for the diagram component
	function toChainData(ns: NsChain, clusterName: string, clId: string): ChainData {
		// Pick first ingress as the primary (diagram shows one ingress node)
		const ing = ns.ingresses?.[0];
		return {
			host: ing?.host ?? '',
			cluster: clusterName,
			cluster_id: clId,
			namespace: ns.namespace,
			ingress: ing ? {
				kind: ing.kind,
				name: ing.name,
				namespace: ns.namespace,
				ingress_class: ing.ingress_class,
				tls: ing.tls,
				lb_ips: '',
				paths: [],
				backends: ing.backends
			} : null,
			services: ns.services?.map(s => ({
				...s,
				namespace: ns.namespace,
				pod_count: 0
			})) ?? [],
			pods: ns.pods?.map(p => ({
				...p,
				service_names: p.service_names ?? []
			})) ?? []
		};
	}

	$effect(() => {
		if (!clusterId) return;
		loading = true;
		error = '';
		data = null;

		fetch(`/api/clusters/chain?cluster_id=${encodeURIComponent(clusterId)}`, { credentials: 'include' })
			.then(r => { if (!r.ok) throw new Error(`${r.status}`); return r.json(); })
			.then(d => { data = d; })
			.catch(e => { error = e.message || 'Failed to load'; })
			.finally(() => { loading = false; });
	});
</script>

<div class="flex h-full flex-col overflow-hidden rounded-l-[10px] bg-[var(--bg-soft)]">
	<!-- Header -->
	<div class="shrink-0 pb-2 pl-7 pr-7 pt-7">
		<div class="flex items-start gap-3">
			<Server class="mt-0.5 h-5 w-5 shrink-0 text-[var(--accent)]" />
			<div class="min-w-0 flex-1">
				<h3 class="truncate text-base font-semibold text-[var(--text-bright)]">{cluster || clusterId}</h3>
				<p class="mt-0.5 text-xs text-[var(--text-tertiary)]">
					{data ? `${data.namespaces.length} namespace${data.namespaces.length !== 1 ? 's' : ''}` : 'Loading...'}
				</p>
			</div>
			<button
				type="button"
				class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition hover:bg-[var(--hover-bg)]"
				onclick={onClose}
				aria-label="Close"
			>
				<X size={18} stroke-width={2} />
			</button>
		</div>
	</div>

	<!-- Body -->
	<div class="flex-1 overflow-y-auto bg-[var(--bg-soft)] px-4 pb-6">
		{#if loading}
			<div class="flex h-48 items-center justify-center">
				<div class="h-5 w-5 animate-spin rounded-full border-2 border-[var(--border-color)] border-t-[var(--accent)]"></div>
			</div>
		{:else if error}
			<div class="flex h-48 items-center justify-center text-sm text-[var(--text-tertiary)]">
				Failed to load cluster data
			</div>
		{:else if data?.namespaces?.length}
			{#each data.namespaces as ns}
				<div class="mt-4">
					<h4 class="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.2em] text-[var(--text-muted)]">
						<span class="inline-block h-px flex-1 bg-[var(--border-color)]/40"></span>
						{ns.namespace}
						<span class="inline-block h-px flex-1 bg-[var(--border-color)]/40"></span>
					</h4>

					{#if ns.ingresses?.length || ns.services?.length || ns.pods?.length}
						<div class="overflow-x-auto rounded-xl border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40 p-3">
							<HostChainDiagram chain={toChainData(ns, data.cluster, data.cluster_id)} />
						</div>
					{/if}
				</div>
			{/each}
		{:else}
			<div class="flex h-48 items-center justify-center text-sm text-[var(--text-tertiary)]">
				No data available
			</div>
		{/if}
	</div>
</div>
