<script lang="ts">
	import { X, Server, ExternalLink } from 'lucide-svelte';
	import HostChainDiagram from './HostChainDiagram.svelte';
	import { nsChainToChainData, type ClusterChainData } from './chainLayout';

	let {
		cluster,
		clusterId,
		onClose = () => {}
	}: {
		cluster: string;
		clusterId: string;
		onClose?: () => void;
	} = $props();

	let data: ClusterChainData | null = $state(null);
	let loading = $state(true);
	let error = $state('');

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
				<div class="mt-0.5 flex flex-wrap items-center gap-x-3 gap-y-0.5">
					<p class="text-xs text-[var(--text-tertiary)]">
						{data ? `${data.namespaces.length} namespace${data.namespaces.length !== 1 ? 's' : ''}` : 'Loading...'}
					</p>
					<a
						href="/cluster/{encodeURIComponent(clusterId)}"
						class="inline-flex items-center gap-1 text-xs font-medium leading-none text-[var(--accent)] transition hover:underline"
					>
						Open cluster page <ExternalLink class="h-3 w-3" />
					</a>
				</div>
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
							<HostChainDiagram chain={nsChainToChainData(ns, data.cluster, data.cluster_id)} />
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
