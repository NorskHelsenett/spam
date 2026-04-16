<script lang="ts">
	import { X, Globe } from 'lucide-svelte';
	import HostChainDiagram from './HostChainDiagram.svelte';
	import type { ChainData } from './HostChainDiagram.svelte';

	let {
		host,
		clusterId,
		namespace,
		kind,
		name,
		onClose = () => {}
	}: {
		host: string;
		clusterId: string;
		namespace: string;
		kind: string;
		name: string;
		onClose?: () => void;
	} = $props();

	let chain: ChainData | null = $state(null);
	let loading = $state(true);
	let error = $state('');

	$effect(() => {
		if (!host || !clusterId || !namespace) return;
		loading = true;
		error = '';
		chain = null;

		const params = new URLSearchParams({ host, cluster_id: clusterId, namespace });
		fetch(`/api/clusters/hosts/chain?${params}`, { credentials: 'include' })
			.then((r) => {
				if (!r.ok) throw new Error(`${r.status}`);
				return r.json();
			})
			.then((data) => {
				chain = data;
			})
			.catch((e) => {
				error = e.message || 'Failed to load';
			})
			.finally(() => {
				loading = false;
			});
	});
</script>

<div class="flex h-full flex-col overflow-hidden rounded-l-[10px] bg-[var(--bg-soft)]">
	<!-- Header -->
	<div class="shrink-0 pb-2 pl-7 pr-7 pt-7">
		<div class="flex items-start gap-3">
			<Globe class="mt-0.5 h-5 w-5 shrink-0 text-[var(--green)]" />
			<div class="min-w-0 flex-1">
				<h3 class="truncate text-base font-semibold text-[var(--text-bright)]">{host}</h3>
				<p class="mt-0.5 text-xs text-[var(--text-tertiary)]">
					{kind} <span class="text-[var(--text-muted)]">·</span> {name}
					<span class="text-[var(--text-muted)]">·</span> {namespace}
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
				Failed to load chain data
			</div>
		{:else if chain}
			<div class="mt-2">
				<h4 class="mb-3 text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Exposure chain</h4>
				<div class="rounded-xl border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40 p-4">
					<HostChainDiagram {chain} />
				</div>
			</div>

			<!-- Details below the diagram -->
			{#if chain.services?.length}
				<div class="mt-5">
					<h4 class="mb-2 text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Services</h4>
					{#each chain.services as svc}
						<div class="mb-2 rounded-lg border border-[var(--border-color)]/30 bg-[var(--bg1)]/30 px-4 py-3">
							<div class="flex items-center gap-2">
								<span class="font-semibold text-[var(--text-bright)]">{svc.name}</span>
								<span class="rounded-full bg-[var(--blue)]/15 px-1.5 py-0.5 text-[10px] font-medium text-[var(--blue)]">{svc.service_type || 'ClusterIP'}</span>
							</div>
							{#if svc.ports?.length}
								<div class="mt-1 text-xs text-[var(--text-tertiary)]">
									{svc.ports.map((p) => `${p.port}${p.target_port ? ':' + p.target_port : ''}/${p.protocol || 'TCP'}`).join(', ')}
								</div>
							{/if}
							{#if svc.selector && Object.keys(svc.selector).length}
								<div class="mt-1 flex flex-wrap gap-1">
									{#each Object.entries(svc.selector) as [k, v]}
										<span class="rounded bg-[var(--bg2)]/60 px-1.5 py-0.5 text-[10px] text-[var(--fg4)]">{k}={v}</span>
									{/each}
								</div>
							{/if}
						</div>
					{/each}
				</div>
			{/if}

			{#if chain.pods?.length}
				<div class="mt-4">
					<h4 class="mb-2 text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Workloads</h4>
					{#each chain.pods as pg}
						<div class="mb-2 rounded-lg border border-[var(--border-color)]/30 bg-[var(--bg1)]/30 px-4 py-3">
							<div class="flex items-center gap-2">
								<span class="font-semibold text-[var(--text-bright)]">{pg.owner}</span>
								<span class="rounded-full bg-[var(--aqua)]/15 px-1.5 py-0.5 text-[10px] font-medium text-[var(--aqua)]">{pg.owner_kind}</span>
								<span class="text-xs text-[var(--text-tertiary)]">{pg.pod_count} pod{pg.pod_count !== 1 ? 's' : ''}</span>
							</div>
							{#if pg.containers?.length}
								<div class="mt-1.5 space-y-0.5">
									{#each pg.containers as c}
										<div class="flex items-center gap-1.5 text-xs">
											<code class="text-[var(--text-secondary)]">{c.image}{c.tag ? ':' + c.tag : ''}</code>
											{#if c.registry}
												<span class="text-[var(--text-muted)]">{c.registry}</span>
											{/if}
										</div>
									{/each}
								</div>
							{/if}
						</div>
					{/each}
				</div>
			{/if}
		{:else}
			<div class="flex h-48 items-center justify-center text-sm text-[var(--text-tertiary)]">
				No chain data available
			</div>
		{/if}
	</div>
</div>
