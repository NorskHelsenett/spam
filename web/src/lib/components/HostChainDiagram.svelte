<script lang="ts">
	export type ChainIngress = {
		kind: string;
		name: string;
		namespace: string;
		ingress_class: string;
		tls: boolean;
		lb_ips: string;
		paths: { path?: string; backend_name?: string; backend_port?: string }[];
		backends?: string;
	};
	export type ChainService = {
		name: string;
		namespace: string;
		service_type: string;
		ports: { name?: string; port: number; target_port?: string; protocol?: string }[];
		selector: Record<string, string>;
		pod_count: number;
	};
	export type ChainPodGroup = {
		owner: string;
		owner_kind: string;
		pod_count: number;
		phase: string;
		containers: { name: string; image: string; tag: string; digest?: string; registry: string }[];
		service_name?: string;
		service_names?: string[];
	};
	export type ChainData = {
		host: string;
		cluster: string;
		cluster_id: string;
		namespace: string;
		ingress: ChainIngress | null;
		services: ChainService[];
		pods: ChainPodGroup[];
	};

	let { chain }: { chain: ChainData } = $props();

	const ICON_R = 18;
	const SMALL_R = 12;
	const COL_GAP = 110;
	const ROW_GAP = 52;
	const REPLICA_GAP = 32;
	const PAD = { top: 28, left: 70, right: 44, bottom: 28 };
	const LABEL_OFFSET = 28;
	const SUBLABEL_OFFSET = 42;
	const MAX_INDIVIDUAL_PODS = 4;

	function truncate(s: string, max: number): string {
		return s.length > max ? s.slice(0, max - 1) + '…' : s;
	}

	function arrow(x1: number, y1: number, x2: number, y2: number): string {
		const cx = (x1 + x2) / 2;
		return `M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}`;
	}

	// Get all service names a pod is connected to
	function podServices(pg: ChainPodGroup): string[] {
		if (pg.service_names?.length) return pg.service_names;
		if (pg.service_name) return [pg.service_name];
		return [];
	}

	// --- Deduplicate pods by owner ---
	let uniquePods = $derived.by(() => {
		const seen = new Map<string, ChainPodGroup>();
		for (const p of chain.pods ?? []) {
			const key = `${p.owner_kind}/${p.owner}`;
			const existing = seen.get(key);
			if (!existing) {
				seen.set(key, { ...p });
			} else {
				// Merge service_names
				const merged = new Set([...podServices(existing), ...podServices(p)]);
				existing.service_names = [...merged];
				if (p.pod_count > existing.pod_count) existing.pod_count = p.pod_count;
			}
		}
		return [...seen.values()];
	});

	// Has ingress?
	let hasIngress = $derived(!!chain.ingress);
	let hasServices = $derived((chain.services?.length ?? 0) > 0);

	// Column x positions — skip ingress column if no ingress
	let colPositions = $derived.by(() => {
		const cols: number[] = [];
		if (hasIngress) cols.push(PAD.left); // ingress
		if (hasServices) cols.push(PAD.left + (hasIngress ? COL_GAP : 0)); // services
		cols.push(PAD.left + (hasIngress ? COL_GAP : 0) + (hasServices ? COL_GAP : 0)); // pods
		return cols;
	});

	let ingressX = $derived(hasIngress ? colPositions[0] : -1);
	let serviceX = $derived(hasServices ? colPositions[hasIngress ? 1 : 0] : -1);
	let podX = $derived(colPositions[colPositions.length - 1]);

	// --- Compute individual pod nodes per group ---
	type PodNode = { x: number; y: number; pg: ChainPodGroup; isCollapsed: boolean; replicaIndex: number };
	type OwnerGroup = { owner: string; ownerKind: string; nodes: PodNode[]; y1: number; y2: number; pg: ChainPodGroup };

	let layout = $derived.by(() => {
		const services = chain.services ?? [];
		const pods = uniquePods;

		// Count pod nodes (individual up to MAX, then 1 collapsed node)
		let totalPodSlots = 0;
		const podSlots: number[] = [];
		for (const pg of pods) {
			const slots = pg.pod_count <= MAX_INDIVIDUAL_PODS ? Math.max(pg.pod_count, 1) : 1;
			podSlots.push(slots);
			totalPodSlots += slots;
		}

		const svcCount = Math.max(services.length, 0);
		const svcColHeight = svcCount > 0 ? svcCount * (ICON_R * 2) + (svcCount - 1) * ROW_GAP : 0;
		const podColHeight = totalPodSlots > 0 ? totalPodSlots * (SMALL_R * 2) + (totalPodSlots - 1) * REPLICA_GAP + (pods.length - 1) * (ROW_GAP - REPLICA_GAP) : 0;
		const maxColHeight = Math.max(svcColHeight, podColHeight, ICON_R * 2);
		const totalHeight = maxColHeight + PAD.top + PAD.bottom + SUBLABEL_OFFSET;
		const totalWidth = podX + ICON_R + PAD.right + 30;

		const ingressY = PAD.top + maxColHeight / 2;

		// Services
		const svcStartY = PAD.top + (maxColHeight - svcColHeight) / 2 + ICON_R;
		const svcPositions: { x: number; y: number; svc: ChainService }[] = [];
		for (let i = 0; i < services.length; i++) {
			svcPositions.push({ x: serviceX, y: svcStartY + i * (ICON_R * 2 + ROW_GAP), svc: services[i] });
		}

		// Pod groups with individual nodes
		const ownerGroups: OwnerGroup[] = [];
		let podNodeY = PAD.top + (maxColHeight - podColHeight) / 2 + SMALL_R;
		for (let gi = 0; gi < pods.length; gi++) {
			const pg = pods[gi];
			const nodes: PodNode[] = [];
			if (pg.pod_count <= MAX_INDIVIDUAL_PODS) {
				for (let ri = 0; ri < Math.max(pg.pod_count, 1); ri++) {
					nodes.push({ x: podX, y: podNodeY, pg, isCollapsed: false, replicaIndex: ri });
					podNodeY += SMALL_R * 2 + REPLICA_GAP;
				}
			} else {
				nodes.push({ x: podX, y: podNodeY, pg, isCollapsed: true, replicaIndex: 0 });
				podNodeY += SMALL_R * 2 + REPLICA_GAP;
			}
			const y1 = nodes[0].y - SMALL_R - 6;
			const y2 = nodes[nodes.length - 1].y + SMALL_R + SUBLABEL_OFFSET + 2;
			ownerGroups.push({ owner: pg.owner, ownerKind: pg.owner_kind, nodes, y1, y2, pg });
			if (gi < pods.length - 1) podNodeY += ROW_GAP - REPLICA_GAP;
		}

		// Build edges: service → pod
		type Edge = { sx: number; sy: number; px: number; py: number };
		const svcToPodEdges: Edge[] = [];
		for (const sp of svcPositions) {
			for (const og of ownerGroups) {
				const svcNames = podServices(og.pg);
				if (svcNames.includes(sp.svc.name)) {
					// Connect to center of the owner group
					const centerY = og.nodes.reduce((s, n) => s + n.y, 0) / og.nodes.length;
					svcToPodEdges.push({ sx: sp.x + ICON_R + 4, sy: sp.y, px: og.nodes[0].x - SMALL_R - 4, py: centerY });
				}
			}
		}

		// Ingress → service edges (only for services named as backends)
		const ingToSvcEdges: { sx: number; sy: number; tx: number; ty: number }[] = [];
		if (hasIngress && hasServices && chain.ingress) {
			const backendNames = new Set<string>();
			for (const p of chain.ingress.paths ?? []) {
				if (p.backend_name) backendNames.add(p.backend_name);
			}
			// Also check if ingress has a backends string (from cluster chain)
			if (chain.ingress.backends) {
				for (const b of chain.ingress.backends.split(', ')) {
					if (b) backendNames.add(b);
				}
			}
			for (const sp of svcPositions) {
				if (backendNames.has(sp.svc.name)) {
					ingToSvcEdges.push({ sx: ingressX + ICON_R + 4, sy: ingressY, tx: sp.x - ICON_R - 4, ty: sp.y });
				}
			}
		}

		return { totalWidth, totalHeight, ingressY, svcPositions, ownerGroups, svcToPodEdges, ingToSvcEdges };
	});

	// --- Popover ---
	type ContainerInfo = { name: string; image: string; tag: string; digest?: string; registry: string };
	type PopoverData = { type: string; title: string; lines: string[]; containers?: ContainerInfo[] };
	let popover: PopoverData | null = $state(null);

	function showIngress() {
		if (!chain.ingress) return;
		const ing = chain.ingress;
		popover = {
			type: 'ingress', title: ing.name,
			lines: [
				`Kind: ${ing.kind}`,
				ing.ingress_class ? `Class: ${ing.ingress_class}` : '',
				`TLS: ${ing.tls ? 'yes' : 'no'}`,
				ing.lb_ips ? `LB: ${ing.lb_ips}` : '',
				...(ing.paths ?? []).map(p => `${p.path ?? '/'} → ${p.backend_name}${p.backend_port ? ':' + p.backend_port : ''}`),
			].filter(Boolean)
		};
	}
	function showService(svc: ChainService) {
		popover = {
			type: 'service', title: svc.name,
			lines: [
				`Type: ${svc.service_type || 'ClusterIP'}`,
				...(svc.ports ?? []).map(p => `${p.port}${p.target_port ? ':' + p.target_port : ''}/${p.protocol || 'TCP'}`),
				...Object.entries(svc.selector ?? {}).map(([k, v]) => `${k}=${v}`),
			]
		};
	}
	function showPod(pg: ChainPodGroup) {
		popover = {
			type: 'pod', title: pg.owner,
			lines: [
				`${pg.owner_kind} · ${pg.pod_count} pod${pg.pod_count !== 1 ? 's' : ''} · ${pg.phase}`,
			],
			containers: pg.containers ?? []
		};
	}
	function hidePopover() { popover = null; }
</script>

<svg
	viewBox="0 0 {layout.totalWidth} {layout.totalHeight}"
	width={layout.totalWidth}
	height={layout.totalHeight}
	class="max-w-full"
	xmlns="http://www.w3.org/2000/svg"
>
	<defs>
		<marker id="arrowhead" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
			<polygon points="0 0, 8 3, 0 6" fill="var(--bg4)" />
		</marker>
	</defs>

	<!-- Ingress → Service arrows (only if ingress exists) -->
	{#each layout.ingToSvcEdges as e}
		<path d={arrow(e.sx, e.sy, e.tx, e.ty)} stroke="var(--bg4)" stroke-width="1.5" stroke-dasharray="6 4" fill="none" marker-end="url(#arrowhead)" opacity="0.6" />
	{/each}

	<!-- Service → Pod arrows -->
	{#each layout.svcToPodEdges as e}
		<path d={arrow(e.sx, e.sy, e.px, e.py)} stroke="var(--bg4)" stroke-width="1.5" stroke-dasharray="6 4" fill="none" marker-end="url(#arrowhead)" opacity="0.6" />
	{/each}

	<!-- Ingress node -->
	{#if chain.ingress && hasIngress}
		<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
		<g class="cursor-pointer" onclick={showIngress}>
			<circle cx={ingressX} cy={layout.ingressY} r={ICON_R} fill="var(--green)" opacity="0.15" stroke="var(--green)" stroke-width="1.5" />
			<g transform="translate({ingressX - 7}, {layout.ingressY - 7})">
				<circle cx="7" cy="7" r="6" fill="none" stroke="var(--green)" stroke-width="1.2" />
				<ellipse cx="7" cy="7" rx="3" ry="6" fill="none" stroke="var(--green)" stroke-width="0.8" />
				<line x1="1" y1="7" x2="13" y2="7" stroke="var(--green)" stroke-width="0.8" />
			</g>
			<text x={ingressX} y={layout.ingressY + LABEL_OFFSET} text-anchor="middle" fill="var(--fg1)" font-size="9" font-weight="600">{truncate(chain.host, 22)}</text>
			<text x={ingressX} y={layout.ingressY + SUBLABEL_OFFSET} text-anchor="middle" fill="var(--fg4)" font-size="8">
				{chain.ingress.kind}{chain.ingress.ingress_class ? ` · ${chain.ingress.ingress_class}` : ''}{chain.ingress.tls ? ' · TLS' : ''}
			</text>
		</g>
	{/if}

	<!-- Service nodes -->
	{#each layout.svcPositions as sp}
		<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
		<g class="cursor-pointer" onclick={() => showService(sp.svc)}>
			<circle cx={sp.x} cy={sp.y} r={ICON_R} fill="var(--blue)" opacity="0.15" stroke="var(--blue)" stroke-width="1.5" />
			<g transform="translate({sp.x - 7}, {sp.y - 7})">
				<rect x="1" y="1" width="12" height="12" rx="2.5" fill="none" stroke="var(--blue)" stroke-width="1.2" />
				<circle cx="7" cy="7" r="2" fill="var(--blue)" opacity="0.6" />
			</g>
			<text x={sp.x} y={sp.y + LABEL_OFFSET} text-anchor="middle" fill="var(--fg1)" font-size="9" font-weight="600">{truncate(sp.svc.name, 22)}</text>
			<text x={sp.x} y={sp.y + SUBLABEL_OFFSET} text-anchor="middle" fill="var(--fg4)" font-size="8">
				{sp.svc.service_type || 'ClusterIP'}{sp.svc.ports?.length ? ` · ${sp.svc.ports.map((p) => `${p.port}`).join(',')}` : ''}
			</text>
		</g>
	{/each}

	<!-- Pod owner groups -->
	{#each layout.ownerGroups as og}
		<!-- Grouping box when multiple nodes -->
		{#if og.nodes.length > 1}
			<rect
				x={og.nodes[0].x - SMALL_R - 10}
				y={og.y1}
				width={SMALL_R * 2 + 20}
				height={og.y2 - og.y1}
				rx="8"
				fill="var(--bg1)" opacity="0.3"
				stroke="var(--bg3)" stroke-width="0.5" stroke-dasharray="3 2"
			/>
		{/if}

		{#each og.nodes as node}
			<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
			<g class="cursor-pointer" onclick={() => showPod(node.pg)}>
				{#if node.pg.pod_count > 0}
					<circle cx={node.x} cy={node.y} r={SMALL_R} fill="var(--aqua)" opacity="0.15" stroke="var(--aqua)" stroke-width="1.2" />
					<g transform="translate({node.x - 5}, {node.y - 5})">
						<rect x="0" y="2" width="10" height="7" rx="1" fill="none" stroke="var(--aqua)" stroke-width="1" />
						<line x1="0" y1="5" x2="10" y2="5" stroke="var(--aqua)" stroke-width="0.7" />
					</g>
					{#if node.isCollapsed}
						<circle cx={node.x + SMALL_R - 2} cy={node.y - SMALL_R + 2} r="7" fill="var(--accent)" />
						<text x={node.x + SMALL_R - 2} y={node.y - SMALL_R + 5} text-anchor="middle" fill="var(--bg-hard)" font-size="8" font-weight="700">{node.pg.pod_count}</text>
					{/if}
				{:else}
					<circle cx={node.x} cy={node.y} r={SMALL_R} fill="var(--bg2)" opacity="0.3" stroke="var(--bg3)" stroke-width="1.2" stroke-dasharray="3 2" />
					<text x={node.x} y={node.y + 3} text-anchor="middle" fill="var(--fg4)" font-size="8">—</text>
				{/if}
			</g>
		{/each}

		<!-- Owner label below the group -->
		{@const lastNode = og.nodes[og.nodes.length - 1]}
		<text x={lastNode.x} y={lastNode.y + LABEL_OFFSET} text-anchor="middle" fill="var(--fg1)" font-size="9" font-weight="600">{truncate(og.owner, 22)}</text>
		<text x={lastNode.x} y={lastNode.y + SUBLABEL_OFFSET} text-anchor="middle" fill="var(--fg4)" font-size="8">
			{og.ownerKind}{og.pg.containers?.length ? ` · ${og.pg.containers.map((c) => c.image.split('/').pop()).join(', ').slice(0, 28)}` : ''}
		</text>
	{/each}

	<!-- Click-away on empty SVG area -->
	<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
	<rect x="0" y="0" width={layout.totalWidth} height={layout.totalHeight} fill="transparent" onclick={hidePopover} style="pointer-events: none;" />
</svg>

{#if popover}
	<div class="mt-2 rounded-lg border border-[var(--border-color)]/60 bg-[var(--bg)] px-4 py-3 text-xs shadow-lg">
		<div class="flex items-center justify-between">
			<span class="font-semibold text-[var(--text-bright)]">{popover.title}</span>
			<button class="text-[var(--text-muted)] hover:text-[var(--text-bright)]" onclick={hidePopover}>&times;</button>
		</div>
		<div class="mt-1.5 space-y-0.5">
			{#each popover.lines as line}
				<div class="whitespace-pre-wrap text-[var(--text-secondary)]">{line}</div>
			{/each}
		</div>
		{#if popover.containers?.length}
			<div class="mt-2 space-y-1.5">
				{#each popover.containers as c}
					{@const fullRef = `${c.registry ? c.registry + '/' : ''}${c.image}${c.digest ? '@' + c.digest : c.tag ? ':' + c.tag : ''}`}
					<div class="relative rounded bg-[var(--bg2)]/40 px-2.5 py-1.5">
						<button
							type="button"
							class="absolute right-2 top-1.5 rounded px-1.5 py-0.5 text-[10px] text-[var(--text-muted)] transition hover:bg-[var(--bg3)] hover:text-[var(--text-bright)]"
							title="Copy: docker pull {fullRef}"
							onclick={() => navigator.clipboard.writeText(`docker pull ${fullRef}`)}
						>
							<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
						</button>
						<div class="flex items-baseline gap-1">
							<span class="text-[var(--text-muted)]">image</span>
							<code class="text-[var(--text-bright)]">{c.registry ? c.registry + '/' : ''}{c.image}</code>
						</div>
						{#if c.tag}
							<div class="mt-0.5 flex items-baseline gap-1">
								<span class="text-[var(--text-muted)]">tag</span>
								<code class="text-[var(--green)]">{c.tag}</code>
							</div>
						{/if}
						{#if c.digest}
							<div class="mt-0.5 flex items-baseline gap-1">
								<span class="text-[var(--text-muted)]">digest</span>
								<code class="truncate text-[var(--text-tertiary)]">{c.digest}</code>
							</div>
						{/if}
					</div>
				{/each}
			</div>
		{/if}
	</div>
{/if}
