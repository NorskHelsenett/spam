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
		host?: string;
	};
	export type ChainService = {
		name: string;
		namespace: string;
		service_type: string;
		ports: { name?: string; port: number; target_port?: string; protocol?: string }[];
		selector: Record<string, string>;
		pod_count: number;
		endpoint_ips?: string[];
		endpoint_ports?: number[];
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
		ingresses?: ChainIngress[];
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
	const SUBLABEL_OFFSET = 40;
	const PORT_OFFSET = 51;
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

	// Collect all ingresses (single or multiple)
	let allIngresses = $derived.by(() => {
		if (chain.ingresses?.length) return chain.ingresses;
		if (chain.ingress) return [chain.ingress];
		return [];
	});
	let hasIngress = $derived(allIngresses.length > 0);
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
	type EndpointNode = { x: number; y: number; ip: string; svcName: string };

	let layout = $derived.by(() => {
		const services = chain.services ?? [];
		const pods = uniquePods;
		const POD_SLOT_H = SMALL_R * 2 + REPLICA_GAP;

		// --- Map pods to services ---
		// For each service, find which pod groups connect to it.
		// Each pod group is only placed once (under the first service that claims it).
		const svcToPods = new Map<string, ChainPodGroup[]>();
		const connectedPodKeys = new Set<string>();
		const placedPodKeys = new Set<string>(); // pods already assigned to a service row
		for (const svc of services) {
			const matched: ChainPodGroup[] = [];
			for (const pg of pods) {
				if (podServices(pg).includes(svc.name)) {
					connectedPodKeys.add(`${pg.owner_kind}/${pg.owner}`);
					// Only place pods in the first service row that claims them
					if (!placedPodKeys.has(`${pg.owner_kind}/${pg.owner}`)) {
						matched.push(pg);
						placedPodKeys.add(`${pg.owner_kind}/${pg.owner}`);
					}
				}
			}
			svcToPods.set(svc.name, matched);
		}
		// Orphan pods (not connected to any service)
		const orphanPods = pods.filter(pg => !connectedPodKeys.has(`${pg.owner_kind}/${pg.owner}`));

		// --- Count pod slots per service for height calculation ---
		function podSlotCount(pg: ChainPodGroup): number {
			return pg.pod_count <= MAX_INDIVIDUAL_PODS ? Math.max(pg.pod_count, 1) : 1;
		}

		// Each service row's height = max(service node height, its pod/endpoint group height)
		type SvcRow = { svc: ChainService; pods: ChainPodGroup[]; podSlots: number; rowH: number; hasEndpoints: boolean };
		const svcRows: SvcRow[] = [];
		for (const svc of services) {
			const matched = svcToPods.get(svc.name) ?? [];
			const hasEndpoints = matched.length === 0 && (svc.endpoint_ips?.length ?? 0) > 0;
			let slots = 0;
			for (const pg of matched) slots += podSlotCount(pg);
			if (hasEndpoints) slots = Math.min(svc.endpoint_ips!.length, MAX_INDIVIDUAL_PODS);
			const podH = slots > 0 ? slots * POD_SLOT_H - REPLICA_GAP : 0;
			const rowH = Math.max(ICON_R * 2 + SUBLABEL_OFFSET, podH + SUBLABEL_OFFSET);
			svcRows.push({ svc, pods: matched, podSlots: slots, rowH, hasEndpoints });
		}

		// Orphan pod rows
		type OrphanRow = { pg: ChainPodGroup; slots: number; rowH: number };
		const orphanRows: OrphanRow[] = orphanPods.map(pg => {
			const slots = podSlotCount(pg);
			return { pg, slots, rowH: slots * POD_SLOT_H - REPLICA_GAP + SUBLABEL_OFFSET };
		});

		// Total content height
		const svcTotalH = svcRows.reduce((s, r) => s + r.rowH, 0) + Math.max(svcRows.length - 1, 0) * ROW_GAP;
		const orphanTotalH = orphanRows.reduce((s, r) => s + r.rowH, 0) + Math.max(orphanRows.length - 1, 0) * ROW_GAP;
		const gapBetween = (svcRows.length > 0 && orphanRows.length > 0) ? ROW_GAP : 0;
		const contentH = svcTotalH + gapBetween + orphanTotalH;

		// --- Map ingresses to their backend services ---
		function ingressBackends(ing: ChainIngress): Set<string> {
			const names = new Set<string>();
			for (const p of ing.paths ?? []) { if (p.backend_name) names.add(p.backend_name); }
			if (ing.backends) { for (const b of ing.backends.split(', ')) { if (b) names.add(b); } }
			return names;
		}
		const svcToIngresses = new Map<string, ChainIngress[]>();
		const orphanIngresses: ChainIngress[] = [];
		for (const ing of allIngresses) {
			const backends = ingressBackends(ing);
			let matched = false;
			for (const svc of services) {
				if (backends.has(svc.name)) {
					const list = svcToIngresses.get(svc.name) ?? [];
					list.push(ing);
					svcToIngresses.set(svc.name, list);
					matched = true;
				}
			}
			if (!matched) orphanIngresses.push(ing);
		}

		const maxColHeight = Math.max(contentH, ICON_R * 2 + SUBLABEL_OFFSET);
		const totalHeight = maxColHeight + PAD.top + PAD.bottom;
		const totalWidth = podX + SMALL_R + PAD.right + 60;

		// --- Position services, pods, endpoints, and ingresses aligned by row ---
		type IngPos = { x: number; y: number; ing: ChainIngress };
		const ingPositions: IngPos[] = [];
		const svcPositions: { x: number; y: number; svc: ChainService }[] = [];
		const ownerGroups: OwnerGroup[] = [];
		const endpointNodes: EndpointNode[] = [];
		let curY = PAD.top + (maxColHeight - contentH) / 2;

		for (const row of svcRows) {
			const svcY = curY + row.rowH / 2;
			svcPositions.push({ x: serviceX, y: svcY, svc: row.svc });

			// Position ingresses aligned to this service
			const ings = svcToIngresses.get(row.svc.name) ?? [];
			if (ings.length === 1) {
				ingPositions.push({ x: ingressX, y: svcY, ing: ings[0] });
			} else if (ings.length > 1) {
				const ingH = ings.length * (ICON_R * 2) + (ings.length - 1) * 8;
				let iy = svcY - ingH / 2 + ICON_R;
				for (const ing of ings) {
					ingPositions.push({ x: ingressX, y: iy, ing });
					iy += ICON_R * 2 + 8;
				}
			}

			// Position pods or endpoint IPs centered on this service row
			if (row.hasEndpoints) {
				const EP_SLOT_H = ICON_R * 2 + ROW_GAP;
				const ips = row.svc.endpoint_ips ?? [];
				const epCount = Math.min(ips.length, MAX_INDIVIDUAL_PODS);
				let epY = curY + (row.rowH - (epCount * EP_SLOT_H - ROW_GAP)) / 2 + ICON_R;
				for (const ip of ips.slice(0, MAX_INDIVIDUAL_PODS)) {
					endpointNodes.push({ x: podX, y: epY, ip, svcName: row.svc.name });
					epY += EP_SLOT_H;
				}
			} else {
				let podY = curY + (row.rowH - (row.podSlots * POD_SLOT_H - (row.podSlots > 0 ? REPLICA_GAP : 0))) / 2 + SMALL_R;
				for (const pg of row.pods) {
					const nodes: PodNode[] = [];
					const slots = podSlotCount(pg);
					if (pg.pod_count <= MAX_INDIVIDUAL_PODS) {
						for (let ri = 0; ri < Math.max(pg.pod_count, 1); ri++) {
							nodes.push({ x: podX, y: podY, pg, isCollapsed: false, replicaIndex: ri });
							podY += POD_SLOT_H;
						}
					} else {
						nodes.push({ x: podX, y: podY, pg, isCollapsed: true, replicaIndex: 0 });
						podY += POD_SLOT_H;
					}
					const y1 = nodes[0].y - SMALL_R - 6;
					const y2 = nodes[nodes.length - 1].y + SMALL_R + SUBLABEL_OFFSET + 2;
					ownerGroups.push({ owner: pg.owner, ownerKind: pg.owner_kind, nodes, y1, y2, pg });
				}
			}
			curY += row.rowH + ROW_GAP;
		}

		// Orphan pods (no service)
		if (orphanRows.length > 0 && svcRows.length > 0) curY += gapBetween - ROW_GAP;
		for (const orow of orphanRows) {
			let podY = curY + SMALL_R;
			const nodes: PodNode[] = [];
			if (orow.pg.pod_count <= MAX_INDIVIDUAL_PODS) {
				for (let ri = 0; ri < Math.max(orow.pg.pod_count, 1); ri++) {
					nodes.push({ x: podX, y: podY, pg: orow.pg, isCollapsed: false, replicaIndex: ri });
					podY += POD_SLOT_H;
				}
			} else {
				nodes.push({ x: podX, y: podY, pg: orow.pg, isCollapsed: true, replicaIndex: 0 });
				podY += POD_SLOT_H;
			}
			const y1 = nodes[0].y - SMALL_R - 6;
			const y2 = nodes[nodes.length - 1].y + SMALL_R + SUBLABEL_OFFSET + 2;
			ownerGroups.push({ owner: orow.pg.owner, ownerKind: orow.pg.owner_kind, nodes, y1, y2, pg: orow.pg });
			curY += orow.rowH + ROW_GAP;
		}

		// Orphan ingresses (not connected to any service in this namespace)
		for (const ing of orphanIngresses) {
			ingPositions.push({ x: ingressX, y: curY + ICON_R, ing });
			curY += ICON_R * 2 + SUBLABEL_OFFSET + ROW_GAP;
		}

		// --- Build edges ---
		type Edge = { sx: number; sy: number; px: number; py: number };
		const svcToPodEdges: Edge[] = [];
		for (const sp of svcPositions) {
			for (const og of ownerGroups) {
				if (podServices(og.pg).includes(sp.svc.name)) {
					for (const node of og.nodes) {
						svcToPodEdges.push({ sx: sp.x + ICON_R + 4, sy: sp.y, px: node.x - SMALL_R - 4, py: node.y });
					}
				}
			}
			// Edges to endpoint IP nodes
			for (const ep of endpointNodes) {
				if (ep.svcName === sp.svc.name) {
					svcToPodEdges.push({ sx: sp.x + ICON_R + 4, sy: sp.y, px: ep.x - ICON_R - 4, py: ep.y });
				}
			}
		}

		const ingToSvcEdges: { sx: number; sy: number; tx: number; ty: number }[] = [];
		if (hasIngress && hasServices) {
			for (const ip of ingPositions) {
				const backendNames = new Set<string>();
				for (const p of ip.ing.paths ?? []) {
					if (p.backend_name) backendNames.add(p.backend_name);
				}
				if (ip.ing.backends) {
					for (const b of ip.ing.backends.split(', ')) {
						if (b) backendNames.add(b);
					}
				}
				for (const sp of svcPositions) {
					if (backendNames.has(sp.svc.name)) {
						ingToSvcEdges.push({ sx: ip.x + ICON_R + 4, sy: ip.y, tx: sp.x - ICON_R - 4, ty: sp.y });
					}
				}
			}
		}

		return { totalWidth, totalHeight, ingPositions, svcPositions, ownerGroups, endpointNodes, svcToPodEdges, ingToSvcEdges };
	});

	// --- Popover ---
	type ContainerInfo = { name: string; image: string; tag: string; digest?: string; registry: string };
	type PopoverData = { type: string; title: string; lines: string[]; containers?: ContainerInfo[] };
	let popover: PopoverData | null = $state(null);

	function showIngress(ing?: ChainIngress) {
		const target = ing ?? chain.ingress;
		if (!target) return;
		popover = {
			type: 'ingress', title: target.name,
			lines: [
				`Kind: ${target.kind}`,
				target.host ? `Host: ${target.host}` : '',
				target.ingress_class ? `Class: ${target.ingress_class}` : '',
				`TLS: ${target.tls ? 'yes' : 'no'}`,
				target.lb_ips ? `LB: ${target.lb_ips}` : '',
				target.backends ? `Backends: ${target.backends}` : '',
				...(target.paths ?? []).map(p => `${p.path ?? '/'} → ${p.backend_name}${p.backend_port ? ':' + p.backend_port : ''}`),
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

	<!-- Ingress nodes -->
	{#each layout.ingPositions as ip}
		<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
		<g class="cursor-pointer" onclick={() => showIngress(ip.ing)}>
			<circle cx={ip.x} cy={ip.y} r={ICON_R} fill="var(--green)" opacity="0.15" stroke="var(--green)" stroke-width="1.5" />
			<g transform="translate({ip.x - 7}, {ip.y - 7})">
				<circle cx="7" cy="7" r="6" fill="none" stroke="var(--green)" stroke-width="1.2" />
				<ellipse cx="7" cy="7" rx="3" ry="6" fill="none" stroke="var(--green)" stroke-width="0.8" />
				<line x1="1" y1="7" x2="13" y2="7" stroke="var(--green)" stroke-width="0.8" />
			</g>
			<text x={ip.x} y={ip.y + LABEL_OFFSET} text-anchor="middle" fill="var(--fg1)" font-size="9" font-weight="600">{truncate(ip.ing.host ?? ip.ing.name, 22)}</text>
			<text x={ip.x} y={ip.y + SUBLABEL_OFFSET} text-anchor="middle" fill="var(--fg4)" font-size="8">
				{ip.ing.kind}{ip.ing.ingress_class ? ` · ${ip.ing.ingress_class}` : ''}
			</text>
			{#if ip.ing.lb_ips}
				<text x={ip.x} y={ip.y + PORT_OFFSET} text-anchor="middle" fill="var(--fg4)" font-size="7">{ip.ing.lb_ips}</text>
			{/if}
		</g>
	{/each}

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
			<text x={sp.x} y={sp.y + SUBLABEL_OFFSET} text-anchor="middle" fill="var(--fg4)" font-size="8">{sp.svc.service_type || 'ClusterIP'}</text>
			{#if sp.svc.ports?.length}
				<text x={sp.x} y={sp.y + PORT_OFFSET} text-anchor="middle" fill="var(--fg4)" font-size="7">{sp.svc.ports.map((p) => `${p.port}/${p.protocol || 'TCP'}`).join(', ')}</text>
			{/if}
		</g>
	{/each}

	<!-- Pod owner groups -->
	{#each layout.ownerGroups as og}
		{@const imgLabel = og.pg.containers?.length ? og.pg.containers.map((c) => c.image.split('/').pop()).join(', ') : ''}

		{#each og.nodes as node, ni}
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
					<!-- Image name to the right of each pod -->
					<text x={node.x + SMALL_R + 6} y={node.y + 3} fill="var(--fg4)" font-size="7">{truncate(imgLabel, 24)}</text>
				{:else}
					<circle cx={node.x} cy={node.y} r={SMALL_R} fill="var(--bg2)" opacity="0.3" stroke="var(--bg3)" stroke-width="1.2" stroke-dasharray="3 2" />
					<text x={node.x} y={node.y + 3} text-anchor="middle" fill="var(--fg4)" font-size="8">—</text>
				{/if}
			</g>
		{/each}

		<!-- Owner label below the last node -->
		{@const lastNode = og.nodes[og.nodes.length - 1]}
		<text x={lastNode.x} y={lastNode.y + LABEL_OFFSET} text-anchor="middle" fill="var(--fg1)" font-size="9" font-weight="600">{truncate(og.owner, 22)}</text>
		<text x={lastNode.x} y={lastNode.y + SUBLABEL_OFFSET} text-anchor="middle" fill="var(--fg4)" font-size="8">{og.ownerKind}</text>
	{/each}

	<!-- Endpoint IP nodes (external services) -->
	{#each layout.endpointNodes as ep}
		{@const svc = chain.services?.find(s => s.name === ep.svcName)}
		{@const ports = svc?.endpoint_ports?.length ? svc.endpoint_ports : svc?.ports?.map(p => p.port) ?? []}
		<g>
			<circle cx={ep.x} cy={ep.y} r={ICON_R} fill="var(--orange)" opacity="0.15" stroke="var(--orange)" stroke-width="1.5" />
			<!-- Server icon -->
			<g transform="translate({ep.x - 7}, {ep.y - 7})">
				<rect x="1" y="0" width="12" height="14" rx="2" fill="none" stroke="var(--orange)" stroke-width="1.2" />
				<line x1="1" y1="5" x2="13" y2="5" stroke="var(--orange)" stroke-width="0.8" />
				<line x1="1" y1="9" x2="13" y2="9" stroke="var(--orange)" stroke-width="0.8" />
				<circle cx="10" cy="2.5" r="1" fill="var(--orange)" />
				<circle cx="10" cy="7" r="1" fill="var(--orange)" />
			</g>
			<text x={ep.x} y={ep.y + LABEL_OFFSET} text-anchor="middle" fill="var(--orange)" font-size="9" font-weight="600">{ep.ip}</text>
			<text x={ep.x} y={ep.y + SUBLABEL_OFFSET} text-anchor="middle" fill="var(--fg4)" font-size="8">external</text>
			{#if ports.length}
				<text x={ep.x} y={ep.y + PORT_OFFSET} text-anchor="middle" fill="var(--fg4)" font-size="7">{ports.join(', ')}</text>
			{/if}
		</g>
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
