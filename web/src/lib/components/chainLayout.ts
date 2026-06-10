// Shared data model + geometry for the exposure-chain diagrams.
// computeChainLayout turns one namespace's ChainData (ingresses → services
// → pods) into node positions and edges. HostChainDiagram renders a single
// chain per SVG (host/cluster drawers); ClusterMap stacks every namespace's
// layout into one pannable, zoomable SVG on the cluster detail page.

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
	// Transient groups aren't currently running but were observed in the
	// last 24h (completed Jobs, CronJob-spawned pods, Failed replicas).
	// The diagram styles their nodes muted to keep the eye on live work.
	transient?: boolean;
	last_seen?: string;
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

// Per-namespace slice of the /api/clusters/chain payload.
export type NsChain = {
	namespace: string;
	ingresses: {
		host: string;
		kind: string;
		name: string;
		ingress_class: string;
		tls: boolean;
		backends: string;
	}[];
	services: {
		name: string;
		service_type: string;
		ports: { name?: string; port: number; target_port?: string; protocol?: string }[];
		selector: Record<string, string>;
	}[];
	pods: {
		owner: string;
		owner_kind: string;
		pod_count: number;
		phase: string;
		containers: { name: string; image: string; tag: string; digest?: string; registry: string }[];
		service_names?: string[];
		transient?: boolean;
		last_seen?: string;
	}[];
};

export type ClusterChainData = {
	cluster: string;
	cluster_id: string;
	namespaces: NsChain[];
};

// Convert a NsChain into a ChainData for the diagram layout.
export function nsChainToChainData(ns: NsChain, clusterName: string, clId: string): ChainData {
	return {
		host: ns.ingresses?.[0]?.host ?? '',
		cluster: clusterName,
		cluster_id: clId,
		namespace: ns.namespace,
		ingress: null,
		ingresses: (ns.ingresses ?? []).map((ing) => ({
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
		services:
			ns.services?.map((s) => ({
				...s,
				namespace: ns.namespace,
				pod_count: 0
			})) ?? [],
		pods:
			ns.pods?.map((p) => ({
				...p,
				service_names: p.service_names ?? [],
				transient: p.transient ?? false,
				last_seen: p.last_seen
			})) ?? []
	};
}

export const ICON_R = 18;
export const SMALL_R = 12;
const COL_GAP = 110;
const ROW_GAP = 52;
const REPLICA_GAP = 32;
const PAD = { top: 28, left: 70, right: 44, bottom: 28 };
export const LABEL_OFFSET = 28;
export const SUBLABEL_OFFSET = 40;
export const PORT_OFFSET = 51;
// Replica display: show up to this many individual pod nodes per owner
// group; beyond that collapse to a single node with a counter badge.
const MAX_INDIVIDUAL_PODS = 3;

export function truncate(s: string, max: number): string {
	return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

export function arrow(x1: number, y1: number, x2: number, y2: number): string {
	const cx = (x1 + x2) / 2;
	return `M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}`;
}

// Get all service names a pod is connected to
export function podServices(pg: ChainPodGroup): string[] {
	if (pg.service_names?.length) return pg.service_names;
	if (pg.service_name) return [pg.service_name];
	return [];
}

// containerSignature produces a stable key from a pod group's
// container set — same images = same signature. Used to collapse
// CronJob-spawned Jobs: each firing has a unique owner name but
// identical containers, so they render as one node with a counter
// instead of 50 visually identical rows.
function containerSignature(pg: ChainPodGroup): string {
	const parts = (pg.containers ?? [])
		.map((c) => `${c.registry ?? ''}/${c.image ?? ''}:${c.tag ?? ''}@${c.digest ?? ''}`)
		.sort();
	return parts.join('|');
}

// Deduplicate pods by owner (Jobs collapse by container signature).
function dedupePods(pods: ChainPodGroup[]): ChainPodGroup[] {
	const seen = new Map<string, ChainPodGroup>();
	for (const p of pods) {
		const key =
			p.owner_kind === 'Job' ? `Job/${containerSignature(p)}` : `${p.owner_kind}/${p.owner}`;
		const existing = seen.get(key);
		if (!existing) {
			seen.set(key, { ...p });
		} else {
			// Merge service_names
			const merged = new Set([...podServices(existing), ...podServices(p)]);
			existing.service_names = [...merged];
			// Sum pod_count across merged Job firings so the counter
			// badge reflects total Job pods, not just the biggest firing.
			if (existing.owner_kind === 'Job') {
				existing.pod_count += p.pod_count;
				existing.owner = existing.owner.replace(/-[0-9a-f]+$/i, '-*');
			} else if (p.pod_count > existing.pod_count) {
				existing.pod_count = p.pod_count;
			}
		}
	}
	return [...seen.values()];
}

export type PodNode = {
	x: number;
	y: number;
	pg: ChainPodGroup;
	isCollapsed: boolean;
	replicaIndex: number;
};
export type OwnerGroup = {
	owner: string;
	ownerKind: string;
	nodes: PodNode[];
	y1: number;
	y2: number;
	pg: ChainPodGroup;
};
export type EndpointNode = { x: number; y: number; ip: string; svcName: string };
export type IngPosition = { x: number; y: number; ing: ChainIngress };
export type SvcPosition = { x: number; y: number; svc: ChainService };
export type SvcPodEdge = { sx: number; sy: number; px: number; py: number };
export type IngSvcEdge = { sx: number; sy: number; tx: number; ty: number };

export type ChainLayout = {
	totalWidth: number;
	totalHeight: number;
	ingPositions: IngPosition[];
	svcPositions: SvcPosition[];
	ownerGroups: OwnerGroup[];
	endpointNodes: EndpointNode[];
	svcToPodEdges: SvcPodEdge[];
	ingToSvcEdges: IngSvcEdge[];
};

export function computeChainLayout(chain: ChainData): ChainLayout {
	// Collect all ingresses (single or multiple)
	const allIngresses = chain.ingresses?.length
		? chain.ingresses
		: chain.ingress
			? [chain.ingress]
			: [];
	const hasIngress = allIngresses.length > 0;
	const hasServices = (chain.services?.length ?? 0) > 0;

	// Column x positions — skip ingress column if no ingress
	const ingressX = hasIngress ? PAD.left : -1;
	const serviceX = hasServices ? PAD.left + (hasIngress ? COL_GAP : 0) : -1;
	const podX = PAD.left + (hasIngress ? COL_GAP : 0) + (hasServices ? COL_GAP : 0);

	const services = chain.services ?? [];
	const pods = dedupePods(chain.pods ?? []);
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
	const orphanPods = pods.filter((pg) => !connectedPodKeys.has(`${pg.owner_kind}/${pg.owner}`));

	// --- Count pod slots per service for height calculation ---
	function podSlotCount(pg: ChainPodGroup): number {
		return pg.pod_count <= MAX_INDIVIDUAL_PODS ? Math.max(pg.pod_count, 1) : 1;
	}

	// Each service row's height = max(service node height, its pod/endpoint group height)
	type SvcRow = {
		svc: ChainService;
		pods: ChainPodGroup[];
		podSlots: number;
		rowH: number;
		hasEndpoints: boolean;
	};
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
	const orphanRows: OrphanRow[] = orphanPods.map((pg) => {
		const slots = podSlotCount(pg);
		return { pg, slots, rowH: slots * POD_SLOT_H - REPLICA_GAP + SUBLABEL_OFFSET };
	});

	// Total content height
	const svcTotalH =
		svcRows.reduce((s, r) => s + r.rowH, 0) + Math.max(svcRows.length - 1, 0) * ROW_GAP;
	const orphanTotalH =
		orphanRows.reduce((s, r) => s + r.rowH, 0) + Math.max(orphanRows.length - 1, 0) * ROW_GAP;
	const gapBetween = svcRows.length > 0 && orphanRows.length > 0 ? ROW_GAP : 0;
	const contentH = svcTotalH + gapBetween + orphanTotalH;

	// --- Map ingresses to their backend services ---
	function ingressBackends(ing: ChainIngress): Set<string> {
		const names = new Set<string>();
		for (const p of ing.paths ?? []) {
			if (p.backend_name) names.add(p.backend_name);
		}
		if (ing.backends) {
			for (const b of ing.backends.split(', ')) {
				if (b) names.add(b);
			}
		}
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
	const ingPositions: IngPosition[] = [];
	const svcPositions: SvcPosition[] = [];
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
			let podY =
				curY +
				(row.rowH - (row.podSlots * POD_SLOT_H - (row.podSlots > 0 ? REPLICA_GAP : 0))) / 2 +
				SMALL_R;
			for (const pg of row.pods) {
				const nodes: PodNode[] = [];
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
	const svcToPodEdges: SvcPodEdge[] = [];
	for (const sp of svcPositions) {
		for (const og of ownerGroups) {
			if (podServices(og.pg).includes(sp.svc.name)) {
				for (const node of og.nodes) {
					svcToPodEdges.push({
						sx: sp.x + ICON_R + 4,
						sy: sp.y,
						px: node.x - SMALL_R - 4,
						py: node.y
					});
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

	const ingToSvcEdges: IngSvcEdge[] = [];
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

	return {
		totalWidth,
		totalHeight,
		ingPositions,
		svcPositions,
		ownerGroups,
		endpointNodes,
		svcToPodEdges,
		ingToSvcEdges
	};
}

// --- Popover content builders (shared by diagram + map) ---
export type PopoverContainer = {
	name: string;
	image: string;
	tag: string;
	digest?: string;
	registry: string;
};
export type PopoverData = {
	type: string;
	title: string;
	lines: string[];
	containers?: PopoverContainer[];
};

export function ingressPopover(ing: ChainIngress): PopoverData {
	return {
		type: 'ingress',
		title: ing.name,
		lines: [
			`Kind: ${ing.kind}`,
			ing.host ? `Host: ${ing.host}` : '',
			ing.ingress_class ? `Class: ${ing.ingress_class}` : '',
			`TLS: ${ing.tls ? 'yes' : 'no'}`,
			ing.lb_ips ? `LB: ${ing.lb_ips}` : '',
			ing.backends ? `Backends: ${ing.backends}` : '',
			...(ing.paths ?? []).map(
				(p) => `${p.path ?? '/'} → ${p.backend_name}${p.backend_port ? ':' + p.backend_port : ''}`
			)
		].filter(Boolean)
	};
}

export function servicePopover(svc: ChainService): PopoverData {
	return {
		type: 'service',
		title: svc.name,
		lines: [
			`Type: ${svc.service_type || 'ClusterIP'}`,
			...(svc.ports ?? []).map(
				(p) => `${p.port}${p.target_port ? ':' + p.target_port : ''}/${p.protocol || 'TCP'}`
			),
			...Object.entries(svc.selector ?? {}).map(([k, v]) => `${k}=${v}`)
		]
	};
}

export function podPopover(pg: ChainPodGroup): PopoverData {
	return {
		type: 'pod',
		title: pg.owner,
		lines: [`${pg.owner_kind} · ${pg.pod_count} pod${pg.pod_count !== 1 ? 's' : ''} · ${pg.phase}`],
		containers: pg.containers ?? []
	};
}
