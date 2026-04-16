<script lang="ts">
	export type ChainIngress = {
		kind: string;
		name: string;
		namespace: string;
		ingress_class: string;
		tls: boolean;
		lb_ips: string;
		paths: { path?: string; backend_name?: string; backend_port?: string }[];
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
		service_name: string;
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

	// --- Layout constants ---
	const ICON_R = 18;
	const COL_GAP = 110;
	const ROW_GAP = 62;
	const PAD = { top: 28, left: 70, right: 44, bottom: 28 };
	const LABEL_OFFSET = 28;
	const SUBLABEL_OFFSET = 42;

	// --- Build service → pod group map ---
	let svcPodMap = $derived.by(() => {
		const m = new Map<string, ChainPodGroup[]>();
		for (const p of chain.pods ?? []) {
			const list = m.get(p.service_name) ?? [];
			list.push(p);
			m.set(p.service_name, list);
		}
		return m;
	});

	// --- Column x positions ---
	const col0x = PAD.left;
	const col1x = PAD.left + COL_GAP;
	const col2x = PAD.left + 2 * COL_GAP;

	// --- Compute node positions ---
	let layout = $derived.by(() => {
		const services = chain.services ?? [];
		// Count total pod groups across all services for height calculation
		let totalPodNodes = 0;
		const svcPodCounts: number[] = [];
		for (const s of services) {
			const pods = svcPodMap.get(s.name) ?? [];
			const count = Math.max(pods.length, 1); // at least 1 placeholder
			svcPodCounts.push(count);
			totalPodNodes += count;
		}

		// Services column height
		const svcCount = Math.max(services.length, 1);
		const svcColHeight = svcCount * (ICON_R * 2) + (svcCount - 1) * ROW_GAP;

		// Pod column height (may be taller if many pod groups)
		const podColHeight = totalPodNodes * (ICON_R * 2) + Math.max(totalPodNodes - 1, 0) * ROW_GAP;

		const maxColHeight = Math.max(svcColHeight, podColHeight, ICON_R * 2);
		const totalHeight = maxColHeight + PAD.top + PAD.bottom;
		const totalWidth = col2x + PAD.right;

		// Ingress: single node, centered vertically
		const ingressY = PAD.top + maxColHeight / 2;

		// Services: stacked vertically, centered
		const svcStartY = PAD.top + (maxColHeight - svcColHeight) / 2 + ICON_R;
		const svcPositions: { x: number; y: number; svc: ChainService }[] = [];
		for (let i = 0; i < services.length; i++) {
			svcPositions.push({
				x: col1x,
				y: svcStartY + i * (ICON_R * 2 + ROW_GAP),
				svc: services[i],
			});
		}

		// Pods: grouped by their parent service
		const podPositions: { x: number; y: number; pg: ChainPodGroup; svcIdx: number }[] = [];
		let podIdx = 0;
		const podStartY = PAD.top + (maxColHeight - podColHeight) / 2 + ICON_R;
		for (let si = 0; si < services.length; si++) {
			const pods = svcPodMap.get(services[si].name) ?? [];
			if (pods.length === 0) {
				podPositions.push({
					x: col2x,
					y: podStartY + podIdx * (ICON_R * 2 + ROW_GAP),
					pg: { owner: 'none', owner_kind: '-', pod_count: 0, phase: '', containers: [], service_name: services[si].name },
					svcIdx: si,
				});
				podIdx++;
			} else {
				for (const pg of pods) {
					podPositions.push({
						x: col2x,
						y: podStartY + podIdx * (ICON_R * 2 + ROW_GAP),
						pg,
						svcIdx: si,
					});
					podIdx++;
				}
			}
		}

		return { totalWidth, totalHeight, ingressY, svcPositions, podPositions };
	});

	// Bezier arrow path between two points
	function arrow(x1: number, y1: number, x2: number, y2: number): string {
		const cx = (x1 + x2) / 2;
		return `M ${x1} ${y1} C ${cx} ${y1}, ${cx} ${y2}, ${x2} ${y2}`;
	}

	function truncate(s: string, max: number): string {
		return s.length > max ? s.slice(0, max - 1) + '…' : s;
	}

	// --- Popover state ---
	type PopoverData = {
		x: number;
		y: number;
		type: 'ingress' | 'service' | 'pod';
		title: string;
		lines: string[];
	};
	let popover: PopoverData | null = $state(null);

	function showIngress(e: MouseEvent) {
		if (!chain.ingress) return;
		const ing = chain.ingress;
		popover = {
			x: col0x, y: layout.ingressY,
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
			x: 0, y: 0, // positioned via CSS
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
			x: 0, y: 0,
			type: 'pod', title: pg.owner,
			lines: [
				`${pg.owner_kind} · ${pg.pod_count} pod${pg.pod_count !== 1 ? 's' : ''} · ${pg.phase}`,
				...(pg.containers ?? []).map(c =>
					`${c.registry ? c.registry + '/' : ''}${c.image}${c.tag ? ':' + c.tag : ''}${c.digest ? '\n  @' + c.digest : ''}`
				),
			]
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

	<!-- Arrows: Ingress → Services -->
	{#each layout.svcPositions as sp}
		<path
			d={arrow(col0x + ICON_R + 4, layout.ingressY, sp.x - ICON_R - 4, sp.y)}
			stroke="var(--bg4)"
			stroke-width="1.5"
			stroke-dasharray="6 4"
			fill="none"
			marker-end="url(#arrowhead)"
			opacity="0.6"
		/>
	{/each}

	<!-- Arrows: Services → Pod groups -->
	{#each layout.podPositions as pp}
		{@const sp = layout.svcPositions[pp.svcIdx]}
		{#if sp}
			<path
				d={arrow(sp.x + ICON_R + 4, sp.y, pp.x - ICON_R - 4, pp.y)}
				stroke="var(--bg4)"
				stroke-width="1.5"
				stroke-dasharray="6 4"
				fill="none"
				marker-end="url(#arrowhead)"
				opacity="0.6"
			/>
		{/if}
	{/each}

	<!-- Ingress node -->
	{#if chain.ingress}
		<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
		<g class="cursor-pointer" onclick={showIngress}>
			<circle cx={col0x} cy={layout.ingressY} r={ICON_R} fill="var(--green)" opacity="0.15" stroke="var(--green)" stroke-width="1.5" />
			<!-- Globe icon -->
			<g transform="translate({col0x - 7}, {layout.ingressY - 7})">
				<circle cx="7" cy="7" r="6" fill="none" stroke="var(--green)" stroke-width="1.2" />
				<ellipse cx="7" cy="7" rx="3" ry="6" fill="none" stroke="var(--green)" stroke-width="0.8" />
				<line x1="1" y1="7" x2="13" y2="7" stroke="var(--green)" stroke-width="0.8" />
			</g>
			<text x={col0x} y={layout.ingressY + LABEL_OFFSET} text-anchor="middle" fill="var(--fg1)" font-size="9" font-weight="600">{truncate(chain.host, 22)}</text>
			<text x={col0x} y={layout.ingressY + SUBLABEL_OFFSET} text-anchor="middle" fill="var(--fg4)" font-size="8">
				{chain.ingress.kind}{chain.ingress.ingress_class ? ` · ${chain.ingress.ingress_class}` : ''}{chain.ingress.tls ? ' · TLS' : ''}
			</text>
		</g>
	{/if}

	<!-- Service nodes -->
	{#each layout.svcPositions as sp}
		<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
		<g class="cursor-pointer" onclick={() => showService(sp.svc)}>
			<circle cx={sp.x} cy={sp.y} r={ICON_R} fill="var(--blue)" opacity="0.15" stroke="var(--blue)" stroke-width="1.5" />
			<!-- Service/network icon -->
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

	<!-- Pod group nodes -->
	{#each layout.podPositions as pp}
		<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
		<g class="cursor-pointer" onclick={() => pp.pg.pod_count > 0 && showPod(pp.pg)}>
			{#if pp.pg.pod_count > 0}
				<circle cx={pp.x} cy={pp.y} r={ICON_R} fill="var(--aqua)" opacity="0.15" stroke="var(--aqua)" stroke-width="1.5" />
				<!-- Container/box icon -->
				<g transform="translate({pp.x - 7}, {pp.y - 7})">
					<rect x="1" y="3" width="12" height="10" rx="1.5" fill="none" stroke="var(--aqua)" stroke-width="1.2" />
					<line x1="1" y1="7" x2="13" y2="7" stroke="var(--aqua)" stroke-width="0.8" />
					<line x1="7" y1="0" x2="3" y2="3" stroke="var(--aqua)" stroke-width="0.8" />
					<line x1="7" y1="0" x2="11" y2="3" stroke="var(--aqua)" stroke-width="0.8" />
				</g>
				<!-- Pod count badge -->
				{#if pp.pg.pod_count > 1}
					<circle cx={pp.x + ICON_R - 4} cy={pp.y - ICON_R + 4} r="8" fill="var(--accent)" />
					<text x={pp.x + ICON_R - 4} y={pp.y - ICON_R + 7.5} text-anchor="middle" fill="var(--bg-hard)" font-size="9" font-weight="700">{pp.pg.pod_count}</text>
				{/if}
				<text x={pp.x} y={pp.y + LABEL_OFFSET} text-anchor="middle" fill="var(--fg1)" font-size="9" font-weight="600">{truncate(pp.pg.owner, 22)}</text>
				<text x={pp.x} y={pp.y + SUBLABEL_OFFSET} text-anchor="middle" fill="var(--fg4)" font-size="8">
					{pp.pg.owner_kind}{pp.pg.containers?.length ? ` · ${pp.pg.containers.map((c) => c.image.split('/').pop()).join(', ').slice(0, 30)}` : ''}
				</text>
			{:else}
				<!-- Empty/missing pod placeholder -->
				<circle cx={pp.x} cy={pp.y} r={ICON_R} fill="var(--bg2)" opacity="0.3" stroke="var(--bg3)" stroke-width="1.5" stroke-dasharray="4 3" />
				<text x={pp.x} y={pp.y + 4} text-anchor="middle" fill="var(--fg4)" font-size="10">—</text>
				<text x={pp.x} y={pp.y + LABEL_OFFSET} text-anchor="middle" fill="var(--fg4)" font-size="11">no pods</text>
			{/if}
		</g>
	{/each}

	<!-- Click-away background -->
	{#if popover}
		<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
		<rect x="0" y="0" width={layout.totalWidth} height={layout.totalHeight} fill="transparent" onclick={hidePopover} />
	{/if}
</svg>

<!-- Metadata popover (HTML overlay) -->
{#if popover}
	<div
		class="mt-2 rounded-lg border border-[var(--border-color)]/60 bg-[var(--bg)] px-4 py-3 text-xs shadow-lg"
	>
		<div class="flex items-center justify-between">
			<span class="font-semibold text-[var(--text-bright)]">{popover.title}</span>
			<button class="text-[var(--text-muted)] hover:text-[var(--text-bright)]" onclick={hidePopover}>&times;</button>
		</div>
		<div class="mt-1.5 space-y-0.5">
			{#each popover.lines as line}
				<div class="whitespace-pre-wrap text-[var(--text-secondary)]">{line}</div>
			{/each}
		</div>
	</div>
{/if}
