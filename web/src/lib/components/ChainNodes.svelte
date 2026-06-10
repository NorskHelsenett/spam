<svelte:options namespace="svg" />

<!-- SVG fragment for one namespace's exposure chain. Rendered inside an
     <svg> by HostChainDiagram (one chain per SVG) and ClusterMap (all
     namespaces stacked in a single SVG). The parent SVG must define the
     #arrowhead marker. -->
<script lang="ts">
	import {
		ICON_R,
		LABEL_OFFSET,
		PORT_OFFSET,
		SMALL_R,
		SUBLABEL_OFFSET,
		arrow,
		truncate,
		type ChainData,
		type ChainIngress,
		type ChainLayout,
		type ChainPodGroup,
		type ChainService
	} from './chainLayout';

	let {
		chain,
		layout,
		onShowIngress,
		onShowService,
		onShowPod,
		riskyKeys = undefined
	}: {
		chain: ChainData;
		layout: ChainLayout;
		onShowIngress: (ing: ChainIngress) => void;
		onShowService: (svc: ChainService) => void;
		onShowPod: (pg: ChainPodGroup) => void;
		// "namespace/digest" keys of extremely vulnerable images — flagged
		// pod nodes get a red shield badge. Computed by the caller (the
		// cluster page has the vuln data; the chain payload doesn't).
		riskyKeys?: Set<string>;
	} = $props();

	const isRisky = (pg: ChainPodGroup) =>
		!!riskyKeys &&
		(pg.containers ?? []).some((c) => c.digest && riskyKeys.has(`${chain.namespace}/${c.digest}`));
</script>

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
	<g class="cursor-pointer" onclick={() => onShowIngress(ip.ing)}>
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
	<g class="cursor-pointer" onclick={() => onShowService(sp.svc)}>
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

<!-- Pod owner groups. Transient groups (completed Jobs, failed
     replicas observed in the last 24h) render at 45% opacity with
     muted fill/stroke to keep focus on live workloads. -->
{#each layout.ownerGroups as og}
	{@const imgLabel = og.pg.containers?.length ? og.pg.containers.map((c) => c.image.split('/').pop()).join(', ') : ''}
	{@const isTransient = og.pg.transient === true}
	{@const risky = isRisky(og.pg)}

	{#each og.nodes as node}
		<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
		<g class="cursor-pointer" onclick={() => onShowPod(node.pg)} opacity={isTransient ? 0.45 : 1}>
			{#if node.pg.pod_count > 0}
				<circle cx={node.x} cy={node.y} r={SMALL_R} fill={isTransient ? 'var(--bg2)' : 'var(--aqua)'} opacity={isTransient ? 0.25 : 0.15} stroke={isTransient ? 'var(--fg4)' : 'var(--aqua)'} stroke-width="1.2" stroke-dasharray={isTransient ? '3 2' : undefined} />
				<g transform="translate({node.x - 5}, {node.y - 5})">
					<rect x="0" y="2" width="10" height="7" rx="1" fill="none" stroke={isTransient ? 'var(--fg4)' : 'var(--aqua)'} stroke-width="1" />
					<line x1="0" y1="5" x2="10" y2="5" stroke={isTransient ? 'var(--fg4)' : 'var(--aqua)'} stroke-width="0.7" />
				</g>
				{#if node.isCollapsed}
					<circle cx={node.x + SMALL_R - 2} cy={node.y - SMALL_R + 2} r="7" fill={isTransient ? 'var(--fg4)' : 'var(--accent)'} />
					<text x={node.x + SMALL_R - 2} y={node.y - SMALL_R + 5} text-anchor="middle" fill="var(--bg-hard)" font-size="8" font-weight="700">{node.pg.pod_count}</text>
				{/if}
				{#if risky}
					<!-- Red shield: image is extremely vulnerable (KEV + high
					     EPSS) and reachable through an exposed domain. -->
					<g transform="translate({node.x - SMALL_R + 2}, {node.y - SMALL_R + 2})">
						<title>Extremely vulnerable image — KEV + high EPSS behind an exposed domain</title>
						<circle r="7" fill="var(--red)" />
						<path
							d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1 1 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"
							transform="translate(-5, -5) scale(0.42)"
							fill="var(--bg-hard)"
						/>
					</g>
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
	<text x={lastNode.x} y={lastNode.y + LABEL_OFFSET} text-anchor="middle" fill={isTransient ? 'var(--fg4)' : 'var(--fg1)'} font-size="9" font-weight="600" opacity={isTransient ? 0.75 : 1}>{truncate(og.owner, 22)}</text>
	<text x={lastNode.x} y={lastNode.y + SUBLABEL_OFFSET} text-anchor="middle" fill="var(--fg4)" font-size="8" opacity={isTransient ? 0.75 : 1}>{og.ownerKind}{isTransient ? ` · ${og.pg.phase || 'past'}` : ''}</text>
{/each}

<!-- Endpoint IP nodes (external services) -->
{#each layout.endpointNodes as ep}
	{@const svc = chain.services?.find((s) => s.name === ep.svcName)}
	{@const ports = svc?.endpoint_ports?.length ? svc.endpoint_ports : svc?.ports?.map((p) => p.port) ?? []}
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
