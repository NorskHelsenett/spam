<script lang="ts">
	import { Maximize, ZoomIn, ZoomOut } from 'lucide-svelte';
	import ChainNodes from './ChainNodes.svelte';
	import ChainPopover from './ChainPopover.svelte';
	import {
		computeChainLayout,
		ingressPopover,
		nsChainToChainData,
		podPopover,
		servicePopover,
		type ChainData,
		type ChainLayout,
		type ClusterChainData,
		type PopoverData
	} from './chainLayout';

	let {
		clusterId,
		riskyKeys = undefined
	}: {
		clusterId: string;
		// "namespace/digest" keys of extremely vulnerable images, badged
		// with a red shield on their pod nodes (see ChainNodes).
		riskyKeys?: Set<string>;
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
			.then((r) => { if (!r.ok) throw new Error(`${r.status}`); return r.json(); })
			.then((d) => { data = d; })
			.catch((e) => { error = e.message || 'Failed to load'; })
			.finally(() => { loading = false; });
	});

	// --- Single-SVG layout: namespaces packed into balanced columns ---
	// so the map spreads in both directions (pans like a map) instead of
	// one tall strip. Greedy shortest-column packing; the column count
	// targets a landscape-ish overall aspect.
	const NS_HEADER_H = 36;
	const NS_GAP = 28;
	const COL_GUTTER = 56;
	const TARGET_ASPECT = 1.6;
	type MapSection = {
		namespace: string;
		chain: ChainData;
		layout: ChainLayout;
		x: number;
		y: number;
	};

	let map = $derived.by(() => {
		const prepared: { namespace: string; chain: ChainData; layout: ChainLayout; h: number }[] = [];
		let colW = 320;
		if (data) {
			for (const ns of data.namespaces) {
				// Skip namespaces with nothing to draw (drawer shows an empty
				// header for these; the map saves the space).
				if (!ns.ingresses?.length && !ns.services?.length && !ns.pods?.length) continue;
				const chain = nsChainToChainData(ns, data.cluster, data.cluster_id);
				const layout = computeChainLayout(chain);
				prepared.push({ namespace: ns.namespace, chain, layout, h: NS_HEADER_H + layout.totalHeight });
				colW = Math.max(colW, layout.totalWidth);
			}
		}
		// Column count N so that N·colW / (totalH/N) ≈ TARGET_ASPECT.
		const totalH = prepared.reduce((s, p) => s + p.h + NS_GAP, 0);
		const cols = Math.max(
			1,
			Math.min(prepared.length, Math.round(Math.sqrt((totalH * TARGET_ASPECT) / (colW + COL_GUTTER))))
		);
		const colHeights: number[] = new Array(cols).fill(0);
		const sections: MapSection[] = prepared.map((p) => {
			let c = 0;
			for (let i = 1; i < cols; i++) if (colHeights[i] < colHeights[c]) c = i;
			const sec = { namespace: p.namespace, chain: p.chain, layout: p.layout, x: c * (colW + COL_GUTTER), y: colHeights[c] };
			colHeights[c] += p.h + NS_GAP;
			return sec;
		});
		const width = cols * colW + (cols - 1) * COL_GUTTER;
		const height = Math.max(...colHeights, NS_GAP) - NS_GAP;
		return { sections, colW, width: Math.max(width, 320), height: Math.max(height, 1) };
	});

	// --- Pan/zoom via viewBox ---
	// `view` holds x/y/w in map coordinates; the viewBox height always
	// follows the container's aspect ratio so nothing letterboxes and
	// cursor↔map conversion stays linear.
	let svgEl: SVGSVGElement | undefined = $state();
	let containerW = $state(0);
	let containerH = $state(0);
	let view = $state({ x: 0, y: 0, w: 0 });
	let viewH = $derived(containerW > 0 ? (view.w * containerH) / containerW : view.w);

	const FIT_PAD = 24;
	const MIN_VIEW_W = 200; // map units across the screen at max zoom-in

	// viewBox width that frames the whole map in the container's aspect.
	const fullW = () => {
		const aspect = containerW > 0 && containerH > 0 ? containerW / containerH : TARGET_ASPECT;
		return Math.max(map.width + FIT_PAD * 2, (map.height + FIT_PAD * 2) * aspect);
	};

	// Fit = zoom out until the entire cluster is visible, centered.
	const fit = () => {
		const aspect = containerW > 0 && containerH > 0 ? containerW / containerH : TARGET_ASPECT;
		const w = fullW();
		const h = w / aspect;
		view = { x: (map.width - w) / 2, y: (map.height - h) / 2, w };
	};

	// Frame the whole cluster once both the data and container size are known.
	let fitted = $state(false);
	$effect(() => {
		if (!fitted && map.sections.length > 0 && containerW > 0) {
			fitted = true;
			fit();
		}
	});

	const clampW = (w: number) => Math.min(Math.max(w, MIN_VIEW_W), fullW() * 1.4);

	// Convert a client-space point into map coordinates via the SVG's CTM.
	const clientToMap = (cx: number, cy: number) => {
		const ctm = svgEl?.getScreenCTM();
		if (!ctm) return { x: 0, y: 0 };
		const p = new DOMPoint(cx, cy).matrixTransform(ctm.inverse());
		return { x: p.x, y: p.y };
	};

	// Zoom keeping the given map-space point fixed under the cursor.
	const zoomAt = (factor: number, px: number, py: number) => {
		const w = clampW(view.w * factor);
		const s = w / view.w;
		view = { x: px - (px - view.x) * s, y: py - (py - view.y) * s, w };
	};

	const zoomCenter = (factor: number) =>
		zoomAt(factor, view.x + view.w / 2, view.y + viewH / 2);

	// Two-finger scroll pans the map; pinch (trackpads report it as
	// ctrl+wheel) or Ctrl/⌘+scroll zooms at the cursor. Svelte 5 attaches
	// wheel handlers passively, so preventDefault (needed to stop the page
	// scrolling under the map) requires a manual listener.
	const wheelNav = (node: SVGSVGElement) => {
		const onWheel = (e: WheelEvent) => {
			e.preventDefault();
			if (e.ctrlKey || e.metaKey) {
				const p = clientToMap(e.clientX, e.clientY);
				// Exponential scaling keeps pinch (small deltas) smooth and
				// caps a notchy mouse wheel at ~1.5x per tick.
				const factor = Math.exp(Math.max(-40, Math.min(40, e.deltaY)) * 0.01);
				zoomAt(factor, p.x, p.y);
			} else {
				const scale = view.w / (containerW || 1);
				// Firefox reports shift+wheel in deltaY; treat it as horizontal.
				const horiz = e.shiftKey && !e.deltaX;
				view = {
					...view,
					x: view.x + (horiz ? e.deltaY : e.deltaX) * scale,
					y: view.y + (horiz ? 0 : e.deltaY) * scale
				};
			}
		};
		node.addEventListener('wheel', onWheel, { passive: false });
		return { destroy: () => node.removeEventListener('wheel', onWheel) };
	};

	// Drag-to-pan. The anchor is captured in map space at pointerdown; each
	// move shifts the view so that anchor stays under the cursor, which is
	// self-stabilizing across viewBox updates.
	let panning = $state(false);
	let panAnchor = { x: 0, y: 0 };
	let downClient = { x: 0, y: 0 };
	let dragged = false;

	const onPointerDown = (e: PointerEvent) => {
		if (e.button !== 0) return;
		panning = true;
		dragged = false;
		panAnchor = clientToMap(e.clientX, e.clientY);
		downClient = { x: e.clientX, y: e.clientY };
		(e.currentTarget as SVGSVGElement).setPointerCapture(e.pointerId);
	};
	const onPointerMove = (e: PointerEvent) => {
		if (!panning) return;
		if (Math.abs(e.clientX - downClient.x) + Math.abs(e.clientY - downClient.y) > 4) dragged = true;
		const p = clientToMap(e.clientX, e.clientY);
		view = { ...view, x: view.x + (panAnchor.x - p.x), y: view.y + (panAnchor.y - p.y) };
	};
	const onPointerUp = () => {
		panning = false;
	};

	// After a drag, swallow the click so releasing over a node doesn't open
	// its popover; a clean click on empty space dismisses the popover.
	const onClickCapture = (e: MouseEvent) => {
		if (dragged) {
			e.preventDefault();
			e.stopPropagation();
			dragged = false;
		} else if (!(e.target as Element).closest('g.cursor-pointer')) {
			popover = null;
		}
	};

	let popover: PopoverData | null = $state(null);

	let viewBoxStr = $derived(
		view.w > 0 && viewH > 0
			? `${view.x} ${view.y} ${view.w} ${viewH}`
			: `0 0 ${map.width} ${map.height}`
	);

	// Approximate label width for the namespace divider lines (font-size 11
	// + letter-spacing 2 ≈ 9px per char) — SVG has no layout to measure.
	const headerHalf = (ns: string) => (ns.length * 9 + 28) / 2;
</script>

<div
	class="relative h-[70vh] min-h-[420px] overflow-hidden rounded-xl border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40"
	bind:clientWidth={containerW}
	bind:clientHeight={containerH}
>
	{#if loading}
		<div class="flex h-full items-center justify-center">
			<div class="h-5 w-5 animate-spin rounded-full border-2 border-[var(--border-color)] border-t-[var(--accent)]"></div>
		</div>
	{:else if error}
		<div class="flex h-full items-center justify-center text-sm text-[var(--text-tertiary)]">
			Failed to load cluster map
		</div>
	{:else if map.sections.length === 0}
		<div class="flex h-full items-center justify-center text-sm text-[var(--text-tertiary)]">
			No data available
		</div>
	{:else}
		<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
		<svg
			bind:this={svgEl}
			use:wheelNav
			width="100%"
			height="100%"
			viewBox={viewBoxStr}
			preserveAspectRatio="xMidYMid meet"
			xmlns="http://www.w3.org/2000/svg"
			class="touch-none select-none {panning ? 'cursor-grabbing' : 'cursor-grab'}"
			onpointerdown={onPointerDown}
			onpointermove={onPointerMove}
			onpointerup={onPointerUp}
			onpointercancel={onPointerUp}
			onclickcapture={onClickCapture}
		>
			<defs>
				<marker id="arrowhead" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
					<polygon points="0 0, 8 3, 0 6" fill="var(--bg4)" />
				</marker>
			</defs>

			{#each map.sections as s (s.namespace)}
				{@const cx = s.x + map.colW / 2}
				{@const half = headerHalf(s.namespace)}
				{@const hy = s.y + NS_HEADER_H / 2}
				<!-- Namespace divider, mirroring the drawer's line · NAME · line header -->
				<line x1={s.x + 8} y1={hy} x2={Math.max(s.x + 8, cx - half)} y2={hy} stroke="var(--border-color)" stroke-opacity="0.5" />
				<line x1={Math.min(s.x + map.colW - 8, cx + half)} y1={hy} x2={s.x + map.colW - 8} y2={hy} stroke="var(--border-color)" stroke-opacity="0.5" />
				<text x={cx} y={hy + 3.5} text-anchor="middle" fill="var(--fg4)" font-size="11" font-weight="600" letter-spacing="2">{s.namespace.toUpperCase()}</text>

				<g transform="translate({s.x}, {s.y + NS_HEADER_H})">
					<ChainNodes
						chain={s.chain}
						layout={s.layout}
						{riskyKeys}
						onShowIngress={(ing) => (popover = ingressPopover(ing))}
						onShowService={(svc) => (popover = servicePopover(svc))}
						onShowPod={(pg) => (popover = podPopover(pg))}
					/>
				</g>
			{/each}
		</svg>

		<!-- Zoom controls -->
		<div class="absolute right-3 top-3 flex flex-col gap-1.5">
			<button
				type="button"
				class="flex h-8 w-8 items-center justify-center rounded-lg border border-[var(--border-color)]/60 bg-[var(--bg)]/90 text-[var(--text-secondary)] shadow transition hover:text-[var(--text-bright)]"
				onclick={() => zoomCenter(1 / 1.4)}
				title="Zoom in"
				aria-label="Zoom in"
			>
				<ZoomIn size={15} />
			</button>
			<button
				type="button"
				class="flex h-8 w-8 items-center justify-center rounded-lg border border-[var(--border-color)]/60 bg-[var(--bg)]/90 text-[var(--text-secondary)] shadow transition hover:text-[var(--text-bright)]"
				onclick={() => zoomCenter(1.4)}
				title="Zoom out"
				aria-label="Zoom out"
			>
				<ZoomOut size={15} />
			</button>
			<button
				type="button"
				class="flex h-8 w-8 items-center justify-center rounded-lg border border-[var(--border-color)]/60 bg-[var(--bg)]/90 text-[var(--text-secondary)] shadow transition hover:text-[var(--text-bright)]"
				onclick={fit}
				title="Reset view"
				aria-label="Reset view"
			>
				<Maximize size={15} />
			</button>
		</div>

		<!-- Node details overlay -->
		{#if popover}
			<div class="absolute bottom-3 left-3 z-10 max-h-[55%] w-80 max-w-[85%] overflow-y-auto">
				<ChainPopover {popover} onClose={() => (popover = null)} />
			</div>
		{/if}

		<p class="pointer-events-none absolute bottom-3 right-3 text-[10px] leading-none text-[var(--text-muted)]">
			Scroll or drag to pan · pinch / Ctrl+scroll to zoom · click a node for details
		</p>
	{/if}
</div>
