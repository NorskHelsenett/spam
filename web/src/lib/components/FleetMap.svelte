<script lang="ts">
	import ButtonGroup from '$lib/components/ButtonGroup.svelte';
	import type { FleetAgent, FleetHealth } from '$lib/fleet';

	type GroupBy = 'environment' | 'version' | 'none';

	// A dense status grid of every agent: one cell each, so 400+ fit on a
	// screen. Cell SIZE = memory footprint (hogs are bigger). Each GROUP
	// gets its own colour (hue); HEALTH is a shade of that hue — live is
	// full strength, stale is muted, dead is a dark shade, and flapping
	// pulses. Shades transition, so a rollout/incident animates across the
	// grid when the `agents` prop updates (e.g. from the SSE stream).

	let { agents = [] as FleetAgent[] } = $props();

	let groupBy = $state<GroupBy>('environment');

	let hovered = $state<FleetAgent | null>(null);
	let tipEl = $state<HTMLDivElement | null>(null);
	let anchor = $state<{ x: number; y: number; w: number; h: number } | null>(null);
	let pos = $state({ left: 0, top: 0 });
	let placed = $state(false);

	function enter(e: MouseEvent, a: FleetAgent) {
		hovered = a;
		// Copy out primitive rect values. Storing the live DOMRect in
		// $state breaks in Safari: Svelte proxies it, and DOMRect's getters
		// throw when invoked with a proxy as `this`, so the effect dies.
		const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
		anchor = { x: r.left, y: r.top, w: r.width, h: r.height };
	}
	function leave() {
		hovered = null;
		anchor = null;
	}

	// Anchor the tooltip to the hovered cell — centred just above it, a
	// small gap away. Keep it fully on-screen: flip below when there's no
	// room above, and clamp on both axes so it never spills off the edge.
	$effect(() => {
		if (!hovered || !anchor || !tipEl) return;
		const gap = 8;
		const w = tipEl.offsetWidth;
		const h = tipEl.offsetHeight;
		let left = anchor.x + anchor.w / 2 - w / 2;
		left = Math.max(8, Math.min(left, window.innerWidth - w - 8));
		let top = anchor.y - h - gap;
		if (top < 8) top = anchor.y + anchor.h + gap;
		top = Math.max(8, Math.min(top, window.innerHeight - h - 8));
		pos = { left, top };
		placed = true;
	});

	const GROUP_OPTS = [
		{ value: 'environment', label: 'Environment' },
		{ value: 'version', label: 'Version' },
		{ value: 'none', label: 'None' }
	];

	const PALETTE = [
		'var(--blue)',
		'var(--purple)',
		'var(--aqua)',
		'var(--yellow)',
		'var(--green)',
		'var(--orange)',
		'var(--blue-dim)',
		'var(--purple-dim)'
	];
	const ENV_COLORS: Record<string, string> = {
		prod: 'var(--orange)',
		production: 'var(--orange)',
		staging: 'var(--purple)',
		test: 'var(--blue)',
		dev: 'var(--aqua)'
	};
	// Semantic colours for the tooltip badge only.
	const HEALTH_BADGE: Record<FleetHealth, string> = {
		live: 'var(--green)',
		stale: 'var(--yellow)',
		dead: 'var(--red)'
	};

	function hashIndex(s: string, mod: number): number {
		let h = 0;
		for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
		return Math.abs(h) % mod;
	}

	function groupColor(key: string): string {
		if (groupBy === 'environment') return ENV_COLORS[key.toLowerCase()] ?? PALETTE[hashIndex(key, PALETTE.length)];
		if (groupBy === 'version') return PALETTE[hashIndex(key, PALETTE.length)];
		return 'var(--blue)';
	}

	// Health is a shade of the group's hue (see the CSS classes below):
	// live = full hue, stale = dimmed, dead = a theme-neutral (light in
	// dark mode, grey in light mode) so dead agents stay distinct instead
	// of fading into the background. All composite over the gruvbox theme.

	// Cell side scales with memory (area ∝ usage via sqrt), normalised to
	// the fleet's max so the biggest consumer is the biggest box.
	const MIN_PX = 10;
	const MAX_PX = 30;
	const rssMax = $derived(Math.max(1, ...agents.map((a) => a.rssBytes)));
	const sideFor = (a: FleetAgent) => Math.round(MIN_PX + (MAX_PX - MIN_PX) * Math.sqrt(Math.min(1, a.rssBytes / rssMax)));

	const needsAttention = (a: FleetAgent) => a.health !== 'live' || a.flapping;

	const kpis = $derived.by(() => {
		let live = 0,
			stale = 0,
			dead = 0,
			attention = 0;
		const versions = new Set<string>();
		for (const a of agents) {
			if (a.health === 'live') live++;
			else if (a.health === 'stale') stale++;
			else dead++;
			if (needsAttention(a)) attention++;
			versions.add(a.version);
		}
		return { total: agents.length, live, stale, dead, attention, versions: versions.size };
	});

	const groups = $derived.by(() => {
		if (groupBy === 'none') return [{ key: 'All agents', color: 'var(--blue)', agents }];
		const m = new Map<string, FleetAgent[]>();
		for (const a of agents) {
			const k = groupBy === 'version' ? a.version : a.environment;
			(m.get(k) ?? m.set(k, []).get(k)!).push(a);
		}
		return [...m.entries()]
			.sort((a, b) => b[1].length - a[1].length)
			.map(([key, list]) => ({ key, color: groupColor(key), agents: list }));
	});

	const SAMPLE = 'var(--blue)';
	const shadeLegend = [
		{ label: 'live', cls: '' },
		{ label: 'stale', cls: 'is-stale' },
		{ label: 'dead', cls: 'is-dead' },
		{ label: 'flapping', cls: 'flap' }
	];

	const fmtBytes = (b: number) => (b >= 1 << 30 ? (b / (1 << 30)).toFixed(1) + ' GiB' : Math.round(b / (1 << 20)) + ' MiB');
	const fmtUptime = (s: number) => (s >= 86400 ? Math.floor(s / 86400) + 'd' : s >= 3600 ? Math.floor(s / 3600) + 'h' : Math.floor(s / 60) + 'm');
</script>

<div class="flex flex-col gap-5" role="group" aria-label="Fleet map">
	<!-- KPIs -->
	<div class="grid grid-cols-3 gap-3 sm:grid-cols-6">
		{#each [['Agents', kpis.total, 'var(--text-bright)'], ['Live', kpis.live, 'var(--green)'], ['Stale', kpis.stale, 'var(--yellow)'], ['Dead', kpis.dead, 'var(--red)'], ['Needs attn', kpis.attention, 'var(--orange)'], ['Versions', kpis.versions, 'var(--blue)']] as [label, value, color]}
			<div class="metric-card space-y-1 rounded-2xl p-4">
				<p class="text-2xl font-bold tabular-nums" style="color:{color}">{value}</p>
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">{label}</h3>
			</div>
		{/each}
	</div>

	<!-- Group control + shade legend -->
	<div class="flex flex-wrap items-center justify-between gap-4">
		<div class="flex items-center gap-2">
			<span class="text-xs uppercase tracking-[0.18em] text-[var(--text-muted)]">Group</span>
			<ButtonGroup size="sm" options={GROUP_OPTS} value={groupBy} onchange={(v) => (groupBy = v as GroupBy)} />
		</div>
		<div class="flex flex-wrap items-center gap-x-3 gap-y-1">
			{#each shadeLegend as item}
				<span class="flex items-center gap-1.5 text-xs text-[var(--text-secondary)]">
					<span class="swatch {item.cls}" style="--cell:{SAMPLE}"></span>
					<span class="capitalize">{item.label}</span>
				</span>
			{/each}
			<span class="text-xs text-[var(--text-muted)]">· box size = memory</span>
		</div>
	</div>

	<!-- Swimlanes (each group its own hue) -->
	<div class="flex flex-col gap-4">
		{#each groups as group (group.key)}
			<div>
				<div class="mb-2 flex items-baseline gap-2">
					<span class="h-3 w-3 self-center rounded-sm" style="background:{group.color}"></span>
					<span class="text-sm font-medium capitalize text-[var(--text-primary)]">{group.key}</span>
					<span class="text-xs tabular-nums text-[var(--text-muted)]">{group.agents.length}</span>
				</div>
				<div class="flex flex-wrap items-end gap-[3px]">
					{#each group.agents as a (a.clusterId)}
						<button
							class="fleet-cell"
							class:is-stale={a.health === 'stale'}
							class:is-dead={a.health === 'dead'}
							class:flap={a.flapping}
							style="--cell:{group.color};width:{sideFor(a)}px;height:{sideFor(a)}px"
							onmouseenter={(e) => enter(e, a)}
							onmouseleave={leave}
							aria-label="{a.name} {a.version} {a.health}"
						></button>
					{/each}
				</div>
			</div>
		{/each}
	</div>
</div>

{#if hovered}
	<div
		bind:this={tipEl}
		class="pointer-events-none fixed z-50 w-60 rounded-lg border border-[var(--border-color)] bg-[var(--bg-hard)] p-3 text-xs shadow-xl"
		style="left:{pos.left}px; top:{pos.top}px; visibility:{placed ? 'visible' : 'hidden'}"
	>
		<div class="mb-1 flex items-center justify-between gap-2">
			<span class="font-semibold text-[var(--text-bright)]">{hovered.name}</span>
			<span class="rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wide" style="background:{HEALTH_BADGE[hovered.health]};color:var(--bg-hard)">{hovered.health}</span>
		</div>
		<dl class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-[var(--text-secondary)]">
			<dt class="text-[var(--text-muted)]">version</dt>
			<dd class="tabular-nums">{hovered.version}</dd>
			<dt class="text-[var(--text-muted)]">environment</dt>
			<dd>{hovered.environment}</dd>
			<dt class="text-[var(--text-muted)]">uptime</dt>
			<dd class="tabular-nums">{fmtUptime(hovered.uptimeSeconds)}</dd>
			<dt class="text-[var(--text-muted)]">memory</dt>
			<dd class="tabular-nums">{fmtBytes(hovered.rssBytes)}</dd>
			<dt class="text-[var(--text-muted)]">cpu</dt>
			<dd class="tabular-nums">{hovered.cpuPct.toFixed(1)}%</dd>
			<dt class="text-[var(--text-muted)]">goroutines</dt>
			<dd class="tabular-nums">{hovered.goroutines}</dd>
		</dl>
		{#if hovered.flapping}
			<div class="mt-1.5 text-[var(--orange)]">⚠ flapping — recent restarts</div>
		{/if}
	</div>
{/if}

<style>
	.fleet-cell,
	.swatch {
		background: var(--cell);
	}
	.swatch {
		display: inline-block;
		width: 12px;
		height: 12px;
		border-radius: 2px;
	}
	.fleet-cell {
		border-radius: 3px;
		cursor: pointer;
		transition:
			background-color 600ms ease,
			width 300ms ease,
			height 300ms ease,
			opacity 200ms ease,
			transform 120ms ease;
		outline: none;
	}
	/* Health as a shade of the group hue. */
	.fleet-cell.is-stale,
	.swatch.is-stale {
		opacity: 0.5;
	}
	/* Dead drops its hue for a theme-neutral so it stays visible:
	   light/whitish in dark mode, grey in light mode. */
	.fleet-cell.is-dead,
	.swatch.is-dead {
		background: var(--fg1);
	}
	:global(html.light) .fleet-cell.is-dead,
	:global(html.light) .swatch.is-dead {
		background: var(--gray);
	}
	.fleet-cell.flap,
	.swatch.flap {
		animation: flap-pulse 1.2s ease-in-out infinite;
	}
	/* Hover lifts the cell solidly above its neighbours — full opacity, on
	   top, animation paused — even for dimmed (stale) cells. */
	.fleet-cell:hover,
	.fleet-cell:focus-visible {
		transform: scale(1.5);
		opacity: 1;
		z-index: 10;
		animation-play-state: paused;
	}
	@keyframes flap-pulse {
		0%,
		100% {
			opacity: 1;
		}
		50% {
			opacity: 0.3;
		}
	}
</style>
