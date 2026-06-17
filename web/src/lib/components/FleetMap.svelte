<script lang="ts">
	import TabSelector from '$lib/components/TabSelector.svelte';
	import type { FleetAgent, FleetHealth } from '$lib/fleet';
	import Tag from 'lucide-svelte/icons/tag';
	import Layers from 'lucide-svelte/icons/layers';
	import Clock from 'lucide-svelte/icons/clock';
	import MemoryStick from 'lucide-svelte/icons/memory-stick';
	import Cpu from 'lucide-svelte/icons/cpu';
	import Workflow from 'lucide-svelte/icons/workflow';
	import X from 'lucide-svelte/icons/x';
	import ArrowUpRight from 'lucide-svelte/icons/arrow-up-right';
	import ShieldAlert from 'lucide-svelte/icons/shield-alert';
	import DonutChart from '$lib/components/DonutChart.svelte';

	// A dense status grid of every agent: one cell each, so 400+ fit on a
	// screen. Cell SIZE = memory footprint (hogs are bigger). Each GROUP
	// gets its own colour (hue); HEALTH is a shade of that hue — live is
	// full strength, stale is muted, dead is a dark shade, and flapping
	// pulses. Shades transition, so a rollout/incident animates across the
	// grid when the `agents` prop updates (e.g. from the SSE stream).

	let { agents = [] as FleetAgent[] } = $props();

	let groupBy = $state('environment');

	let hovered = $state<FleetAgent | null>(null);
	let pinned = $state<FleetAgent | null>(null);
	const active = $derived(pinned ?? hovered);

	let tipEl = $state<HTMLDivElement | null>(null);
	let anchor = $state<{ x: number; y: number; w: number; h: number } | null>(null);
	let pos = $state({ left: 0, top: 0 });
	let placed = $state(false);

	function rectOf(e: MouseEvent) {
		// Copy out primitive rect values. Storing the live DOMRect in $state
		// breaks in Safari: Svelte proxies it and DOMRect's getters throw
		// when invoked with a proxy as `this`.
		const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
		return { x: r.left, y: r.top, w: r.width, h: r.height };
	}
	function enter(e: MouseEvent, a: FleetAgent) {
		if (pinned) return; // a pinned popover owns the view
		hovered = a;
		anchor = rectOf(e);
	}
	function leave() {
		if (pinned) return;
		hovered = null;
	}
	function clickCell(e: MouseEvent, a: FleetAgent) {
		if (pinned && pinned.clusterId === a.clusterId) {
			close(); // toggle off
			return;
		}
		pinned = a;
		hovered = null;
		anchor = rectOf(e);
	}
	function close() {
		pinned = null;
		hovered = null;
	}
	function onKeydown(e: KeyboardEvent) {
		if (e.key === 'Escape') close();
	}
	// Dismiss a pinned popover on outside click — cells and the popover
	// manage their own clicks.
	function onWindowClick(e: MouseEvent) {
		if (!pinned) return;
		const t = e.target as HTMLElement;
		if (t.closest('.fleet-cell') || t.closest('.fleet-popover')) return;
		close();
	}

	// Portal the popover to <body> so position:fixed is viewport-relative
	// regardless of any transformed/clipping ancestor (fixes Firefox/Safari
	// positioning) and so it layers above everything.
	function portal(node: HTMLElement) {
		document.body.appendChild(node);
		return {
			destroy() {
				node.remove();
			}
		};
	}

	// Anchor the popover to the cell — centred just above it, a small gap
	// away. Keep it fully on-screen: flip below when there's no room above,
	// clamp on both axes.
	$effect(() => {
		if (!active || !anchor || !tipEl) return;
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
	const envColor = (e: string) => ENV_COLORS[e.toLowerCase()] ?? PALETTE[hashIndex(e, PALETTE.length)];

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

	const envSegments = $derived.by(() => {
		const m = new Map<string, number>();
		for (const a of agents) m.set(a.environment, (m.get(a.environment) ?? 0) + 1);
		return [...m.entries()]
			.sort((a, b) => b[1] - a[1])
			.map(([label, value]) => ({ label, value, color: envColor(label) }));
	});

	function agg(values: number[]) {
		if (!values.length) return { avg: 0, median: 0, max: 0, min: 0 };
		const s = [...values].sort((a, b) => a - b);
		return {
			avg: s.reduce((t, x) => t + x, 0) / s.length,
			median: s[Math.floor(s.length / 2)],
			max: s[s.length - 1],
			min: s[0]
		};
	}
	const stats = $derived.by(() => ({
		mem: agg(agents.map((a) => a.rssBytes)),
		cpu: agg(agents.map((a) => a.cpuPct)),
		gor: agg(agents.map((a) => a.goroutines))
	}));

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

	const fmtBytes = (b: number) => (b >= 1 << 30 ? (b / (1 << 30)).toFixed(1) + ' GiB' : Math.round(b / (1 << 20)) + ' MiB');
	const fmtUptime = (s: number) => (s >= 86400 ? Math.floor(s / 86400) + 'd' : s >= 3600 ? Math.floor(s / 3600) + 'h' : Math.floor(s / 60) + 'm');
</script>

<div class="flex flex-col gap-5" role="group" aria-label="Fleet map">
	<!-- Overview: environment donut (left) + stat cards (right, two rows) -->
	<div class="grid gap-4 lg:grid-cols-[26rem_1fr]">
		<div class="metric-card flex flex-col justify-center rounded-2xl p-4">
			<DonutChart title="Environments" total={kpis.total} segments={envSegments} />
		</div>
		<div class="grid grid-cols-2 gap-4 sm:grid-cols-3">
			<!-- Row 1 — counts / health -->
			<div class="metric-card space-y-1 rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Agents</h3>
				<p class="text-3xl font-bold tabular-nums text-[var(--text-bright)]">{kpis.total}</p>
				<p class="text-xs text-[var(--text-muted)]">{kpis.live} live · {kpis.stale} stale · {kpis.dead} dead</p>
			</div>
			<div class="metric-card space-y-1 rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Need attention</h3>
				<p class="text-3xl font-bold tabular-nums" style="color:var(--warning)">{kpis.attention}</p>
				<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
					<ShieldAlert size={12} color="var(--warning)" /> stale, dead or flapping
				</p>
			</div>
			<div class="metric-card space-y-1 rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Versions</h3>
				<p class="text-3xl font-bold tabular-nums text-[var(--text-bright)]">{kpis.versions}</p>
				<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
					<Tag size={12} color="var(--blue)" /> distinct builds
				</p>
			</div>
			<!-- Row 2 — resource usage (avg big · median + max/min caption) -->
			<div class="metric-card space-y-1 rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Memory</h3>
				<p class="text-3xl font-bold tabular-nums text-[var(--text-bright)]">{fmtBytes(stats.mem.avg)}</p>
				<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
					<MemoryStick size={12} color="var(--memory-color)" /> med {fmtBytes(stats.mem.median)} · ↑{fmtBytes(stats.mem.max)} ↓{fmtBytes(stats.mem.min)}
				</p>
			</div>
			<div class="metric-card space-y-1 rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">CPU</h3>
				<p class="text-3xl font-bold tabular-nums text-[var(--text-bright)]">{stats.cpu.avg.toFixed(1)}%</p>
				<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
					<Cpu size={12} color="var(--cpu-color)" /> med {stats.cpu.median.toFixed(1)}% · ↑{stats.cpu.max.toFixed(1)}% ↓{stats.cpu.min.toFixed(1)}%
				</p>
			</div>
			<div class="metric-card space-y-1 rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Goroutines</h3>
				<p class="text-3xl font-bold tabular-nums text-[var(--text-bright)]">{Math.round(stats.gor.avg)}</p>
				<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]">
					<Workflow size={12} color="var(--orange)" /> med {stats.gor.median} · ↑{stats.gor.max} ↓{stats.gor.min}
				</p>
			</div>
		</div>
	</div>

	<!-- Group control (centered) -->
	<div class="flex justify-center pt-2">
		<TabSelector options={GROUP_OPTS} bind:value={groupBy} />
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
							class:pinned={pinned?.clusterId === a.clusterId}
							style="--cell:{group.color};width:{sideFor(a)}px;height:{sideFor(a)}px"
							onmouseenter={(e) => enter(e, a)}
							onmouseleave={leave}
							onclick={(e) => clickCell(e, a)}
							aria-label="{a.name} {a.version} {a.health}"
						></button>
					{/each}
				</div>
			</div>
		{/each}
	</div>
</div>

<svelte:window onkeydown={onKeydown} onclick={onWindowClick} />

{#if active}
	<div
		bind:this={tipEl}
		use:portal
		class="fleet-popover fixed z-[100] w-64 rounded-lg border border-[var(--border-color)] bg-[var(--bg-hard)] p-3 text-xs shadow-xl {pinned ? '' : 'pointer-events-none'}"
		style="left:{pos.left}px; top:{pos.top}px; visibility:{placed ? 'visible' : 'hidden'}"
	>
		<div class="mb-1 flex items-center justify-between gap-2">
			<span class="font-semibold text-[var(--text-bright)]">{active.name}</span>
			<div class="flex items-center gap-1.5">
				<span class="rounded px-1.5 py-0.5 text-[10px] uppercase tracking-wide" style="background:{HEALTH_BADGE[active.health]};color:var(--bg-hard)">{active.health}</span>
				{#if pinned}
					<button type="button" class="text-[var(--text-muted)] hover:text-[var(--text-bright)]" aria-label="Close" onclick={close}>
						<X size={14} />
					</button>
				{/if}
			</div>
		</div>
		<div class="flex flex-col gap-1">
			{#each [{ icon: Tag, color: 'var(--blue)', label: 'version', value: active.version }, { icon: Layers, color: 'var(--aqua)', label: 'environment', value: active.environment }, { icon: Clock, color: 'var(--green)', label: 'uptime', value: fmtUptime(active.uptimeSeconds) }, { icon: MemoryStick, color: 'var(--memory-color)', label: 'memory', value: fmtBytes(active.rssBytes) }, { icon: Cpu, color: 'var(--cpu-color)', label: 'cpu', value: active.cpuPct.toFixed(1) + '%' }, { icon: Workflow, color: 'var(--orange)', label: 'goroutines', value: String(active.goroutines) }] as row}
			<div class="flex items-center gap-2">
				<row.icon size={13} color={row.color} />
				<span class="text-[var(--text-muted)]">{row.label}</span>
				<span class="ml-auto tabular-nums text-[var(--text-secondary)]">{row.value}</span>
			</div>
			{/each}
		</div>
		{#if active.flapping}
			<div class="mt-1.5 text-[var(--orange)]">⚠ flapping — recent restarts</div>
		{/if}
		{#if pinned}
			<a
				href="/clusters/{active.clusterId}"
				class="mt-2.5 flex items-center justify-center gap-1.5 rounded-md border border-[var(--border-color)] bg-[var(--card-bg)] px-3 py-1.5 font-medium text-[var(--text-primary)] transition-colors hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
			>
				View cluster details
				<ArrowUpRight size={13} />
			</a>
		{:else}
			<div class="mt-2 text-center text-[10px] text-[var(--text-muted)]">click to pin · open cluster</div>
		{/if}
	</div>
{/if}

<style>
	.fleet-cell {
		background: var(--cell);
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
	.fleet-cell.is-stale {
		opacity: 0.5;
	}
	/* Dead drops its hue for a theme-neutral so it stays visible:
	   light/whitish in dark mode, grey in light mode. */
	.fleet-cell.is-dead {
		background: var(--fg1);
	}
	:global(html.light) .fleet-cell.is-dead {
		background: var(--gray);
	}
	.fleet-cell.flap {
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
		/* A ring in the section background so an expanded cell never blends
		   into same-coloured neighbours it overlaps — it stands out. */
		box-shadow: 0 0 0 2px var(--card-bg);
	}
	/* The pinned cell stays marked while its popover is open. */
	.fleet-cell.pinned {
		outline: 2px solid var(--accent);
		outline-offset: 1px;
		opacity: 1;
		z-index: 6;
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
