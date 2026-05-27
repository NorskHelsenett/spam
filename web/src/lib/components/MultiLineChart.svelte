<script lang="ts">
	import { browser } from '$app/environment';

	export type MultiSeries = { key: string; label: string; color: string };
	// Each point must have a `date` string plus numeric values keyed by series key
	export type MultiPoint = { date: string } & Record<string, number>;

	export let data: MultiPoint[] = [];
	export let series: MultiSeries[] = [];
	export let title = 'Trend';

	let container: HTMLDivElement;
	let W = 480;
	const H = 180;
	const PAD = { top: 16, right: 16, bottom: 36, left: 44 };

	$: chartW = W - PAD.left - PAD.right;
	const chartH = H - PAD.top - PAD.bottom;

	let hoveredIndex: number | null = null;
	let tooltipX = 0;
	let tooltipY = 0;
	let tooltipW = 0;

	$: if (container) {
		W = Math.max(480, container.clientWidth);
	}

	const handleResize = () => {
		if (!browser) return;
		W = Math.max(480, container?.clientWidth ?? 480);
	};

	$: maxVal = data.length === 0 ? 1 : Math.max(
		1,
		...data.flatMap((d) => series.map((s) => (d[s.key] as number) ?? 0))
	);

	const getX = (i: number, len: number, cw: number) =>
		len <= 1 ? PAD.left + cw / 2 : PAD.left + (i / (len - 1)) * cw;

	const getY = (v: number, max: number) => PAD.top + chartH - (v / max) * chartH;

	$: xPositions = data.map((_, i) => getX(i, data.length, chartW));

	const buildPath = (pts: { x: number; y: number }[]) => {
		if (pts.length === 0) return '';
		if (pts.length === 1) return `M${pts[0].x.toFixed(1)},${pts[0].y.toFixed(1)}`;
		const n = pts.length;
		const dx: number[] = [];
		const dy: number[] = [];
		const m: number[] = [];
		for (let i = 0; i < n - 1; i++) {
			dx.push(pts[i + 1].x - pts[i].x);
			dy.push(pts[i + 1].y - pts[i].y);
			m.push(dy[i] / dx[i]);
		}
		const tangents: number[] = [m[0]];
		for (let i = 1; i < n - 1; i++) {
			if (m[i - 1] * m[i] <= 0) tangents.push(0);
			else tangents.push(2 / (1 / m[i - 1] + 1 / m[i]));
		}
		tangents.push(m[n - 2]);
		let d2 = `M${pts[0].x.toFixed(1)},${pts[0].y.toFixed(1)}`;
		for (let i = 0; i < n - 1; i++) {
			const seg = dx[i] / 3;
			d2 += ` C${(pts[i].x + seg).toFixed(1)},${(pts[i].y + tangents[i] * seg).toFixed(1)} ${(pts[i + 1].x - seg).toFixed(1)},${(pts[i + 1].y - tangents[i + 1] * seg).toFixed(1)} ${pts[i + 1].x.toFixed(1)},${pts[i + 1].y.toFixed(1)}`;
		}
		return d2;
	};

	$: paths = (() => {
		const result: Record<string, string> = {};
		for (const s of series) {
			if (data.length === 0) { result[s.key] = ''; continue; }
			const pts = data.map((d, i) => ({ x: xPositions[i], y: getY((d[s.key] as number) ?? 0, maxVal) }));
			result[s.key] = buildPath(pts);
		}
		return result;
	})();

	const formatShortDate = (date: string) => {
		const [year, month, day] = date.split('-').map(Number);
		if (!year || !month || !day) return date;
		return `${day}.${month}`;
	};

	$: labelStep = data.length <= 7 ? 1 : data.length <= 14 ? 2 : 7;

	$: xLabelList = data
		.filter((_, i) => i % labelStep === 0 || i === data.length - 1)
		.map((d) => ({ label: formatShortDate(d.date), index: data.indexOf(d) }));

	const handleMouseMove = (e: MouseEvent) => {
		const svg = e.currentTarget as SVGElement;
		const rect = svg.getBoundingClientRect();
		const mx = e.clientX - rect.left - PAD.left;
		if (data.length === 0) return;
		const idx = Math.round((mx / chartW) * (data.length - 1));
		hoveredIndex = Math.max(0, Math.min(data.length - 1, idx));
		tooltipX = e.clientX - rect.left;
		tooltipY = e.clientY - rect.top;
	};
</script>

<div class="rounded-2xl">
	<p class="mb-4 text-sm uppercase tracking-[0.22em] text-[var(--text-muted)]">{title}</p>

	{#if data.length === 0}
		<div class="flex h-32 items-center justify-center text-xs text-[var(--text-tertiary)]">
			No scan data yet
		</div>
	{:else}
		<div class="relative" bind:this={container}>
			<svg
				viewBox="0 0 {W} {H}"
				width="100%"
				style="display: block; height: {H}px;"
				on:mousemove={handleMouseMove}
				on:mouseleave={() => (hoveredIndex = null)}
				role="img"
				aria-label="Secrets trend chart"
			>
				<!-- Y-axis gridlines -->
				{#each [0, 0.25, 0.5, 0.75, 1] as frac (frac)}
					{@const y = PAD.top + chartH * (1 - frac)}
					<line
						x1={PAD.left}
						y1={y}
						x2={PAD.left + chartW}
						y2={y}
						stroke="var(--border-color)"
						stroke-width="0.5"
						opacity="0.4"
					/>
					<text
						x={PAD.left - 6}
						y={y + 4}
						text-anchor="end"
						font-size="9"
						fill="var(--text-tertiary)"
					>{Math.round(maxVal * frac)}</text>
				{/each}

				<!-- Series lines -->
				{#each series as s (s.key)}
					<path
						d={paths[s.key]}
						fill="none"
						stroke={s.color}
						stroke-width="1.8"
						stroke-linejoin="round"
						stroke-linecap="round"
					/>
				{/each}

				{#if data.length === 1}
					{#each series as s (s.key)}
						<circle
							cx={xPositions[0]}
							cy={getY((data[0][s.key] as number) ?? 0, maxVal)}
							r="4"
							fill={s.color}
						/>
					{/each}
				{/if}

				<!-- Hover crosshair -->
				{#if hoveredIndex !== null}
					<line
						x1={xPositions[hoveredIndex]}
						y1={PAD.top}
						x2={xPositions[hoveredIndex]}
						y2={PAD.top + chartH}
						stroke="var(--text-tertiary)"
						stroke-width="1"
						stroke-dasharray="3 3"
					/>
					{#each series as s (s.key)}
						<circle
							cx={xPositions[hoveredIndex]}
							cy={getY((data[hoveredIndex][s.key] as number) ?? 0, maxVal)}
							r="3"
							fill={s.color}
						/>
					{/each}
				{/if}

				<!-- X axis labels -->
				{#each xLabelList as lbl (lbl.index)}
					<text
						x={xPositions[lbl.index]}
						y={H - 6}
						text-anchor="middle"
						font-size="9"
						fill="var(--text-tertiary)"
					>{lbl.label}</text>
				{/each}
			</svg>

			<!-- Tooltip -->
			{#if hoveredIndex !== null}
				{@const d = data[hoveredIndex]}
				{@const offset = 12}
				{@const margin = 16}
				{@const chartRightEdge = PAD.left + chartW}
				{@const idealLeft = tooltipX + offset}
				{@const constrainedLeft = Math.max(PAD.left + margin, Math.min(idealLeft, chartRightEdge - tooltipW - margin))}
				<div
					bind:clientWidth={tooltipW}
					class="pointer-events-none absolute z-20 whitespace-nowrap space-y-1 rounded-lg border border-[var(--border-color)] bg-[var(--card-bg)] px-3 py-2 text-[10px] shadow-xl"
					style="left: {constrainedLeft}px; top: {Math.max(0, tooltipY - 80)}px;"
				>
					{#each series as s (s.key)}
						<div class="flex items-center justify-between gap-2">
							<span class="flex items-center gap-1.5">
								<span class="h-1.5 w-1.5 rounded-full" style="background:{s.color}"></span>
								<span class="text-[var(--text-tertiary)]">{s.label}</span>
							</span>
							<span class="font-medium text-[var(--text-bright)]">{(d[s.key] as number) ?? 0}</span>
						</div>
					{/each}
				</div>
			{/if}
		</div>

		<!-- Legend -->
		<div class="mt-3 flex flex-wrap gap-x-4 gap-y-1">
			{#each series as s (s.key)}
				<span class="flex items-center gap-1.5 text-[10px] text-[var(--text-tertiary)]">
					<span class="h-2 w-6 rounded-full" style="background:{s.color}; opacity:0.85"></span>
					{s.label}
				</span>
			{/each}
		</div>
	{/if}
</div>

<svelte:window on:resize={handleResize} />
