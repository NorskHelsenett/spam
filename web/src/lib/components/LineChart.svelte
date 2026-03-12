<script lang="ts">
	type TrendKey = 'critical' | 'high' | 'medium' | 'low';

	type TrendPoint = {
		date: string;
		critical: number;
		high: number;
		medium: number;
		low: number;
	};

	export let data: TrendPoint[] = [];
	export let title = 'Trend';

	const W = 480;
	const H = 180;
	const PAD = { top: 16, right: 16, bottom: 36, left: 44 };

	const chartW = W - PAD.left - PAD.right;
	const chartH = H - PAD.top - PAD.bottom;

	const series: { key: TrendKey; label: string; color: string }[] = [
		{ key: 'critical', label: 'Critical', color: 'var(--red)' },
		{ key: 'high', label: 'High', color: 'var(--orange)' },
		{ key: 'medium', label: 'Medium', color: 'var(--yellow)' },
		{ key: 'low', label: 'Low', color: 'var(--blue)' }
	];

	let hoveredIndex: number | null = null;
	let tooltipX = 0;
	let tooltipY = 0;

	$: maxVal = data.length === 0 ? 1 : Math.max(
		1,
		...data.flatMap((d) => [d.critical, d.high, d.medium, d.low])
	);

	const xPos = (i: number) =>
		data.length <= 1 ? PAD.left + chartW / 2 : PAD.left + (i / (data.length - 1)) * chartW;

	const yPos = (v: number) => PAD.top + chartH - (v / maxVal) * chartH;

	const makePath = (key: TrendKey) => {
		if (data.length === 0) return '';
		return data
			.map((d, i) => `${i === 0 ? 'M' : 'L'}${xPos(i).toFixed(1)},${yPos(d[key]).toFixed(1)}`)
			.join(' ');
	};

	const formatShortDate = (date: string) => {
		const [year, month, day] = date.split('-').map(Number);
		if (!year || !month || !day) return date;
		return `${day}.${month}`;
	};

	const xLabels = (step: number) =>
		data
			.filter((_, i) => i % step === 0 || i === data.length - 1)
			.map((d) => ({ label: formatShortDate(d.date), index: data.indexOf(d) }));

	$: labelStep = data.length <= 7 ? 1 : data.length <= 14 ? 2 : 7;

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

<div class="rounded-2xl bg-[var(--card-bg)]/20">
	<p class="text-sm uppercase tracking-[0.22em] text-[var(--text-muted)] mb-4">{title}</p>

	{#if data.length === 0}
		<div class="flex h-32 items-center justify-center text-[var(--text-tertiary)] text-xs">
			No scan data yet
		</div>
	{:else}
		<div class="relative">
			<svg
				viewBox="0 0 {W} {H}"
				width="100%"
				preserveAspectRatio="none"
				style="display: block; height: {H}px;"
				on:mousemove={handleMouseMove}
				on:mouseleave={() => (hoveredIndex = null)}
				role="img"
				aria-label="Vulnerability trend chart"
			>
				<!-- Y-axis gridlines -->
				{#each [0, 0.25, 0.5, 0.75, 1] as frac}
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
				{#each series as s}
					<path
						d={makePath(s.key)}
						fill="none"
						stroke={s.color}
						stroke-width="1.8"
						stroke-linejoin="round"
						stroke-linecap="round"
					/>
				{/each}

				{#if data.length === 1}
					{#each series as s}
						<circle
							cx={xPos(0)}
							cy={yPos(data[0][s.key])}
							r="4"
							fill={s.color}
						/>
					{/each}
				{/if}

				<!-- Hover crosshair -->
				{#if hoveredIndex !== null}
					<line
						x1={xPos(hoveredIndex)}
						y1={PAD.top}
						x2={xPos(hoveredIndex)}
						y2={PAD.top + chartH}
						stroke="var(--text-tertiary)"
						stroke-width="1"
						stroke-dasharray="3 3"
					/>
					{#each series as s}
						<circle
							cx={xPos(hoveredIndex)}
							cy={yPos(data[hoveredIndex][s.key])}
							r="3"
							fill={s.color}
						/>
					{/each}
				{/if}

				<!-- X axis labels -->
				{#each xLabels(labelStep) as lbl}
					<text
						x={xPos(lbl.index)}
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
				<div
					class="pointer-events-none absolute z-20 rounded-lg border border-[var(--border-color)] bg-[var(--card-bg)] px-3 py-2 text-[10px] shadow-xl space-y-1"
					style="left: {tooltipX + 12}px; top: {Math.max(0, tooltipY - 80)}px;"
				>
					<p class="uppercase tracking-widest text-[var(--text-muted)] mb-1">{formatShortDate(d.date)}</p>
					{#each series as s}
						<div class="flex items-center gap-2 justify-between">
							<span class="flex items-center gap-1.5">
								<span class="h-1.5 w-1.5 rounded-full" style="background:{s.color}"></span>
								<span class="text-[var(--text-tertiary)]">{s.label}</span>
							</span>
							<span class="text-[var(--text-bright)] font-medium">{d[s.key]}</span>
						</div>
					{/each}
				</div>
			{/if}
		</div>

		<!-- Legend -->
		<div class="mt-3 flex flex-wrap gap-x-4 gap-y-1">
			{#each series as s}
				<span class="flex items-center gap-1.5 text-[10px] text-[var(--text-tertiary)]">
					<span class="h-2 w-6 rounded-full" style="background:{s.color}; opacity:0.85"></span>
					{s.label}
				</span>
			{/each}
		</div>
	{/if}
</div>
