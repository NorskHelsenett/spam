<script lang="ts">
	export type DonutSegment = {
		label: string;
		value: number;
		color: string;
	};

	export let title = '';
	export let total = 0;
	export let segments: DonutSegment[] = [];

	let hoveredIndex: number | 'other' | null = null;
	let tooltipX = 0;
	let tooltipY = 0;

	const size = 156;
	const strokeWidth = 20;
	const radius = (size - strokeWidth) / 2;
	const circumference = 2 * Math.PI * radius;
	const center = size / 2;

	const clamp = (num: number, min: number, max: number) => Math.min(Math.max(num, min), max);

	const handleMouseMove = (e: MouseEvent) => {
		const rect = (e.currentTarget as SVGElement).getBoundingClientRect();
		tooltipX = e.clientX - rect.left;
		tooltipY = e.clientY - rect.top;
	};

	$: segmentTotal = segments.reduce((sum, s) => sum + s.value, 0);
	$: otherValue = total - segmentTotal;
	$: otherPercent = total > 0 ? (otherValue / total) * 100 : 0;

	$: segmentData = (() => {
		if (total <= 0 || segments.length === 0) {
			return [];
		}
		let cumulativePercent = 0;
		return segments.map((segment, index) => {
			const percent = clamp((segment.value / total) * 100, 0, 100);
			const offset = cumulativePercent;
			cumulativePercent += percent;
			return {
				...segment,
				index,
				percent,
				offset,
				dashArray: (percent / 100) * circumference,
				dashOffset: -(offset / 100) * circumference
			};
		});
	})();
</script>

<div class="rounded-2xl bg-[var(--card-bg)]/20">
	<div class="flex items-center justify-between">
		<p class="text-sm uppercase tracking-[0.22em] text-[var(--text-muted)]">{title}</p>
		<p class="text-xs text-[var(--text-tertiary)]">{total.toLocaleString()} components</p>
	</div>
	<div class="mt-3 flex flex-col gap-4 sm:flex-row sm:items-center">
		<div class="relative h-44 w-44 shrink-0">
			<svg
				viewBox="0 0 {size} {size}"
				class="h-44 w-44 -rotate-90 overflow-visible p-[1em]"
				on:mousemove={handleMouseMove}
				role="img"
				aria-label="Donut chart showing {title}"
			>
				{#if otherValue > 0}
				<circle
					cx={center}
					cy={center}
					r={radius}
					fill="none"
					stroke="var(--gray)"
					stroke-width={strokeWidth}
					opacity={hoveredIndex === 'other' ? 0.6 : 0.35}
					class="donut-segment transition-all duration-200 ease-out"
					class:hovered={hoveredIndex === 'other'}
					on:mouseenter={() => (hoveredIndex = 'other')}
					on:mouseleave={() => (hoveredIndex = null)}
					role="button"
					tabindex="0"
					aria-label="Other: {otherValue}"
				/>
			{:else}
				<circle
					cx={center}
					cy={center}
					r={radius}
					fill="none"
					stroke="var(--bg3)"
					stroke-width={strokeWidth}
					opacity="0.3"
				/>
			{/if}
				{#each segmentData as seg (seg.index)}
					<circle
						cx={center}
						cy={center}
						r={radius}
						fill="none"
						stroke={seg.color}
						stroke-width={strokeWidth}
						stroke-dasharray="{seg.dashArray} {circumference}"
						stroke-dashoffset={seg.dashOffset}
						class="donut-segment transition-all duration-200 ease-out"
						class:hovered={hoveredIndex === seg.index}
						style="transform-origin: {center}px {center}px;"
						on:mouseenter={() => (hoveredIndex = seg.index)}
						on:mouseleave={() => (hoveredIndex = null)}
						role="button"
						tabindex="0"
						aria-label="{seg.label}: {seg.value}"
					/>
				{/each}
			</svg>
			<div class="pointer-events-none absolute inset-0 grid place-items-center">
				<div class="grid h-20 w-20 place-items-center rounded-full bg-[var(--main-content-bg)]">
					<span class="text-lg font-semibold text-[var(--text-bright)]">{total}</span>
				</div>
			</div>
			{#if hoveredIndex !== null}
				<div
					class="pointer-events-none absolute z-10 whitespace-nowrap rounded-lg border border-[var(--border-color)] bg-[var(--card-bg)] px-3 py-2 text-[10px] uppercase tracking-[0.2em] text-[var(--text-muted)] shadow-xl"
					style="left: {tooltipX + 16}px; top: {tooltipY - 24}px; transform: translateX(-50%);"
				>
					{#if hoveredIndex === 'other'}
						<span class="inline-block h-2 w-2 rounded-full mr-1.5 bg-[var(--gray)]"></span>
						Other · {otherValue}
						<span class="text-[var(--text-tertiary)]">({otherPercent.toFixed(1)}%)</span>
					{:else if segmentData[hoveredIndex]}
						<span class="inline-block h-2 w-2 rounded-full mr-1.5" style="background: {segmentData[hoveredIndex].color}"></span>
						{segmentData[hoveredIndex].label} · {segmentData[hoveredIndex].value}
						<span class="text-[var(--text-tertiary)]">({segmentData[hoveredIndex].percent.toFixed(1)}%)</span>
					{/if}
				</div>
			{/if}
		</div>
		<div class="flex-1 space-y-2">
			{#each segmentData as seg (seg.index)}
				<button
					type="button"
					class="flex w-full items-center justify-between rounded-xl px-3 py-2 text-left text-xs text-[var(--text-tertiary)] transition"
					class:bg-[var(--hover-bg)]={hoveredIndex === seg.index}
					class:bg-[var(--card-bg)]={hoveredIndex !== seg.index}
					on:mouseenter={() => (hoveredIndex = seg.index)}
					on:mouseleave={() => (hoveredIndex = null)}
				>
					<span class="inline-flex items-center gap-2">
						<span class="h-2.5 w-2.5 rounded-full" style="background: {seg.color}"></span>
						{seg.label}
					</span>
					<span class="text-[var(--text-bright)]">{seg.value}</span>
				</button>
			{/each}
		</div>
	</div>
</div>

<style>
	.donut-segment {
		cursor: pointer;
	}
	.donut-segment.hovered {
		stroke-width: 22;
		filter: brightness(1.15);
	}
</style>
