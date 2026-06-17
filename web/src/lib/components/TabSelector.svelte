<script lang="ts">
	export type TabOption = {
		value: string;
		label: string;
		badge?: number;
	};

	export let options: TabOption[] = [];
	export let value: string = '';
	export let onchange: ((value: string) => void) | undefined = undefined;
	export let showLines: boolean = true;

	// -1 when the current value isn't in this selector's options (e.g.
	// two selectors sharing one selection); the indicator hides instead
	// of falsely parking on the first tab.
	$: activeIndex = options.findIndex((option) => option.value === value);
</script>

<div class="tab-selector">
	{#if showLines}
		<span class="side-line" aria-hidden="true"></span>
	{/if}
	<div class="tabs" style={`--tab-count: ${options.length}; --tab-index: ${Math.max(0, activeIndex)};`}>
		{#if activeIndex >= 0}
			<span class="indicator" aria-hidden="true"></span>
		{/if}
		{#each options as option}
			<label class={`tab ${option.value === value ? 'is-active' : ''}`}>
				<input
					class="sr-only"
					type="radio"
					bind:group={value}
					value={option.value}
					on:change={() => onchange?.(option.value)}
				/>
				<span>{option.label}</span>
				{#if option.badge}
					<span class="badge-chip">{option.badge > 99 ? '99+' : option.badge}</span>
				{/if}
			</label>
		{/each}
	</div>
	{#if showLines}
		<span class="side-line" aria-hidden="true"></span>
	{/if}
</div>

<style>
	.tab-selector {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 16px;
	}

	.side-line {
		display: inline-block;
		width: clamp(40px, 18vw, 160px);
		height: 1px;
		background: var(--border-color);
		opacity: 0.7;
	}

	.tabs {
		--tab-count: 1;
		--tab-index: 0;
		position: relative;
		display: grid;
		grid-template-columns: repeat(var(--tab-count), 1fr);
		min-width: max-content;
		gap: 6px;
		padding: 4px;
		border: 1px solid var(--border-color);
		border-radius: 999px;
		background: color-mix(in srgb, var(--main-content-bg) 68%, transparent);
		box-shadow: inset 0 1px 1px rgb(0 0 0 / 0.06);
		font-size: 10px;
		letter-spacing: 0.18em;
		text-transform: uppercase;
	}

	.indicator {
		position: absolute;
		top: 4px;
		bottom: 4px;
		left: 4px;
		width: calc((100% - 8px) / var(--tab-count));
		border-radius: 999px;
		background: var(--accent);
		box-shadow: 0 1px 2px rgb(0 0 0 / 0.28);
		transform: translateX(calc(var(--tab-index) * 100%));
		transition: transform 220ms ease, width 220ms ease;
	}

	.tab {
		position: relative;
		z-index: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 6px 14px;
		color: var(--text-secondary);
		cursor: pointer;
		user-select: none;
		white-space: nowrap;
		transition: color 200ms ease;
	}

	.tab.is-active {
		color: var(--main-content-bg);
	}

	.badge-chip {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 16px;
		height: 16px;
		margin-left: 6px;
		padding: 0 4px;
		border-radius: 999px;
		font-size: 9px;
		font-weight: 700;
		letter-spacing: 0;
		background: var(--accent);
		color: var(--main-content-bg);
		transition: background 200ms ease, color 200ms ease;
	}

	.tab.is-active .badge-chip {
		background: var(--main-content-bg);
		color: var(--accent);
	}
</style>
