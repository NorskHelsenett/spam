<script lang="ts">
	export type ButtonGroupOption = {
		value: string;
		label: string;
		disabled?: boolean;
	};

	interface Props {
		value: string;
		options: ButtonGroupOption[];
		disabled?: boolean;
		size?: 'sm' | 'md';
		onchange?: (value: string) => void;
	}

	let {
		value = $bindable(''),
		options = [],
		disabled = false,
		size = 'md',
		onchange
	}: Props = $props();

	const activeIndex = $derived(Math.max(0, options.findIndex((o) => o.value === value)));

	const select = (option: ButtonGroupOption) => {
		if (disabled || option.disabled) return;
		value = option.value;
		onchange?.(option.value);
	};
</script>

<div
	class="button-group"
	class:disabled
	class:sm={size === 'sm'}
	role="radiogroup"
	style={`--count: ${options.length}; --index: ${activeIndex};`}
>
	<span class="indicator" aria-hidden="true"></span>
	{#each options as option}
		<button
			type="button"
			class="option"
			class:is-active={option.value === value}
			class:is-disabled={option.disabled}
			disabled={disabled || option.disabled}
			role="radio"
			aria-checked={option.value === value}
			onclick={() => select(option)}
		>
			{option.label}
		</button>
	{/each}
</div>

<style>
	.button-group {
		--count: 1;
		--index: 0;
		position: relative;
		display: inline-grid;
		grid-template-columns: repeat(var(--count), minmax(0, 1fr));
		gap: 0;
		padding: 3px;
		border: 1px solid var(--border-color);
		border-radius: 999px;
		background: color-mix(in srgb, var(--card-bg) 60%, transparent);
	}

	.indicator {
		position: absolute;
		inset: 3px;
		width: calc((100% - 6px) / var(--count));
		border-radius: 999px;
		background: var(--accent);
		transform: translateX(calc(var(--index) * 100%));
		transition: transform 220ms ease;
		pointer-events: none;
	}

	.option {
		position: relative;
		z-index: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 0.4rem 0.8rem;
		font-size: 0.8rem;
		color: var(--text-secondary);
		background: transparent;
		border: none;
		cursor: pointer;
		user-select: none;
		white-space: nowrap;
		transition: color 200ms ease;
	}

	.option.is-active {
		color: var(--main-content-bg);
	}

	.option:hover:not(.is-active):not(.is-disabled) {
		color: var(--text-bright);
	}

	.option.is-disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.button-group.disabled .option {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.button-group.sm {
		padding: 2px;
	}

	.button-group.sm .indicator {
		inset: 2px;
		width: calc((100% - 4px) / var(--count));
	}

	.button-group.sm .option {
		padding: 0.25rem 0.55rem;
		font-size: 0.65rem;
		letter-spacing: 0.04em;
	}
</style>
