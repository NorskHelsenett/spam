<script lang="ts">
	import ChevronDown from 'lucide-svelte/icons/chevron-down';

	export type SelectOption = {
		value: string;
		label: string;
		disabled?: boolean;
	};

	interface Props {
		value: string;
		options: SelectOption[];
		disabled?: boolean;
	}

	let { value = $bindable(''), options = [], disabled = false }: Props = $props();
	let open = $state(false);

	const selectedOption = $derived(options.find((option) => option.value === value) ?? options[0]);

	const toggleOpen = () => {
		if (!disabled) {
			open = !open;
		}
	};

	const setValue = (option: SelectOption) => {
		if (disabled || option.disabled) return;
		value = option.value;
		open = false;
	};

	const handleFocusOut = (event: FocusEvent) => {
		const nextTarget = event.relatedTarget as Node | null;
		if (!nextTarget || !event.currentTarget.contains(nextTarget)) {
			open = false;
		}
	};
</script>

<div
	class="select"
	class:open
	class:disabled
	tabindex={disabled ? undefined : 0}
	on:focusout={handleFocusOut}
>
	<button
		type="button"
		class="select-button"
		disabled={disabled}
		aria-haspopup="listbox"
		aria-expanded={open}
		on:click={toggleOpen}
	>
		<span>{selectedOption?.label ?? 'Select'}</span>
		<ChevronDown class="select-caret" aria-hidden="true" />
	</button>
	<div class="select-menu" role="listbox">
		{#each options as option}
			<button
				type="button"
				class="select-option"
				class:is-active={option.value === value}
				class:is-disabled={option.disabled}
				disabled={option.disabled}
				role="option"
				aria-selected={option.value === value}
				on:click={() => setValue(option)}
			>
				<span>{option.label}</span>
				{#if option.value === value}
					<span class="select-check" aria-hidden="true">●</span>
				{/if}
			</button>
		{/each}
	</div>
</div>

<style>
	.select {
		position: relative;
	}

	.select-button {
		width: 100%;
		height: 37px;
		border-radius: 999px;
		border: 1px solid var(--border-color);
		background: var(--card-bg);
		padding: 0 1rem;
		font-size: 0.9rem;
		color: var(--text-secondary);
		display: inline-flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.5rem;
		transition: border-color 150ms ease, box-shadow 150ms ease;
		cursor: pointer;
	}

	.select-button:focus-visible {
		outline: none;
		border-color: var(--accent);
		box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 30%, transparent);
	}

	.select-caret {
		width: 14px;
		height: 14px;
		color: var(--text-tertiary);
		transition: transform 150ms ease;
	}

	.select.open .select-caret {
		transform: rotate(180deg);
	}

	.select-menu {
		position: absolute;
		top: calc(100% + 8px);
		left: 0;
		right: 0;
		background: var(--card-bg);
		border: 1px solid var(--border-color);
		border-radius: 1rem;
		padding: 0.4rem;
		box-shadow: 0 16px 40px rgba(0, 0, 0, 0.25);
		max-height: 0;
		opacity: 0;
		transform: translateY(-8px);
		overflow: hidden;
		pointer-events: none;
		transition: max-height 200ms ease, opacity 200ms ease, transform 200ms ease;
		z-index: 20;
	}

	.select.open .select-menu {
		max-height: 220px;
		opacity: 1;
		transform: translateY(0);
		pointer-events: auto;
	}

	.select-option {
		width: 100%;
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.5rem;
		padding: 0.55rem 0.8rem;
		border-radius: 0.75rem;
		font-size: 0.85rem;
		color: var(--text-secondary);
		background: transparent;
		transition: background 150ms ease, color 150ms ease;
		cursor: pointer;
	}

	.select-option:hover {
		background: var(--hover-bg-subtle);
		color: var(--text-bright);
	}

	.select-option.is-active {
		background: color-mix(in srgb, var(--accent) 16%, transparent);
		color: var(--text-bright);
	}

	.select-option.is-disabled {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.select-check {
		color: var(--accent);
		font-size: 0.7rem;
	}

	.select.disabled .select-button {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.select.disabled .select-menu {
		pointer-events: none;
	}
</style>
