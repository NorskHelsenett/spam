<script lang="ts">
	import { tick } from 'svelte';
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
		size?: 'sm' | 'md';
		class?: string;
		onchange?: (value: string) => void;
	}

	let { value = $bindable(''), options = [], disabled = false, size = 'md', class: className = '', onchange }: Props = $props();
	let open = $state(false);
	let wrapperEl: HTMLDivElement | undefined = $state();
	let menuEl: HTMLDivElement | undefined = $state();

	const selectedOption = $derived(options.find((option) => option.value === value) ?? options[0]);
	const sizeClass = $derived(size === 'sm' ? 'select-sm' : '');

	function positionMenu() {
		if (!wrapperEl || !menuEl) return;
		const rect = wrapperEl.getBoundingClientRect();
		const spaceBelow = window.innerHeight - rect.bottom;
		const openAbove = spaceBelow < 200;

		menuEl.style.left = `${rect.left}px`;
		menuEl.style.minWidth = `${rect.width}px`;
		if (openAbove) {
			menuEl.style.top = 'auto';
			menuEl.style.bottom = `${window.innerHeight - rect.top + 4}px`;
		} else {
			menuEl.style.bottom = 'auto';
			menuEl.style.top = `${rect.bottom + 4}px`;
		}
	}

	async function toggleOpen() {
		if (disabled) return;
		open = !open;
		if (open) {
			await tick();
			positionMenu();
		}
	}

	function setValue(option: SelectOption) {
		if (disabled || option.disabled) return;
		value = option.value;
		open = false;
		onchange?.(option.value);
	}

	function portal(node: HTMLElement) {
		document.body.appendChild(node);

		const handleClick = (e: MouseEvent) => {
			if (!node.contains(e.target as Node) && !wrapperEl?.contains(e.target as Node)) {
				open = false;
			}
		};

		const handleScroll = () => {
			if (open) positionMenu();
		};

		document.addEventListener('click', handleClick, true);
		window.addEventListener('scroll', handleScroll, true);

		return {
			destroy() {
				document.removeEventListener('click', handleClick, true);
				window.removeEventListener('scroll', handleScroll, true);
				node.remove();
			}
		};
	}
</script>

<div
	bind:this={wrapperEl}
	class="select {sizeClass} {className}"
	class:open
	class:disabled
>
	<button
		type="button"
		class="select-button"
		disabled={disabled}
		aria-haspopup="listbox"
		aria-expanded={open}
		onclick={toggleOpen}
	>
		<span class="select-label">
			<span class="select-sizer" aria-hidden="true">
				{#each options as option}
					<span>{option.label}</span>
				{/each}
			</span>
			<span class="select-value">{selectedOption?.label ?? 'Select'}</span>
		</span>
		<ChevronDown class="select-caret" aria-hidden="true" />
	</button>
</div>

{#if open}
	<div bind:this={menuEl} use:portal class="select-menu {sizeClass}" role="listbox">
		{#each options as option}
			<button
				type="button"
				class="select-option"
				class:is-active={option.value === value}
				class:is-disabled={option.disabled}
				disabled={option.disabled}
				role="option"
				aria-selected={option.value === value}
				onclick={() => setValue(option)}
			>
				<span>{option.label}</span>
				{#if option.value === value}
					<span class="select-check" aria-hidden="true">●</span>
				{/if}
			</button>
		{/each}
	</div>
{/if}

<style>
	.select {
		position: relative;
		display: inline-block;
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
		white-space: nowrap;
		transition: border-color 150ms ease, box-shadow 150ms ease;
		cursor: pointer;
	}

	.select-button:focus-visible {
		outline: none;
		border-color: var(--accent);
		box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 30%, transparent);
	}

	.select-label {
		position: relative;
		display: inline-grid;
	}

	.select-sizer {
		grid-area: 1 / 1;
		visibility: hidden;
		display: grid;
	}

	.select-sizer > span {
		grid-area: 1 / 1;
	}

	.select-value {
		grid-area: 1 / 1;
	}

	.select :global(.select-caret) {
		width: 14px;
		height: 14px;
		color: var(--text-tertiary);
		transition: transform 150ms ease;
		transform-origin: center;
		flex-shrink: 0;
	}

	.select.open :global(.select-caret) {
		transform: rotate(180deg);
	}

	:global(.select-menu) {
		position: fixed;
		background: var(--card-bg);
		border: 1px solid var(--border-color);
		border-radius: 1rem;
		padding: 0.4rem;
		box-shadow: 0 16px 40px rgba(0, 0, 0, 0.25);
		z-index: 9999;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	:global(.select-option) {
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
		white-space: nowrap;
		transition: background 150ms ease, color 150ms ease;
		cursor: pointer;
		border: none;
	}

	:global(.select-option:hover) {
		background: var(--hover-bg-subtle);
		color: var(--text-bright);
	}

	:global(.select-option.is-active) {
		background: color-mix(in srgb, var(--accent) 16%, transparent);
		color: var(--text-bright);
	}

	:global(.select-option.is-disabled) {
		opacity: 0.6;
		cursor: not-allowed;
	}

	:global(.select-check) {
		color: var(--accent);
		font-size: 0.7rem;
	}

	.select-sm .select-button {
		height: 28px;
		padding: 0 0.6rem;
		font-size: 0.75rem;
	}

	.select-sm :global(.select-caret) {
		width: 12px;
		height: 12px;
	}

	:global(.select-sm.select-menu .select-option) {
		padding: 0.4rem 0.6rem;
		font-size: 0.75rem;
	}

	.select.disabled .select-button {
		opacity: 0.6;
		cursor: not-allowed;
	}
</style>
