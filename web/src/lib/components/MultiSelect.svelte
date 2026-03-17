<script lang="ts">
	import { tick } from 'svelte';
	import ChevronDown from 'lucide-svelte/icons/chevron-down';
	import X from 'lucide-svelte/icons/x';

	export type MultiSelectOption = {
		value: string;
		label: string;
		disabled?: boolean;
	};

	interface Props {
		selected: string[];
		options: MultiSelectOption[];
		placeholder?: string;
		disabled?: boolean;
		size?: 'sm' | 'md';
		class?: string;
		onchange?: (selected: string[]) => void;
	}

	let {
		selected = $bindable([]),
		options = [],
		placeholder = 'Select…',
		disabled = false,
		size = 'md',
		class: className = '',
		onchange
	}: Props = $props();

	let open = $state(false);
	let wrapperEl: HTMLDivElement | undefined = $state();
	let menuEl: HTMLDivElement | undefined = $state();

	const selectedLabels = $derived(
		selected
			.map((v) => options.find((o) => o.value === v)?.label)
			.filter(Boolean)
	);
	const allSelected = $derived(selected.length === options.filter((o) => !o.disabled).length);
	const sizeClass = $derived(size === 'sm' ? 'ms-sm' : '');

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

	function toggleOption(option: MultiSelectOption) {
		if (disabled || option.disabled) return;
		if (selected.includes(option.value)) {
			selected = selected.filter((v) => v !== option.value);
		} else {
			selected = [...selected, option.value];
		}
		onchange?.(selected);
	}

	function toggleAll() {
		if (disabled) return;
		if (allSelected) {
			selected = [];
		} else {
			selected = options.filter((o) => !o.disabled).map((o) => o.value);
		}
		onchange?.(selected);
	}

	function removeTag(value: string) {
		selected = selected.filter((v) => v !== value);
		onchange?.(selected);
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
	class="ms {sizeClass} {className}"
	class:open
	class:disabled
>
	<button
		type="button"
		class="ms-button"
		disabled={disabled}
		aria-haspopup="listbox"
		aria-expanded={open}
		onclick={toggleOpen}
	>
		<span class="ms-label">
			{#if selected.length === 0}
				<span class="ms-placeholder">{placeholder}</span>
			{:else if selected.length <= 2}
				<span class="ms-tags">
					{#each selectedLabels as label, i}
						<span class="ms-tag">
							{label}
							<button
								type="button"
								class="ms-tag-x"
								onclick={(e: MouseEvent) => { e.stopPropagation(); removeTag(selected[i]); }}
								aria-label="Remove {label}"
							>
								<X size={10} />
							</button>
						</span>
					{/each}
				</span>
			{:else}
				<span class="ms-count">{selected.length} selected</span>
			{/if}
		</span>
		<ChevronDown class="ms-caret" aria-hidden="true" />
	</button>
</div>

{#if open}
	<div bind:this={menuEl} use:portal class="ms-menu {sizeClass}" role="listbox" aria-multiselectable="true">
		<button
			type="button"
			class="ms-option ms-option-all"
			role="option"
			aria-selected={allSelected}
			onclick={toggleAll}
		>
			<span>Select all</span>
			{#if allSelected}
				<span class="ms-dot" aria-hidden="true">●</span>
			{/if}
		</button>
		<div class="ms-divider"></div>
		{#each options as option}
			<button
				type="button"
				class="ms-option"
				class:is-active={selected.includes(option.value)}
				class:is-disabled={option.disabled}
				disabled={option.disabled}
				role="option"
				aria-selected={selected.includes(option.value)}
				onclick={() => toggleOption(option)}
			>
				<span>{option.label}</span>
				{#if selected.includes(option.value)}
					<span class="ms-dot" aria-hidden="true">●</span>
				{/if}
			</button>
		{/each}
	</div>
{/if}

<style>
	.ms {
		position: relative;
		display: inline-block;
	}

	.ms-button {
		width: 100%;
		min-height: 37px;
		border-radius: 999px;
		border: 1px solid var(--border-color);
		background: var(--card-bg);
		padding: 0.35rem 0.75rem 0.35rem 0.85rem;
		font-size: 0.85rem;
		color: var(--text-secondary);
		display: inline-flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.5rem;
		white-space: nowrap;
		transition: border-color 150ms ease, box-shadow 150ms ease;
		cursor: pointer;
	}

	.ms-button:focus-visible {
		outline: none;
		border-color: var(--accent);
		box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 30%, transparent);
	}

	.ms-placeholder {
		color: var(--text-muted);
	}

	.ms-label {
		display: inline-flex;
		align-items: center;
		min-width: 0;
		overflow: hidden;
	}

	.ms-tags {
		display: inline-flex;
		align-items: center;
		gap: 0.3rem;
		flex-wrap: nowrap;
		overflow: hidden;
	}

	.ms-tag {
		display: inline-flex;
		align-items: center;
		gap: 0.25rem;
		padding: 0.1rem 0.45rem;
		border-radius: 999px;
		background: color-mix(in srgb, var(--accent) 16%, transparent);
		color: var(--text-bright);
		font-size: 0.75rem;
		white-space: nowrap;
	}

	.ms-tag-x {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		border: none;
		background: transparent;
		color: var(--text-tertiary);
		cursor: pointer;
		padding: 0;
		border-radius: 50%;
		transition: color 120ms ease;
	}

	.ms-tag-x:hover {
		color: var(--text-bright);
	}

	.ms-count {
		color: var(--text-secondary);
		font-size: 0.85rem;
	}

	.ms :global(.ms-caret) {
		width: 14px;
		height: 14px;
		color: var(--text-tertiary);
		transition: transform 150ms ease;
		transform-origin: center;
		flex-shrink: 0;
	}

	.ms.open :global(.ms-caret) {
		transform: rotate(180deg);
	}

	:global(.ms-menu) {
		position: fixed;
		background: var(--card-bg);
		border: 1px solid var(--border-color);
		border-radius: 1rem;
		padding: 0.4rem;
		box-shadow: 0 16px 40px rgba(0, 0, 0, 0.25);
		z-index: 9999;
		max-height: 280px;
		overflow-y: auto;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}

	:global(.ms-option) {
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

	:global(.ms-option:hover) {
		background: var(--hover-bg-subtle);
		color: var(--text-bright);
	}

	:global(.ms-option.is-active) {
		background: color-mix(in srgb, var(--accent) 16%, transparent);
		color: var(--text-bright);
	}

	:global(.ms-option.is-disabled) {
		opacity: 0.6;
		cursor: not-allowed;
	}

	:global(.ms-option-all) {
		font-weight: 600;
		font-size: 0.8rem;
		text-transform: uppercase;
		letter-spacing: 0.06em;
		color: var(--text-tertiary);
	}

	:global(.ms-divider) {
		height: 1px;
		background: var(--border-color);
		margin: 0.3rem 0.5rem;
		opacity: 0.5;
	}

	:global(.ms-dot) {
		color: var(--accent);
		font-size: 0.7rem;
	}

	/* Small variant */
	.ms-sm .ms-button {
		min-height: 28px;
		padding: 0.2rem 0.5rem 0.2rem 0.6rem;
		font-size: 0.75rem;
	}

	.ms-sm :global(.ms-caret) {
		width: 12px;
		height: 12px;
	}

	:global(.ms-sm.ms-menu .ms-option) {
		padding: 0.4rem 0.6rem;
		font-size: 0.75rem;
	}

	.ms.disabled .ms-button {
		opacity: 0.6;
		cursor: not-allowed;
	}
</style>
