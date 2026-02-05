<script lang="ts">
	interface Props {
		checked: boolean;
		label?: string;
		disabled?: boolean;
		onchange?: (checked: boolean) => void;
	}

	let { checked = $bindable(false), label, disabled = false, onchange }: Props = $props();

	const handleChange = () => {
		if (!disabled) {
			onchange?.(checked);
		}
	};
</script>

<label class="toggle" class:disabled ondblclick={(e) => e.preventDefault()}>
	<input type="checkbox" bind:checked {disabled} onchange={handleChange} />
	<span class="toggle-track"></span>
	{#if label}
		<span class="text-sm text-[var(--text-secondary)]">{label}</span>
	{/if}
</label>

<style>
	.toggle {
		display: inline-flex;
		align-items: center;
		gap: 0.6rem;
		cursor: pointer;
		user-select: none;
		-webkit-user-select: none;
		-moz-user-select: none;
		-ms-user-select: none;
	}

	.toggle.disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.toggle input {
		display: none;
	}

	.toggle-track {
		position: relative;
		width: 42px;
		height: 22px;
		border-radius: 999px;
		background: var(--bg2);
		border: 1px solid var(--border-color);
		transition: background 150ms ease;
	}

	.toggle-track::after {
		content: '';
		position: absolute;
		top: 2px;
		left: 2px;
		width: 16px;
		height: 16px;
		border-radius: 999px;
		background: var(--text-bright);
		transition: transform 150ms ease;
	}

	.toggle input:checked + .toggle-track {
		background: color-mix(in srgb, var(--accent) 60%, var(--bg2));
	}

	.toggle input:checked + .toggle-track::after {
		transform: translateX(20px);
	}

	.toggle.disabled .toggle-track {
		cursor: not-allowed;
	}
</style>
