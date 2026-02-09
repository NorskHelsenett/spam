<script lang="ts">
	interface Props {
		value: string;
		group: string;
		name: string;
		label?: string;
		disabled?: boolean;
		onchange?: (value: string) => void;
	}

	let { value, group = $bindable(''), name, label, disabled = false, onchange }: Props = $props();

	const handleChange = () => {
		if (!disabled) {
			onchange?.(value);
		}
	};
</script>

<label class="radio-wrapper" class:disabled ondblclick={(e) => e.preventDefault()}>
	<input type="radio" {name} {value} bind:group {disabled} onchange={handleChange} />
	{#if label}
		<span class="text-sm text-[var(--text-secondary)]">{label}</span>
	{/if}
</label>

<style>
	.radio-wrapper {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		cursor: pointer;
		user-select: none;
		-webkit-user-select: none;
		-moz-user-select: none;
		-ms-user-select: none;
	}

	.radio-wrapper.disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	input[type='radio'] {
		appearance: none;
		width: 18px;
		height: 18px;
		border-radius: 999px;
		border: 1px solid var(--border-color);
		background: var(--card-bg);
		display: inline-grid;
		place-items: center;
		cursor: pointer;
		transition: border-color 150ms ease, background 150ms ease, box-shadow 150ms ease;
		flex-shrink: 0;
	}

	input[type='radio']::after {
		content: '';
		width: 8px;
		height: 8px;
		border-radius: 999px;
		background: var(--accent);
		transform: scale(0);
		transition: transform 120ms ease;
	}

	input[type='radio']:checked {
		background: color-mix(in srgb, var(--accent) 18%, transparent);
		border-color: var(--accent);
	}

	input[type='radio']:checked::after {
		transform: scale(1);
		animation: radio-pop 180ms ease-out;
	}

	input[type='radio']:focus-visible {
		outline: none;
		box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 35%, transparent);
	}

	input[type='radio']:disabled {
		cursor: not-allowed;
	}

	.radio-wrapper.disabled input[type='radio'] {
		cursor: not-allowed;
	}

	@keyframes radio-pop {
		0% {
			transform: scale(0.3);
		}
		70% {
			transform: scale(1.2);
		}
		100% {
			transform: scale(1);
		}
	}
</style>
