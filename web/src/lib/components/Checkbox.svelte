<script lang="ts">
	import Check from 'lucide-svelte/icons/check';

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

<label class="checkbox-wrapper" class:disabled ondblclick={(e) => e.preventDefault()}>
	<input class="checkbox-input" type="checkbox" bind:checked {disabled} onchange={handleChange} />
	<span class="checkbox-box" aria-hidden="true">
    {#if checked}
		  <Check class="checkmark" size={14} strokeWidth={3} stroke="var(--bg-hard)" />
    {/if}
	</span>
	{#if label}
		<span class="text-sm text-[var(--text-secondary)]">{label}</span>
	{/if}
</label>

<style>

  :global(.checkmark){
    stroke: var(--bg-hard);
  }
	.checkbox-wrapper {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		cursor: pointer;
		user-select: none;
		-webkit-user-select: none;
		-moz-user-select: none;
		-ms-user-select: none;
		position: relative;
	}

	.checkbox-wrapper.disabled {
		opacity: 0.5;
		cursor: not-allowed;
	}

	.checkbox-input {
		position: absolute;
		opacity: 0;
		width: 1px;
		height: 1px;
		margin: 0;
		overflow: hidden;
		clip: rect(0 0 0 0);
		clip-path: inset(50%);
	}

	.checkbox-box {
		position: relative;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 18px;
		height: 18px;
		border-radius: 6px;
		border: 1px solid var(--border-color);
		background: var(--card-bg);
		transition: border-color 150ms ease, background 150ms ease, box-shadow 150ms ease;
		flex-shrink: 0;
	}

	.checkbox-input:focus-visible + .checkbox-box {
		box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 35%, transparent);
	}

	.checkbox-input:checked + .checkbox-box {
		background: var(--accent);
		border-color: var(--accent);
	}

	.checkbox-input:disabled + .checkbox-box {
		opacity: 0.6;
		cursor: not-allowed;
	}

	.checkbox-wrapper.disabled {
		cursor: not-allowed;
	}

	.checkmark {
		color: var(--bg-hard);
		opacity: 1;
		transform: scale(0.2);
		transition: opacity 120ms ease, transform 180ms ease;
	}

	:global(.checkbox-input:checked) + .checkbox-box .checkmark {
		transform: scale(1);
		animation: checkmark-pop 180ms ease-out;
	}

	@keyframes checkmark-pop {
		0% {
			transform: translate(-50%, -50%) scale(0);
		}
		70% {
			transform: translate(-50%, -50%) scale(1.2);
		}
		100% {
			transform: translate(-50%, -50%) scale(1);
		}
	}
</style>
