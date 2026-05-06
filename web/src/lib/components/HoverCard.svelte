<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		/** Trigger content wrapped by a hover-sensitive inline span. */
		children: Snippet;
		/** Card content. Rendered into a portalled overlay on hover. */
		content: Snippet;
		/** Max width of the card in rem. Default 14. */
		width?: number;
		/** Disable the hover (e.g. nothing useful to show). */
		disabled?: boolean;
	}

	let { children, content, width = 14, disabled = false }: Props = $props();

	let open = $state(false);
	let tipPos = $state({ x: 0, y: 0 });
	let hideTimer: ReturnType<typeof setTimeout> | null = null;

	const show = (e: MouseEvent) => {
		if (disabled) return;
		if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
		const target = e.currentTarget as HTMLElement;
		const rect = target.getBoundingClientRect();
		tipPos = { x: rect.left + rect.width / 2, y: rect.top - 8 };
		open = true;
	};

	const scheduleHide = () => {
		if (hideTimer) clearTimeout(hideTimer);
		hideTimer = setTimeout(() => { open = false; }, 120);
	};

	const clearHide = () => {
		if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
	};

	function portal(node: HTMLElement) {
		document.body.appendChild(node);
		return {
			destroy() { node.remove(); }
		};
	}
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<span
	class="hover-card-trigger"
	onmouseenter={show}
	onmouseleave={scheduleHide}
>
	{@render children()}
</span>

{#if open}
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div
		use:portal
		class="hover-card-layer"
		style="left: {tipPos.x}px; top: {tipPos.y}px; --hc-width: {width}rem;"
		onmouseenter={clearHide}
		onmouseleave={scheduleHide}
	>
		<div class="hover-card-body">
			{@render content()}
		</div>
	</div>
{/if}

<style>
	.hover-card-trigger {
		display: inline-flex;
		cursor: pointer;
	}

	:global(.hover-card-layer) {
		position: fixed;
		z-index: 1200;
		transform: translate(-50%, calc(-100% + 6px)) scale(0.9) rotate(5deg);
		pointer-events: auto;
		opacity: 0;
		animation: hover-card-in 180ms cubic-bezier(0.34, 1.56, 0.64, 1) forwards;
		transform-origin: bottom center;
		will-change: transform, opacity;
	}

	:global(.hover-card-body) {
		width: var(--hc-width, 14rem);
		background: var(--bg-soft);
		border: 1px solid var(--border-color);
		border-radius: 0.75rem;
		padding: 0.75rem;
		box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
	}

	@keyframes hover-card-in {
		from {
			opacity: 0;
			transform: translate(-50%, calc(-100% + 6px)) scale(0.9) rotate(5deg);
		}
		to {
			opacity: 1;
			transform: translate(-50%, -100%) scale(1) rotate(-2deg);
		}
	}
</style>
