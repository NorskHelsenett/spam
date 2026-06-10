<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		/** Plain-text tooltip body. For rich markup pass a content snippet instead. */
		text?: string;
		/** Rich tooltip content; wins over text. */
		content?: Snippet;
		/** Max width in rem. Default 16. */
		width?: number;
		/** Trigger element(s). */
		children: Snippet;
	}

	let { text = '', content, width = 16, children }: Props = $props();

	let open = $state(false);
	let pos = $state({ x: 0, y: 0, below: false });

	const show = (e: Event) => {
		const rect = (e.currentTarget as HTMLElement).getBoundingClientRect();
		// Flip under the trigger when there's no headroom above.
		const below = rect.top < 110;
		pos = {
			x: rect.left + rect.width / 2,
			y: below ? rect.bottom + 7 : rect.top - 7,
			below
		};
		open = true;
	};
	const hide = () => (open = false);

	function portal(node: HTMLElement) {
		document.body.appendChild(node);
		return {
			destroy() {
				node.remove();
			}
		};
	}
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<span
	class="tooltip-trigger"
	onmouseenter={show}
	onmouseleave={hide}
	onfocusin={show}
	onfocusout={hide}
>
	{@render children()}
</span>

{#if open}
	<div
		use:portal
		class="tooltip-layer"
		class:below={pos.below}
		style="left: {pos.x}px; top: {pos.y}px; --tt-width: {width}rem;"
		role="tooltip"
	>
		<div class="tooltip-body">
			{#if content}
				{@render content()}
			{:else}
				<p class="tooltip-text">{text}</p>
			{/if}
			<div class="tooltip-arrow"></div>
		</div>
	</div>
{/if}

<style>
	.tooltip-trigger {
		display: inline-flex;
		min-width: 0;
	}

	:global(.tooltip-layer) {
		position: fixed;
		z-index: 1200;
		transform: translate(-50%, -100%);
		pointer-events: none;
		opacity: 0;
		animation: tooltip-in 140ms ease-out forwards;
		will-change: transform, opacity;
	}

	:global(.tooltip-layer.below) {
		transform: translate(-50%, 0);
		animation-name: tooltip-in-below;
	}

	:global(.tooltip-body) {
		position: relative;
		max-width: var(--tt-width, 16rem);
		width: max-content;
		background: var(--bg-soft);
		border: 1px solid var(--border-color);
		border-radius: 0.6rem;
		padding: 0.55rem 0.7rem;
		box-shadow: 0 6px 18px rgba(0, 0, 0, 0.35);
	}

	:global(.tooltip-text) {
		margin: 0;
		font-size: 0.75rem;
		line-height: 1.45;
		color: var(--text-secondary);
	}

	:global(.tooltip-arrow) {
		position: absolute;
		left: 50%;
		bottom: -4.5px;
		width: 8px;
		height: 8px;
		transform: translateX(-50%) rotate(45deg);
		background: var(--bg-soft);
		border-right: 1px solid var(--border-color);
		border-bottom: 1px solid var(--border-color);
	}

	:global(.tooltip-layer.below .tooltip-arrow) {
		bottom: auto;
		top: -4.5px;
		border-right: 0;
		border-bottom: 0;
		border-left: 1px solid var(--border-color);
		border-top: 1px solid var(--border-color);
	}

	@keyframes tooltip-in {
		from {
			opacity: 0;
			transform: translate(-50%, calc(-100% + 4px));
		}
		to {
			opacity: 1;
			transform: translate(-50%, -100%);
		}
	}

	@keyframes tooltip-in-below {
		from {
			opacity: 0;
			transform: translate(-50%, -4px);
		}
		to {
			opacity: 1;
			transform: translate(-50%, 0);
		}
	}
</style>
