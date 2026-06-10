<script lang="ts">
	import {
		computeChainLayout,
		ingressPopover,
		podPopover,
		servicePopover,
		type ChainData,
		type PopoverData
	} from './chainLayout';
	import ChainNodes from './ChainNodes.svelte';
	import ChainPopover from './ChainPopover.svelte';

	let { chain }: { chain: ChainData } = $props();

	let layout = $derived(computeChainLayout(chain));

	let popover: PopoverData | null = $state(null);
</script>

<svg
	viewBox="0 0 {layout.totalWidth} {layout.totalHeight}"
	width={layout.totalWidth}
	height={layout.totalHeight}
	class="max-w-full"
	xmlns="http://www.w3.org/2000/svg"
>
	<defs>
		<marker id="arrowhead" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
			<polygon points="0 0, 8 3, 0 6" fill="var(--bg4)" />
		</marker>
	</defs>

	<ChainNodes
		{chain}
		{layout}
		onShowIngress={(ing) => (popover = ingressPopover(ing))}
		onShowService={(svc) => (popover = servicePopover(svc))}
		onShowPod={(pg) => (popover = podPopover(pg))}
	/>
</svg>

{#if popover}
	<div class="mt-2">
		<ChainPopover {popover} onClose={() => (popover = null)} />
	</div>
{/if}
