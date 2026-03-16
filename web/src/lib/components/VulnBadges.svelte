<script lang="ts">
	import { ShieldX, ShieldAlert, Shield } from 'lucide-svelte';

	let {
		critical = 0,
		high = 0,
		medium = 0,
		low = 0,
		size = 'md'
	}: {
		critical?: number;
		high?: number;
		medium?: number;
		low?: number;
		size?: 'sm' | 'md';
	} = $props();

	const iconClass = $derived(size === 'sm' ? 'h-3 w-3' : 'h-4 w-4');
	const textClass = $derived(size === 'sm' ? 'text-xs' : 'text-sm');
	const gapClass = $derived(size === 'sm' ? 'gap-2' : 'gap-4');
</script>

<div class="flex items-center {gapClass} {textClass}">
	{#if critical > 0}
		<span class="flex items-center gap-1 font-semibold text-red-500">
			<ShieldX class={iconClass} />{critical}
		</span>
	{/if}
	{#if high > 0}
		<span class="flex items-center gap-1 font-semibold text-orange-500">
			<ShieldAlert class={iconClass} />{high}
		</span>
	{/if}
	{#if medium > 0}
		<span class="flex items-center gap-1 font-semibold text-yellow-500">
			<Shield class={iconClass} />{medium}
		</span>
	{/if}
	{#if low > 0}
		<span class="flex items-center gap-1 text-[var(--text-secondary)]">
			<Shield class={iconClass} />{low}
		</span>
	{/if}
</div>
