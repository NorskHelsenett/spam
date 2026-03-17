<script lang="ts">
	import type { Snippet } from 'svelte';

	let {
		title,
		subtitle,
		icon,
		color = 'var(--error)'
	}: {
		title?: string;
		subtitle?: string;
		icon: Snippet;
		color?: string;
	} = $props();
</script>

<div class="flex min-h-[50vh] flex-col items-center justify-center p-8 text-center">
	<div class="flex h-20 w-20 items-center justify-center rounded-full" style="background: color-mix(in srgb, {color} 10%, transparent)">
		{@render icon()}
	</div>
	{#if title}
		<p class="mt-4 text-lg font-semibold leading-tight text-[var(--text-bright)]">{title}</p>
	{/if}
	{#if subtitle}
		<p class="mt-2 max-w-md text-sm text-[var(--text-secondary)]">{subtitle}</p>
	{/if}
</div>
