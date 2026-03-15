<script lang="ts">
	let { size = 48, class: className = '' }: { size?: number; class?: string } = $props();
</script>

<svg width={size} height={size} viewBox="0 0 100 100" fill="currentColor" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0" class={className}>
	<!-- Shield outline -->
	<path d="M50 8 L86 22 L86 52 C86 72 68 88 50 94 C32 88 14 72 14 52 L14 22 Z" fill="none" stroke="currentColor" stroke-width="6" stroke-linejoin="round"/>
	<!-- Checkmark -->
	<polyline points="34,50 45,62 66,38" fill="none" stroke="currentColor" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/>
</svg>
