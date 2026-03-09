<script lang="ts">
	let { size = 48, class: className = '' }: { size?: number; class?: string } = $props();
</script>

<svg width={size} height={size} viewBox="0 0 100 100" fill="currentColor" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0" class={className}>
	<path d="m50 5a45 45 0 1 0 45 45 45.05 45.05 0 0 0 -45-45zm0 82a37 37 0 1 1 37-37 37 37 0 0 1 -37 37z"/>
	<path d="m67.5 46.54-24-14a4 4 0 0 0 -6 3.46v28a4 4 0 0 0 2 3.46 4 4 0 0 0 4 0l24-14a4 4 0 0 0 0-6.92z"/>
</svg>
