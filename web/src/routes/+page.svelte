<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';

	// Server-side SPAGuard already verified authentication before serving this page.
	onMount(() => {
		goto('/app');
	});
</script>

<svelte:head>
	<title>Redirecting...</title>
</svelte:head>

<div style="display: flex; align-items: center; justify-content: center; min-height: 100vh; color: var(--text-secondary);">
	<p>Redirecting...</p>
</div>
