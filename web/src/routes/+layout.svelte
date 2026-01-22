<script lang="ts">
	import './layout.css';
	import favicon from '$lib/assets/favicon.svg';
	import { page } from '$app/stores';

	let { children } = $props();
	const pageStore = page;
</script>

<svelte:head>
	<title>{$pageStore.data?.title ?? 'Spam Monitor'}</title>
	<link rel="icon" href={favicon} />
</svelte:head>
{@render children()}
