<script lang="ts">
	import '../app.css';
	import '@fontsource/inter';
	import './layout.css';
	import favicon from '$lib/assets/favicon.svg';
	import { page } from '$app/stores';

	const navLinks = [
		{ href: '/', label: 'Overview', external: false },
		{ href: '/api/auth/login', label: 'Sign in', external: true }
	] as const;

	let { children } = $props();
	const pageStore = page;
</script>

<svelte:head>
	<title>{$pageStore.data?.title ?? 'Spam Monitor'}</title>
	<link rel="icon" href={favicon} />
</svelte:head>

<div class="layout">
	<aside class="layout__sidebar" aria-label="Primary navigation">
		<a class="layout__brand" href="/">
			<span class="layout__brand-accent">Spam</span>
			<span>Monitor</span>
		</a>
		<nav class="layout__nav" aria-label="Sections">
			<ul>
				{#each navLinks as link}
					<li>
						<a
							class:is-active={!link.external && $pageStore.url?.pathname === link.href}
							href={link.href}
							data-sveltekit-preload-data={!link.external ? 'hover' : undefined}
							aria-current={!link.external && $pageStore.url?.pathname === link.href ? 'page' : undefined}
						>
							{link.label}
						</a>
					</li>
				{/each}
			</ul>
		</nav>
	</aside>
	<div class="layout__main">
		<main class="layout__content" aria-live="polite">
			<div class="layout__page">
				{@render children?.()}
			</div>
		</main>
	</div>
</div>
