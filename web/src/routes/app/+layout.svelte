<script lang="ts">
	import '../../app.css';
	import '@fontsource/inter';
	import './layout.css';
	import favicon from '$lib/assets/favicon.svg';
	import { page } from '$app/stores';
	import { browser } from '$app/environment';
	import { onMount } from 'svelte';
	import AccountDialog from '$lib/components/AccountDialog.svelte';
	
	let appEventSource: EventSource | null = null;

	const startAppStream = () => {
		if (!browser || appEventSource) {
			return;
		}

		appEventSource = new EventSource('/api/app/stream');

		const parsePayload = (event: MessageEvent) => {
			try {
				return JSON.parse(event.data);
			} catch {
				return event.data;
			}
		};

		appEventSource.addEventListener('ready', (event) => {
			console.info('sse ready', parsePayload(event));
		});

		appEventSource.addEventListener('heartbeat', (event) => {
			console.info('sse heartbeat', parsePayload(event));
		});

		appEventSource.addEventListener('shutting_down', (event) => {
			console.warn('sse shutting down', parsePayload(event));
		});

		appEventSource.onerror = (event) => {
			console.warn('sse connection error', event);
		};
	};

	// Check auth on mount
	onMount(() => {
		if (!browser) {
			return;
		}

		let cancelled = false;

		const checkAuthAndStart = async () => {
			try {
				const response = await fetch('/api/auth/me', {
					credentials: 'include'
				});

				if (!response.ok) {
					// Not authenticated, redirect to login
					window.location.href = '/auth/login';
					return;
				}

				if (!cancelled) {
					startAppStream();
				}
			} catch (error) {
				// Error checking auth, redirect to login
				window.location.href = '/auth/login';
			}
		};

		checkAuthAndStart();

		return () => {
			cancelled = true;
			if (appEventSource) {
				appEventSource.close();
				appEventSource = null;
			}
		};
	});
	import MoonIcon from 'lucide-svelte/icons/moon';
	import SunIcon from 'lucide-svelte/icons/sun';
	import { ChartPie, BellRing, Boxes, CircleUserRound } from 'lucide-svelte';
	import { writable, get } from 'svelte/store';

	let accountDialogOpen = $state(false);

	const navLinks = [
		{ href: '/app', label: 'Dashboard', icon: ChartPie },
		{ href: '/app/agents', label: 'SBOMs', icon: Boxes },
		{ href: '/app/notifications', label: 'Alerts', icon: BellRing }
	] as const;

	type ExtendedMediaQueryList = MediaQueryList & {
		addListener?: (listener: (this: MediaQueryList, ev: MediaQueryListEvent) => void) => void;
		removeListener?: (listener: (this: MediaQueryList, ev: MediaQueryListEvent) => void) => void;
	};

	const THEME_STORAGE_KEY = 'spam-monitor-theme';
	const theme = writable<'light' | 'dark'>('dark');
	let explicitPreference: 'light' | 'dark' | null = null;
	let systemTheme: 'light' | 'dark' = 'dark';
	let mediaQuery: ExtendedMediaQueryList | null = null;

	const applyTheme = (value: 'light' | 'dark') => {
		if (browser) {
			const root = document.documentElement;
			root.classList.remove('light', 'dark');
			root.classList.add(value);
		}
		theme.set(value);
	};

	const toggleTheme = () => {
		const nextTheme: 'light' | 'dark' = get(theme) === 'dark' ? 'light' : 'dark';
		applyTheme(nextTheme);

		if (!browser) {
			return;
		}

		if (nextTheme === systemTheme) {
			localStorage.removeItem(THEME_STORAGE_KEY);
			explicitPreference = null;
		} else {
			localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
			explicitPreference = nextTheme;
		}
	};

	onMount(() => {
		if (!browser) {
			return;
		}

		const stored = localStorage.getItem(THEME_STORAGE_KEY);
		if (stored === 'light' || stored === 'dark') {
			explicitPreference = stored;
		} else {
			explicitPreference = null;
		}

		mediaQuery = window.matchMedia('(prefers-color-scheme: dark)') as ExtendedMediaQueryList;
		systemTheme = mediaQuery.matches ? 'dark' : 'light';
		const initialTheme = explicitPreference ?? systemTheme;
		applyTheme(initialTheme);

		const handleSystemChange = (event: MediaQueryListEvent) => {
			systemTheme = event.matches ? 'dark' : 'light';
			if (!explicitPreference) {
				applyTheme(systemTheme);
			}
		};

		if (typeof mediaQuery.addEventListener === 'function') {
			mediaQuery.addEventListener('change', handleSystemChange);
		} else if (typeof mediaQuery.addListener === 'function') {
			mediaQuery.addListener(handleSystemChange);
		}

		return () => {
			if (!mediaQuery) {
				return;
			}
			if (typeof mediaQuery.removeEventListener === 'function') {
				mediaQuery.removeEventListener('change', handleSystemChange);
			} else if (typeof mediaQuery.removeListener === 'function') {
				mediaQuery.removeListener(handleSystemChange);
			}
		};
	});

	let { children } = $props();
	const pageStore = page;

	const isActive = (href: string) => {
		const path = $pageStore.url?.pathname ?? '/';
		if (href === '/app') {
			return path === '/app';
		}
		return path === href || path.startsWith(`${href}/`);
	};
</script>

<svelte:head>
	<title>{$pageStore.data?.title ?? 'Spam Monitor'}</title>
	<link rel="icon" href={favicon} />
	<meta name="theme-color" content="#1d2021" />
</svelte:head>

<div class="fixed left-0 right-0 top-0 z-50 h-1 w-full" style="background-color: var(--main-content-bg);"></div>

<div class="flex h-screen max-h-screen overflow-hidden text-[var(--text-primary)]">
	<aside class="relative hidden h-screen min-h-screen max-h-screen w-64 flex-shrink-0 flex-col overflow-y-auto bg-[var(--main-content-bg)] px-6 py-10 md:flex">
		<nav class="mt-32 flex-1 space-y-2" aria-label="Primary">
			{#each navLinks as link}
				<a
					href={link.href}
					class={`group flex items-center gap-2 rounded-full border border-transparent px-4 py-2 text-[0.9rem] transition-all duration-200 ${
						isActive(link.href)
							? 'bg-[var(--hover-bg)] text-[var(--accent)] border-[var(--border-color)] shadow-md'
							: 'text-[var(--text-secondary)] hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]'
					}`}
					data-sveltekit-preload-data="hover"
					aria-current={isActive(link.href) ? 'page' : undefined}
				>
					<span class="flex h-8 w-8 items-center justify-center rounded-full text-[var(--accent)]" aria-hidden="true">
						<link.icon size={18} stroke-width={1.7} />
					</span>
					<span class="font-medium">{link.label}</span>
				</a>
			{/each}
		</nav>

		<div class="mt-auto flex flex-col gap-2 pt-6">
			<button
				type="button"
				onclick={toggleTheme}
				class="group flex items-center gap-2 rounded-full border border-transparent px-4 py-2 text-[0.9rem] text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]"
				aria-label={`Switch to ${$theme === 'dark' ? 'light' : 'dark'} theme`}
				title={`Switch to ${$theme === 'dark' ? 'light' : 'dark'} theme`}
			>
				<span class="flex h-8 w-8 items-center justify-center rounded-full text-[var(--accent)]" aria-hidden="true">
					{#if $theme === 'dark'}
						<MoonIcon size={16} />
					{:else}
						<SunIcon size={16} />
					{/if}
				</span>
				<span class="font-medium">Theme: {$theme === 'dark' ? 'Dark' : 'Light'}</span>
			</button>
			<button 
				type="button" 
				class="group flex items-center gap-2 rounded-full border border-transparent px-4 py-2 text-[0.9rem] text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]"
				onclick={() => accountDialogOpen = true}
			>
				<span class="flex h-8 w-8 items-center justify-center rounded-full text-[var(--accent)]" aria-hidden="true">
					<CircleUserRound size={18} stroke-width={1.7} />
				</span>
				<span class="font-medium">Account</span>
			</button>
		</div>
	</aside>

	<div class="flex h-full flex-1 flex-col">
		<main class="flex-1 overflow-y-auto bg-[var(--main-content-bg)] px-3 pb-8 pt-10 sm:px-6">
			<div class="mx-auto w-full max-w-[1520px] space-y-8 p-5 text-[0.9rem] sm:p-8">
				{@render children?.()}
			</div>
		</main>
	</div>
</div>

<AccountDialog bind:open={accountDialogOpen} />
