<script lang="ts">
	import '../../app.css';
	import '@fontsource/inter';
	import './layout.css';
	import favicon from '$lib/assets/favicon.svg';
	import { page } from '$app/stores';
	import { browser } from '$app/environment';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import AccountDialog from '$lib/components/AccountDialog.svelte';
	import SearchPalette from '$lib/components/SearchPalette.svelte';
	import { updateSyncState } from '$lib/stores/providerSync';
	import { newUserCount, newUserEvent } from '$lib/stores/newUserCount';

	let appEventSource: EventSource | null = null;
	let metricCardObserver: MutationObserver | null = null;

	const formatMetricNumber = (value: string) => {
		const normalized = value.replace(/[\s,]/g, '');
		if (!/^-?\d+$/.test(normalized)) {
			return value;
		}

		const parsed = Number.parseInt(normalized, 10);
		if (!Number.isSafeInteger(parsed)) {
			return value;
		}

		return Math.abs(parsed) < 1000 ? `${parsed}` : parsed.toLocaleString('en-US').replace(/,/g, ' ');
	};

	const formatMetricCardTextNode = (node: Text) => {
		if (node.parentElement?.closest('[data-no-format]')) return;
		const value = node.nodeValue ?? '';
		const nextValue = value.replace(/-?\d(?:[\d,\s]*\d)?/g, (token) => formatMetricNumber(token));
		if (nextValue !== value) {
			node.nodeValue = nextValue;
		}
	};

	const formatMetricCardNumbers = (card: Element) => {
		const walker = document.createTreeWalker(card, NodeFilter.SHOW_TEXT);
		let current = walker.nextNode();
		while (current) {
			formatMetricCardTextNode(current as Text);
			current = walker.nextNode();
		}
	};

	const setupMetricCardFormatting = () => {
		if (!browser || metricCardObserver) {
			return;
		}

		document.querySelectorAll('.metric-card').forEach((card) => {
			formatMetricCardNumbers(card);
		});

		metricCardObserver = new MutationObserver((mutations) => {
			for (const mutation of mutations) {
				if (mutation.type === 'characterData') {
					const parent = mutation.target.parentElement;
					const card = parent?.closest('.metric-card');
					if (card) {
						formatMetricCardNumbers(card);
					}
					continue;
				}

				for (const node of mutation.addedNodes) {
					if (!(node instanceof Element)) {
						continue;
					}
					if (node.matches('.metric-card')) {
						formatMetricCardNumbers(node);
					}
					node.querySelectorAll('.metric-card').forEach((card) => {
						formatMetricCardNumbers(card);
					});
				}
			}
		});

		metricCardObserver.observe(document.body, {
			childList: true,
			subtree: true,
			characterData: true
		});
	};

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
			// We deliberately don't pull /api/admin/providers/sync/status
			// here. The endpoint reads SyncManager's in-memory map, which
			// is only populated by manual admin "Sync now" clicks since the
			// process started — `{}` in normal operation. The admin
			// providers page does its own fetch on mount when it actually
			// matters; everywhere else we rely on the live
			// provider_sync_* SSE events (admin-only, see events/stream.go).
		});

		appEventSource.addEventListener('heartbeat', (event) => {
			console.info('sse heartbeat', parsePayload(event));
		});

		appEventSource.addEventListener('new_user', (event) => {
			const payload = parsePayload(event);
			console.info('sse new_user', payload);
			newUserCount.update((n) => n + 1);
			newUserEvent.set(payload);
		});

		appEventSource.addEventListener('provider_sync_started', (event) => {
			updateSyncState(parsePayload(event));
		});

		appEventSource.addEventListener('provider_sync_progress', (event) => {
			updateSyncState(parsePayload(event));
		});

		appEventSource.addEventListener('provider_sync_completed', (event) => {
			updateSyncState(parsePayload(event));
		});

		appEventSource.addEventListener('provider_sync_failed', (event) => {
			updateSyncState(parsePayload(event));
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
					goto('/auth/login');
					return;
				}

				const data = await response.json();
				isAdmin = data?.role === 'admin';

				if (!cancelled) {
					startAppStream();
					setupMetricCardFormatting();
				}
			} catch (error) {
				// Error checking auth, redirect to login
				goto('/auth/login');
			}
		};

		checkAuthAndStart();

		return () => {
			cancelled = true;
			if (appEventSource) {
				appEventSource.close();
				appEventSource = null;
			}
			if (metricCardObserver) {
				metricCardObserver.disconnect();
				metricCardObserver = null;
			}
		};
	});
	import MoonIcon from 'lucide-svelte/icons/moon';
	import SunIcon from 'lucide-svelte/icons/sun';
	import { ChartPie, ShieldAlert, CircleUserRound, Package, GitBranch, Play, KeyRound, Settings, Layers, Boxes, Users } from 'lucide-svelte';
	import KubernetesIcon from '$lib/components/icons/KubernetesIcon.svelte';
	import { writable, get } from 'svelte/store';

let accountDialogOpen = $state(false);
let isAdmin = $state(false);

	// Primary nav — inventory + security overviews. Visible to all
	// authenticated users. Admin-only actions (Runs, Settings) render
	// in a separate block below with an isAdmin gate.
	const navLinks = [
		{ href: '/', label: 'Dashboard', icon: ChartPie },
		{ href: '/vulnerabilities', label: 'Vulnerabilities', icon: ShieldAlert },
		{ href: '/components', label: 'Dependencies', icon: Package },
		{ href: '/providers', label: 'Providers', icon: GitBranch },
		{ href: '/secrets', label: 'Secrets', icon: KeyRound },
		{ href: '/clusters', label: 'Clusters', icon: KubernetesIcon },
		{ href: '/inventory', label: 'Inventory', icon: Boxes }
	] as const;

	// Admin-only nav — Runs exposes the job queue (CREATE_RUN artifacts
	// can contain credentials surfaced in scan history), Jobs is the
	// live queue view across all worker pools, Settings covers provider
	// config + user management.
	const adminNavLinks = [
		{ href: '/runs', label: 'Runs', icon: Play },
		{ href: '/admin/jobs', label: 'Jobs', icon: Layers },
		{ href: '/admin/users', label: 'Users', icon: Users }
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

	$effect(() => {
		if ($pageStore.url?.pathname === '/admin/users') {
			newUserCount.set(0);
		}
	});

	const isActive = (href: string) => {
		const path = $pageStore.url?.pathname ?? '/';
		if (href === '/') {
			return path === '/';
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
				{#if 'groupBreak' in link && link.groupBreak}
					<div class="h-6" aria-hidden="true"></div>
				{/if}
				<button
					type="button"
					class={`group flex items-center gap-2 rounded-full border border-transparent px-4 py-2 text-[0.9rem] transition-all duration-200 active:scale-95 ${
						isActive(link.href)
							? 'bg-[var(--hover-bg)] text-[var(--accent)] border-[var(--border-color)] shadow-md'
							: 'text-[var(--text-secondary)] hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]'
					}`}
					onclick={() => goto(link.href)}
					aria-current={isActive(link.href) ? 'page' : undefined}
					aria-label={link.label}
				>
					<span class="flex h-8 w-8 items-center justify-center rounded-full text-[var(--accent)]" aria-hidden="true">
						<link.icon size={18} stroke-width={1.7} />
					</span>
					<span class="font-medium">{link.label}</span>
				</button>
			{/each}
			{#if isAdmin}
				<div class="h-6" aria-hidden="true"></div>
				{#each adminNavLinks as link}
					<button
						type="button"
						class={`group flex items-center gap-2 rounded-full border border-transparent px-4 py-2 text-[0.9rem] transition-all duration-200 active:scale-95 ${
							isActive(link.href)
								? 'bg-[var(--hover-bg)] text-[var(--accent)] border-[var(--border-color)] shadow-md'
								: 'text-[var(--text-secondary)] hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]'
						}`}
						onclick={() => goto(link.href)}
						aria-current={isActive(link.href) ? 'page' : undefined}
						aria-label={link.label}
					>
						<span class="flex h-8 w-8 items-center justify-center rounded-full text-[var(--accent)]" aria-hidden="true">
							<link.icon size={18} stroke-width={1.7} />
						</span>
						<span class="font-medium">{link.label}</span>
					</button>
				{/each}
				<button
					type="button"
					class={`group flex items-center gap-2 rounded-full border border-transparent px-4 py-2 text-[0.9rem] transition-all duration-200 active:scale-95 ${
						isActive('/admin/providers')
							? 'bg-[var(--hover-bg)] text-[var(--accent)] border-[var(--border-color)] shadow-md'
							: 'text-[var(--text-secondary)] hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]'
					}`}
					onclick={() => goto('/admin/providers')}
					aria-current={isActive('/admin/providers') ? 'page' : undefined}
					aria-label="Settings"
				>
					<span class="flex h-8 w-8 items-center justify-center rounded-full text-[var(--accent)]" aria-hidden="true">
						<Settings size={18} stroke-width={1.7} />
					</span>
					<span class="font-medium">Settings</span>
					{#if $newUserCount > 0}
						<span class="ml-auto flex h-5 min-w-5 items-center justify-center rounded-full bg-[var(--accent)] px-1 text-[10px] font-bold text-[var(--bg-primary)]">
							{$newUserCount > 99 ? '99+' : $newUserCount}
						</span>
					{/if}
				</button>
			{/if}
		</nav>

		<div class="mt-auto flex flex-col gap-2 pt-6">
			<button
				type="button"
				onclick={toggleTheme}
				class="group flex items-center gap-2 rounded-full border border-transparent px-4 py-2 text-[0.9rem] text-[var(--text-secondary)] transition active:scale-95 hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]"
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
				class="group flex items-center gap-2 rounded-full border border-transparent px-4 py-2 text-[0.9rem] text-[var(--text-secondary)] transition active:scale-95 hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]"
				onclick={() => accountDialogOpen = true}
			>
				<span class="flex h-8 w-8 items-center justify-center rounded-full text-[var(--accent)]" aria-hidden="true">
					<CircleUserRound size={18} stroke-width={1.7} />
				</span>
				<span class="font-medium">Account</span>
			</button>
		</div>
	</aside>

	<div class="flex h-full min-w-0 flex-1 flex-col">
		<main class="flex-1 overflow-y-auto bg-[var(--main-content-bg)] px-3 pb-8 pt-10 sm:px-6">
			<div class="mx-auto w-full max-w-[1520px] space-y-8 p-5 text-[0.9rem] sm:p-8">
				{@render children?.()}
			</div>
		</main>
	</div>
</div>

<AccountDialog bind:open={accountDialogOpen} />
<SearchPalette />


<style>
	button {
		cursor: pointer;
		width: 100%;
	}
</style>
