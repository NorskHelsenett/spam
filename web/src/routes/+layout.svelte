<script lang="ts">
	import '../app.css';
	import '@fontsource/inter';
	import './layout.css';
	import favicon from '$lib/assets/favicon.svg';
	import { page } from '$app/stores';

	const navLinks = [
		{ href: '/', label: 'Overview', icon: 'overview' },
		{ href: '/agents', label: 'Agents', icon: 'agents' },
		{ href: '/notifications', label: 'Notifications', icon: 'notifications' }
	] as const;

	const navIcons: Record<(typeof navLinks)[number]['icon'], string> = {
		overview:
			'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" width="28" height="28"><path d="M21.6702 6.94942C21.0302 4.77942 19.2202 2.96942 17.0502 2.32942C15.4002 1.84942 14.2602 1.88942 13.4702 2.47942C12.5202 3.18942 12.4102 4.46942 12.4102 5.37942V7.86942C12.4102 10.3294 13.5302 11.5794 15.7302 11.5794H18.6002C19.5002 11.5794 20.7902 11.4694 21.5002 10.5194C22.1102 9.73942 22.1602 8.59942 21.6702 6.94942ZM18.9094 13.3611C18.6494 13.0611 18.2694 12.8911 17.8794 12.8911H14.2994C12.5394 12.8911 11.1094 11.4611 11.1094 9.70113V6.12113C11.1094 5.73113 10.9394 5.35113 10.6394 5.09113C10.3494 4.83113 9.94941 4.71113 9.56941 4.76113C7.21941 5.06113 5.05941 6.35113 3.64941 8.29113C2.22941 10.2411 1.70941 12.6211 2.15941 15.0011C2.80941 18.4411 5.55941 21.1911 9.00941 21.8411C9.55941 21.9511 10.1094 22.0011 10.6594 22.0011C12.4694 22.0011 14.2194 21.4411 15.7094 20.3511C17.6494 18.9411 18.9394 16.7811 19.2394 14.4311C19.2894 14.0411 19.1694 13.6511 18.9094 13.3611Z"/></svg>',
		agents:
			'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" width="28" height="28"><path d="M15.024 22C16.2771 22 17.3524 21.9342 18.2508 21.7345C19.1607 21.5323 19.9494 21.1798 20.5646 20.5646C21.1798 19.9494 21.5323 19.1607 21.7345 18.2508C21.9342 17.3524 22 16.2771 22 15.024V12C22 10.8954 21.1046 10 20 10H12C10.8954 10 10 10.8954 10 12V20C10 21.1046 10.8954 22 12 22H15.024ZM2 15.024C2 16.2771 2.06584 17.3524 2.26552 18.2508C2.46772 19.1607 2.82021 19.9494 3.43543 20.5646C4.05065 21.1798 4.83933 21.5323 5.74915 21.7345C5.83628 21.7538 5.92385 21.772 6.01178 21.789C7.09629 21.9985 8 21.0806 8 19.976V12C8 10.8954 7.10457 10 6 10H4C2.89543 10 2 10.8954 2 12V15.024ZM8.97597 2C7.72284 2 6.64759 2.06584 5.74912 2.26552C4.8393 2.46772 4.05062 2.82021 3.4354 3.43543C2.82018 4.05065 2.46769 4.83933 2.26549 5.74915C2.24889 5.82386 2.23327 5.89881 2.2186 5.97398C2.00422 7.07267 2.9389 8 4.0583 8H19.976C21.0806 8 21.9985 7.09629 21.789 6.01178C21.772 5.92385 21.7538 5.83628 21.7345 5.74915C21.5322 4.83933 21.1798 4.05065 20.5645 3.43543C19.9493 2.82021 19.1606 2.46772 18.2508 2.26552C17.3523 2.06584 16.2771 2 15.024 2H8.97597Z"/></svg>',
		notifications:
			'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" width="28" height="28"><path d="M20.1892 14.0608L19.0592 12.1808C18.8092 11.7708 18.5892 10.9808 18.5892 10.5008V8.63078C18.5892 5.00078 15.6392 2.05078 12.0192 2.05078C8.38923 2.06078 5.43923 5.00078 5.43923 8.63078V10.4908C5.43923 10.9708 5.21923 11.7608 4.97923 12.1708L3.84923 14.0508C3.41923 14.7808 3.31923 15.6108 3.58923 16.3308C3.85923 17.0608 4.46923 17.6408 5.26923 17.9008C6.34923 18.2608 7.43923 18.5208 8.54923 18.7108C8.65923 18.7308 8.76923 18.7408 8.87923 18.7608C9.01923 18.7808 9.16923 18.8008 9.31923 18.8208C9.57923 18.8608 9.83923 18.8908 10.1092 18.9108C10.7392 18.9708 11.3792 19.0008 12.0192 19.0008C12.6492 19.0008 13.2792 18.9708 13.8992 18.9108C14.1292 18.8908 14.3592 18.8708 14.5792 18.8408C14.7592 18.8208 14.9392 18.8008 15.1192 18.7708C15.2292 18.7608 15.3392 18.7408 15.4492 18.7208C16.5692 18.5408 17.6792 18.2608 18.7592 17.9008C19.5292 17.6408 20.1192 17.0608 20.3992 16.3208C20.6792 15.5708 20.5992 14.7508 20.1892 14.0608ZM12.7492 10.0008C12.7492 10.4208 12.4092 10.7608 11.9892 10.7608C11.5692 10.7608 11.2292 10.4208 11.2292 10.0008V6.90078C11.2292 6.48078 11.5692 6.14078 11.9892 6.14078C12.4092 6.14078 12.7492 6.48078 12.7492 6.90078V10.0008ZM14.8297 20.01C14.4097 21.17 13.2997 22 11.9997 22C11.2097 22 10.4297 21.68 9.87969 21.11C9.55969 20.81 9.31969 20.41 9.17969 20C9.30969 20.02 9.43969 20.03 9.57969 20.05C9.80969 20.08 10.0497 20.11 10.2897 20.13C10.8597 20.18 11.4397 20.21 12.0197 20.21C12.5897 20.21 13.1597 20.18 13.7197 20.13C13.9297 20.11 14.1397 20.1 14.3397 20.07C14.4997 20.05 14.6597 20.03 14.8297 20.01Z"/></svg>'
	};

	const utilityIcons = {
		search:
			'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>',
		newAgent:
			'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12 1a2 2 0 0 0-2 2c0 .74.4 1.39 1 1.73V7H7a3 3 0 0 0-3 3v10a3 3 0 0 0 3 3h10a3 3 0 0 0 3-3V10a3 3 0 0 0-3-3h-4V4.73A2 2 0 0 0 14 3a2 2 0 0 0-2-2Zm-7 9a1 1 0 0 1 1-1h1.38l1.45 2.89A2 2 0 0 0 10.38 13H13.6a2 2 0 0 0 1.8-1.11L16.85 9H18a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1Zm6.38 2-1-2H14.6l-1 2Z"/></svg>',
		theme:
			'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M21.752 15.002a9 9 0 0 1-13.5 7.794.75.75 0 0 1 .135-1.34 4 4 0 0 0 2.366-3.656v-.8a.75.75 0 0 1 .478-.697 5.5 5.5 0 1 0-3.391-5.105.75.75 0 0 1-.724.75H4.25a.75.75 0 0 1-.743-.842 9 9 0 0 1 17.51 3.896.77.77 0 0 1-.05.4"/></svg>',
		account:
			'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M12 12a5 5 0 1 0-5-5 5 5 0 0 0 5 5Zm-4.52 1.2a4 4 0 0 0-3.46 3.97V18a3 3 0 0 0 3 3h9a3 3 0 0 0 3-3v-.83a4 4 0 0 0-3.46-3.97 7 7 0 0 1-8.08 0Z"/></svg>'
	} as const;

	let { children } = $props();
	const pageStore = page;

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
		<aside class="relative hidden h-screen min-h-screen max-h-screen w-64 flex-shrink-0 flex-col overflow-y-auto px-6 py-10 md:flex">


			<div class="mt-10 space-y-3">
				<button type="button" class="group flex w-full items-center gap-3 rounded-full border border-transparent bg-[var(--card-bg)]/70 px-5 py-3 text-left text-sm text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]">
					<span class="flex h-9 w-9 items-center justify-center rounded-full text-[var(--accent)]" aria-hidden="true">{@html utilityIcons.search}</span>
					<span class="flex-1 font-medium">Search...</span>
					<span class="hidden items-center gap-1 text-xs text-[var(--text-muted)] md:flex">
						<kbd class="kbd">Ctrl</kbd>
						<kbd class="kbd">K</kbd>
					</span>
				</button>
				<button type="button" class="group flex w-full items-center gap-3 rounded-full border border-transparent bg-[var(--card-bg)]/70 px-5 py-3 text-left text-sm text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]">
					<span class="flex h-9 w-9 items-center justify-center rounded-full text-[var(--accent)]" aria-hidden="true">{@html utilityIcons.newAgent}</span>
					<span class="flex-1 font-medium">New Agent</span>
				</button>
			</div>

			<nav class="mt-8 flex-1 space-y-2" aria-label="Primary">
				{#each navLinks as link}
					<a
						href={link.href}
						class={`group flex items-center gap-3 rounded-full border border-transparent px-5 py-3 text-sm transition-all duration-200 ${
							isActive(link.href)
								? 'bg-[var(--hover-bg)] text-[var(--accent)] border-[var(--border-color)] shadow-lg'
								: 'text-[var(--text-secondary)] hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]'
						}`}
						data-sveltekit-preload-data="hover"
						aria-current={isActive(link.href) ? 'page' : undefined}
					>
						<span class="flex h-9 w-9 items-center justify-center rounded-full text-[var(--accent)]" aria-hidden="true">{@html navIcons[link.icon]}</span>
						<span class="font-medium">{link.label}</span>
					</a>
				{/each}
			</nav>

			<div class="mt-auto flex flex-col gap-3 pt-6">
				<button type="button" class="group flex items-center gap-3 rounded-full border border-transparent py-3 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]">
					<span class="flex h-9 w-9 items-center justify-center rounded-full text-[var(--accent)]" aria-hidden="true">{@html utilityIcons.theme}</span>
					<span class="font-medium">Theme</span>
				</button>
				<button type="button" class="group flex items-center gap-3 rounded-full border border-transparent py-3 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]">
					<span class="flex h-9 w-9 items-center justify-center rounded-full text-[var(--accent)]" aria-hidden="true">{@html utilityIcons.account}</span>
					<span class="font-medium">Account</span>
				</button>
			</div>
		</aside>

		<div class="flex h-full flex-1 flex-col">
			<main class="flex-1 overflow-y-auto px-4 pb-10 pt-12 sm:px-8">
				<div class="mx-auto w-full max-w-[1900px] space-y-10 rounded-2xl bg-[var(--main-content-bg)]/96 p-6 shadow-[0_24px_60px_rgba(0,0,0,0.35)] backdrop-blur-sm sm:p-10">
					{@render children?.()}
				</div>
			</main>
		</div>
	</div>
