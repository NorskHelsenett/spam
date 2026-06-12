<script lang="ts">
	import { page } from '$app/stores';
	import { newUserCount } from '$lib/stores/newUserCount';

	let { children } = $props();

	// Two groups: configuration on the left, operational/read-mostly
	// monitoring on the right. Each tab is a real route so deep links
	// and back/forward work, and each page stays its own code-split chunk.
	const groups = [
		{
			label: 'Settings',
			links: [
				{ href: '/admin/settings/providers', label: 'Providers' },
				{ href: '/admin/settings/scanners', label: 'Scanners' },
				{ href: '/admin/settings/ai', label: 'AI' },
				{ href: '/admin/settings/users', label: 'Users' },
				{ href: '/admin/settings/namespaces', label: 'Namespaces' }
			]
		},
		{
			label: 'Monitoring',
			links: [
				{ href: '/admin/settings/jobs', label: 'Jobs' },
				{ href: '/admin/settings/database', label: 'Database' }
			]
		}
	];

	const isActive = (href: string) => {
		const path = $page.url?.pathname ?? '';
		return path === href || path.startsWith(`${href}/`);
	};
</script>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Settings</h1>
			<p class="mt-1 text-sm text-[var(--text-tertiary)]">
				Providers, scanners, access, and operational monitoring — admin only.
			</p>
		</header>

		<nav class="flex flex-wrap items-start gap-x-10 gap-y-4" aria-label="Settings sections">
			{#each groups as group (group.label)}
				<div class="space-y-2">
					<p class="px-1 text-[10px] font-semibold uppercase tracking-[0.24em] text-[var(--text-muted)]">
						{group.label}
					</p>
					<div class="flex flex-wrap gap-1.5">
						{#each group.links as link (link.href)}
							<a
								href={link.href}
								class={`inline-flex items-center rounded-full border px-4 py-1.5 text-[0.85rem] font-medium transition active:scale-95 ${
									isActive(link.href)
										? 'border-[var(--border-color)] bg-[var(--hover-bg)] text-[var(--accent)] shadow-md'
										: 'border-transparent text-[var(--text-secondary)] hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]'
								}`}
								aria-current={isActive(link.href) ? 'page' : undefined}
							>
								{link.label}
								{#if link.href === '/admin/settings/users' && $newUserCount > 0}
									<span class="ml-1.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-[var(--accent)] px-1 text-[10px] font-bold text-[var(--bg-primary)]">
										{$newUserCount > 99 ? '99+' : $newUserCount}
									</span>
								{/if}
							</a>
						{/each}
					</div>
				</div>
			{/each}
		</nav>
	</section>

	{@render children?.()}
</div>
