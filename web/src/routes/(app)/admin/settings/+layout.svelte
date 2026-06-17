<script lang="ts">
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import TabSelector from '$lib/components/TabSelector.svelte';
	import SettingsOverviewCards from '$lib/components/settings/SettingsOverviewCards.svelte';
	import { newUserCount } from '$lib/stores/newUserCount';

	type TabOption = { value: string; label: string; badge?: number };

	let { children } = $props();

	// Two groups: configuration on the left, operational/read-mostly
	// monitoring on the right. Tab values are real routes so deep links
	// and back/forward work, and each page stays its own code-split chunk.
	const settingsTabs = $derived<TabOption[]>([
		{ value: '/admin/settings/providers', label: 'Providers' },
		{ value: '/admin/settings/scanners', label: 'Scanners' },
		{ value: '/admin/settings/ai', label: 'AI' },
		{ value: '/admin/settings/users', label: 'Users', badge: $newUserCount },
		{ value: '/admin/settings/namespaces', label: 'Namespaces' }
	]);

	const monitoringTabs: TabOption[] = [
		{ value: '/admin/settings/jobs', label: 'Jobs' },
		{ value: '/admin/settings/database', label: 'Database' },
		{ value: '/admin/settings/fleet', label: 'Fleet' }
	];

	const path = $derived($page.url?.pathname ?? '');

	// '' when the current route belongs to the other group — the
	// selector then renders with no indicator (see TabSelector).
	const activeTab = (tabs: TabOption[]) =>
		tabs.find((t) => path === t.value || path.startsWith(`${t.value}/`))?.value ?? '';

	const settingsValue = $derived(activeTab(settingsTabs));
	const monitoringValue = $derived(activeTab(monitoringTabs));

	const navigate = (href: string) => {
		if (href && href !== path) goto(href);
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

		<SettingsOverviewCards />

		<nav class="flex flex-wrap items-end gap-x-10 gap-y-5" aria-label="Settings sections">
			<div class="space-y-2">
				<p class="px-1 text-[10px] font-semibold uppercase tracking-[0.24em] text-[var(--text-muted)]">
					Settings
				</p>
				<TabSelector options={settingsTabs} value={settingsValue} onchange={navigate} showLines={false} />
			</div>
			<div class="space-y-2">
				<p class="px-1 text-[10px] font-semibold uppercase tracking-[0.24em] text-[var(--text-muted)]">
					Monitoring
				</p>
				<TabSelector options={monitoringTabs} value={monitoringValue} onchange={navigate} showLines={false} />
			</div>
		</nav>
	</section>

	{@render children?.()}
</div>
