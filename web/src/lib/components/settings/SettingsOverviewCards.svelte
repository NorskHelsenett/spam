<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';

	type UserCountRow = { approved: boolean; hidden: boolean; role: string };

	// Headline counts only — each card links to the tab that owns the
	// full view. Every fetch soft-fails to '—' so one failing endpoint
	// doesn't take the hub header down with it.
	let users = $state<UserCountRow[]>([]);
	let usersLoaded = $state(false);
	let providerCount = $state<number | null>(null);
	let osvScanned = $state<number | null>(null);
	let osvVulns = $state<number | null>(null);
	let sbomScanned = $state<number | null>(null);
	let sbomPending = $state<number | null>(null);
	let dbSizeBytes = $state<number | null>(null);
	let dbTableCount = $state<number | null>(null);

	const approvedUsers = $derived(users.filter((u) => u.approved && !u.hidden));
	const adminCount = $derived(approvedUsers.filter((u) => u.role === 'admin').length);
	const readerCount = $derived(approvedUsers.filter((u) => u.role === 'global_reader').length);
	const defaultCount = $derived(approvedUsers.filter((u) => u.role === 'default').length);
	const pendingCount = $derived(users.filter((u) => !u.approved && !u.hidden).length);

	const formatBytes = (bytes: number | null) => {
		if (bytes == null) return '—';
		if (bytes < 1024) return `${bytes} B`;
		const units = ['KB', 'MB', 'GB', 'TB'];
		let value = bytes / 1024;
		let i = 0;
		while (value >= 1024 && i < units.length - 1) {
			value /= 1024;
			i++;
		}
		return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[i]}`;
	};

	const fetchJson = async (url: string) => {
		const response = await fetch(url, { credentials: 'include' });
		if (!response.ok) throw new Error(`${response.status}`);
		return response.json();
	};

	onMount(() => {
		if (!browser) return;
		fetchJson('/api/admin/users')
			.then((data) => {
				users = Array.isArray(data) ? data : [];
				usersLoaded = true;
			})
			.catch(() => {});
		fetchJson('/api/admin/providers')
			.then((data) => {
				providerCount = Array.isArray(data) ? data.length : null;
			})
			.catch(() => {});
		fetchJson('/api/admin/osv/scan/status')
			.then((data) => {
				osvScanned = data?.result?.scanned ?? null;
				osvVulns = data?.result?.vulns_found ?? null;
			})
			.catch(() => {});
		fetchJson('/api/admin/sbom/scan/status')
			.then((data) => {
				sbomScanned = data?.scanned_count ?? null;
				sbomPending = data?.pending_count ?? null;
			})
			.catch(() => {});
		fetchJson('/api/admin/db/storage')
			.then((data) => {
				dbSizeBytes = typeof data.database_bytes === 'number' ? data.database_bytes : null;
				dbTableCount = typeof data.table_count === 'number' ? data.table_count : null;
			})
			.catch(() => {});
	});
</script>

<div class="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
	<a
		href="/admin/settings/users"
		class="metric-card space-y-1 rounded-2xl p-4 transition hover:bg-[var(--hover-bg-subtle)]"
	>
		<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Users</h3>
		<p class="text-2xl font-bold text-[var(--text-bright)]">{usersLoaded ? approvedUsers.length : '—'}</p>
		<p class="text-xs text-[var(--text-muted)]">
			{usersLoaded ? `${adminCount} admin · ${readerCount} reader · ${defaultCount} default` : ''}
		</p>
	</a>
	<a
		href="/admin/settings/users"
		class="metric-card space-y-1 rounded-2xl p-4 transition hover:bg-[var(--hover-bg-subtle)]"
	>
		<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Pending</h3>
		<p class="text-2xl font-bold {usersLoaded && pendingCount > 0 ? 'text-amber-400' : 'text-[var(--text-bright)]'}">
			{usersLoaded ? pendingCount : '—'}
		</p>
		<p class="text-xs text-[var(--text-muted)]">awaiting approval</p>
	</a>
	<a
		href="/admin/settings/providers"
		class="metric-card space-y-1 rounded-2xl p-4 transition hover:bg-[var(--hover-bg-subtle)]"
	>
		<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Providers</h3>
		<p class="text-2xl font-bold text-[var(--text-bright)]">{providerCount ?? '—'}</p>
		<p class="text-xs text-[var(--text-muted)]">configured sources</p>
	</a>
	<a
		href="/admin/settings/scanners"
		class="metric-card space-y-1 rounded-2xl p-4 transition hover:bg-[var(--hover-bg-subtle)]"
	>
		<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">OSV</h3>
		<p class="text-2xl font-bold text-[var(--text-bright)]">{osvScanned ?? '—'}</p>
		<p class="text-xs text-[var(--text-muted)]">{osvVulns != null ? `${osvVulns} vulns found` : 'components scanned'}</p>
	</a>
	<a
		href="/admin/settings/scanners"
		class="metric-card space-y-1 rounded-2xl p-4 transition hover:bg-[var(--hover-bg-subtle)]"
	>
		<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">SBOM scan</h3>
		<p class="text-2xl font-bold text-[var(--text-bright)]">{sbomScanned ?? '—'}</p>
		<p class="text-xs text-[var(--text-muted)]">{sbomPending != null ? `${sbomPending} pending` : 'SBOMs scanned'}</p>
	</a>
	<a
		href="/admin/settings/database"
		class="metric-card space-y-1 rounded-2xl p-4 transition hover:bg-[var(--hover-bg-subtle)]"
	>
		<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Database</h3>
		<p class="text-2xl font-bold text-[var(--text-bright)]">{formatBytes(dbSizeBytes)}</p>
		<p class="text-xs text-[var(--text-muted)]">{dbTableCount != null ? `${dbTableCount} tables` : 'storage used'}</p>
	</a>
</div>
