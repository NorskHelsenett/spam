<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { slide } from 'svelte/transition';
	import Select from '$lib/components/Select.svelte';
	import Toggle from '$lib/components/Toggle.svelte';
	import RotateCw from 'lucide-svelte/icons/rotate-cw';
	import X from 'lucide-svelte/icons/x';
	import RotateCcw from 'lucide-svelte/icons/rotate-ccw';
	import { newUserCount, newUserEvent } from '$lib/stores/newUserCount';

	type UserSummary = {
		id: string;
		subject: string;
		email?: string;
		name?: string;
		picture?: string;
		approved: boolean;
		hidden: boolean;
		role: string;
		groups: string[];
		last_login_at?: string;
		created_at: string;
	};

	const VISIBLE_GROUPS = 6;

	const initials = (user: UserSummary) => {
		const source = user.name || user.email || user.subject || '?';
		const parts = source.trim().split(/[\s@._-]+/).filter(Boolean);
		if (parts.length === 0) return '?';
		if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
		return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
	};

	const dateFmt = new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
	const formatDate = (iso?: string) => {
		if (!iso) return '—';
		const d = new Date(iso);
		return Number.isNaN(d.getTime()) ? '—' : dateFmt.format(d);
	};
	const formatRelative = (iso?: string) => {
		if (!iso) return 'never';
		const d = new Date(iso);
		if (Number.isNaN(d.getTime())) return '—';
		const diff = Date.now() - d.getTime();
		const min = Math.round(diff / 60_000);
		if (min < 1) return 'just now';
		if (min < 60) return `${min}m ago`;
		const hr = Math.round(min / 60);
		if (hr < 24) return `${hr}h ago`;
		const day = Math.round(hr / 24);
		if (day < 30) return `${day}d ago`;
		return dateFmt.format(d);
	};

	const roleOptions = [
		{ value: 'pending', label: 'Pending' },
		{ value: 'default', label: 'Default' },
		{ value: 'global_reader', label: 'Global reader' },
		{ value: 'admin', label: 'Admin' }
	];

	let users: UserSummary[] = $state([]);
	let loading = $state(true);
	let error = $state('');
	let savingUser = $state<string | null>(null);
	let refreshing = $state(false);
	let showHidden = $state(false);

	const visibleUsers = $derived(
		showHidden ? users : users.filter((u) => !u.hidden)
	);

	const loadUsers = async () => {
		loading = true;
		refreshing = true;
		error = '';
		try {
			const response = await fetch('/api/admin/users', { credentials: 'include' });
			if (!response.ok) {
				error = response.status === 403 ? 'Admin access required.' : 'Failed to load users.';
				users = [];
				return;
			}
			users = await response.json();
		} catch {
			error = 'Failed to load users.';
		} finally {
			loading = false;
			setTimeout(() => { refreshing = false; }, 1000);
		}
	};

	const setHidden = async (user: UserSummary, hidden: boolean) => {
		try {
			const response = await fetch(`/api/admin/users/${user.id}/hidden`, {
				method: 'PATCH',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ hidden })
			});
			if (!response.ok) return;
			const updated = await response.json();
			users = users.map((u) => (u.id === updated.id ? updated : u));
		} catch {
			// ignore
		}
	};

	const updateRole = async (user: UserSummary, role: string) => {
		savingUser = user.id;
		try {
			const response = await fetch(`/api/admin/users/${user.id}`, {
				method: 'PATCH',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ role })
			});
			if (!response.ok) {
				error = 'Failed to update role.';
				return;
			}
			const updated = await response.json();
			users = users.map((entry) => (entry.id === updated.id ? updated : entry));
		} catch {
			error = 'Failed to update role.';
		} finally {
			savingUser = null;
		}
	};

	$effect(() => {
		const incoming = $newUserEvent;
		if (!incoming) return;
		newUserEvent.set(null);
		newUserCount.update((n) => Math.max(0, n - 1));
		if (!users.some((u) => u.id === incoming.id)) {
			users = [...users, incoming];
		}
	});

	onMount(() => {
		if (browser) {
			newUserCount.set(0);
			loadUsers();
		}
	});
</script>

<svelte:head>
	<title>User Access • Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Users</h1>
				<p class="text-sm text-[var(--text-tertiary)]">Approve new access requests and adjust roles.</p>
			</div>
			<div class="flex items-center gap-4">
				<Toggle bind:checked={showHidden} label="Show hidden" />
				<button type="button" class="btn btn-ghost" onclick={loadUsers} disabled={refreshing}>
					<span class="inline-flex h-[14px] w-[14px] items-center justify-center {refreshing ? 'animate-spin' : ''}">
						<RotateCw size={14} />
					</span>
					Refresh
				</button>
			</div>
		</header>

		{#if error}
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">{error}</div>
		{/if}

		{#if loading}
			<p class="text-sm text-[var(--text-secondary)]">Loading users…</p>
		{:else if visibleUsers.length === 0}
			<p class="text-sm text-[var(--text-secondary)]">No users found.</p>
		{:else}
			<ul class="divide-y divide-[var(--border-color)]/40 overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
				{#each visibleUsers as user (user.id)}
					<li
						transition:slide={{ duration: 200 }}
						class="flex items-start gap-4 px-5 py-4 text-sm transition hover:bg-[var(--hover-bg-subtle)]"
						class:opacity-60={user.hidden}
					>
						<div class="shrink-0 pt-0.5">
							{#if user.picture}
								<img
									src={user.picture}
									alt=""
									class="h-10 w-10 rounded-full object-cover ring-1 ring-[var(--border-color)]/60"
									referrerpolicy="no-referrer"
								/>
							{:else}
								<div class="flex h-10 w-10 items-center justify-center rounded-full bg-[var(--hover-bg)] text-[11px] font-semibold uppercase text-[var(--text-secondary)] ring-1 ring-[var(--border-color)]/60">
									{initials(user)}
								</div>
							{/if}
						</div>

						<div class="min-w-0 flex-1 space-y-1.5">
							<div class="flex flex-wrap items-baseline gap-x-3 gap-y-0.5">
								<span class="truncate font-semibold text-[var(--text-bright)]">{user.name ?? '—'}</span>
								<span class="truncate text-xs text-[var(--text-secondary)]">{user.email ?? '—'}</span>
							</div>

							<div class="flex flex-wrap items-center gap-1.5">
								{#each user.groups.slice(0, VISIBLE_GROUPS) as group}
									<span class="rounded-full border border-[var(--border-color)]/60 bg-[var(--hover-bg)]/30 px-2 py-0.5 text-[10px] uppercase tracking-[0.08em] text-[var(--text-secondary)]">
										{group}
									</span>
								{/each}
								{#if user.groups.length > VISIBLE_GROUPS}
									<span
										class="rounded-full border border-[var(--border-color)]/60 px-2 py-0.5 text-[10px] uppercase tracking-[0.08em] text-[var(--text-tertiary)]"
										title={user.groups.slice(VISIBLE_GROUPS).join(', ')}
									>
										+{user.groups.length - VISIBLE_GROUPS} more
									</span>
								{:else if user.groups.length === 0}
									<span class="text-[10px] uppercase tracking-[0.08em] text-[var(--text-tertiary)]">No groups</span>
								{/if}
							</div>

							<div class="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[10px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
								<span>Created {formatDate(user.created_at)}</span>
								<span aria-hidden="true">·</span>
								<span>Last seen {formatRelative(user.last_login_at)}</span>
							</div>
						</div>

						<div class="flex shrink-0 items-center gap-3 pt-0.5">
							<span class="badge">{user.approved ? 'Approved' : 'Pending'}</span>
							<Select
								value={user.role}
								options={roleOptions}
								disabled={savingUser === user.id}
								size="sm"
								onchange={(value) => updateRole(user, value)}
							/>
							{#if user.hidden}
								<button
									type="button"
									class="rounded-full p-1 text-[var(--text-tertiary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-secondary)]"
									onclick={() => setHidden(user, false)}
									aria-label="Restore user"
									title="Restore"
								>
									<RotateCcw size={14} />
								</button>
							{:else}
								<button
									type="button"
									class="rounded-full p-1 text-[var(--text-tertiary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-secondary)]"
									onclick={() => setHidden(user, true)}
									aria-label="Hide user"
									title="Hide"
								>
									<X size={14} />
								</button>
							{/if}
						</div>
					</li>
				{/each}
			</ul>
		{/if}
	</section>
</div>
