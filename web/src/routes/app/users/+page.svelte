<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import Select from '$lib/components/Select.svelte';
	import RotateCw from 'lucide-svelte/icons/rotate-cw';

	type UserSummary = {
		id: string;
		subject: string;
		email?: string;
		name?: string;
		approved: boolean;
		role: string;
		groups: string[];
		last_login_at?: string;
		created_at: string;
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

	const loadUsers = async () => {
		loading = true;
		refreshing = true;
		error = '';
		try {
			const response = await fetch('/api/admin/users', {
				credentials: 'include'
			});
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

	const updateRole = async (user: UserSummary, role: string) => {
		savingUser = user.id;
		try {
			const response = await fetch(`/api/admin/users/${user.id}`, {
				method: 'PATCH',
				credentials: 'include',
				headers: {
					'Content-Type': 'application/json'
				},
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

	onMount(() => {
		if (browser) {
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
			<button type="button" class="btn btn-ghost" onclick={loadUsers} disabled={refreshing}>
				<span class="inline-flex h-[14px] w-[14px] items-center justify-center {refreshing ? 'animate-spin' : ''}">
					<RotateCw size={14} />
				</span>
				Refresh
			</button>
		</header>

		{#if error}
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">{error}</div>
		{/if}

		{#if loading}
			<p class="text-sm text-[var(--text-secondary)]">Loading users…</p>
		{:else if users.length === 0}
			<p class="text-sm text-[var(--text-secondary)]">No users found.</p>
		{:else}
			<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
				<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
					<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
						<tr>
							<th class="px-5 py-3 text-left">Name</th>
							<th class="px-5 py-3 text-left">Email</th>
							<th class="px-5 py-3 text-left">Subject</th>
							<th class="px-5 py-3 text-left">Status</th>
							<th class="px-5 py-3 text-left">Role</th>
							<th class="px-5 py-3 text-left">Created</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
						{#each users as user}
							<tr class="transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]">
								<td class="px-5 py-3 font-semibold text-[var(--text-bright)]">{user.name ?? '—'}</td>
								<td class="px-5 py-3">{user.email ?? '—'}</td>
								<td class="px-5 py-3 text-xs">{user.subject}</td>
								<td class="px-5 py-3">
									<span class="badge">
										{user.approved ? 'Approved' : 'Pending'}
									</span>
								</td>
								<td class="px-5 py-3">
									<Select
										value={user.role}
										options={roleOptions}
										disabled={savingUser === user.id}
										size="sm"
										onchange={(value) => updateRole(user, value)}
									/>
								</td>
								<td class="px-5 py-3 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
									{user.created_at}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</section>
</div>
