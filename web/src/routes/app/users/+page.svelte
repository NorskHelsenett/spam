<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';

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

	let users: UserSummary[] = $state([]);
	let loading = $state(true);
	let error = $state('');
	let savingUser = $state<string | null>(null);

	const loadUsers = async () => {
		loading = true;
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
			<button
				type="button"
				class="rounded-full border border-[var(--border-color)] px-4 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
				onclick={loadUsers}
			>
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
									<span class="inline-flex items-center gap-2 rounded-full border border-[var(--border-color)] px-3 py-1 text-xs">
										{user.approved ? 'Approved' : 'Pending'}
									</span>
								</td>
								<td class="px-5 py-3">
									<select
										class="rounded-full border border-[var(--border-color)] bg-transparent px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:text-[var(--text-bright)]"
										disabled={savingUser === user.id}
										onchange={(event) => updateRole(user, (event.target as HTMLSelectElement).value)}
									>
										<option value="pending" selected={user.role === 'pending'}>Pending</option>
										<option value="default" selected={user.role === 'default'}>Default</option>
										<option value="global_reader" selected={user.role === 'global_reader'}>Global reader</option>
										<option value="admin" selected={user.role === 'admin'}>Admin</option>
									</select>
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
