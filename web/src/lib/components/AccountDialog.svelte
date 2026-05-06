<script lang="ts">
	import Dialog from './Dialog.svelte';
	import { User, Mail, LogOut, Users, Building2 } from 'lucide-svelte';
	import { browser } from '$app/environment';
	import { goto } from '$app/navigation';

	let {
		open = $bindable(false)
	}: {
		open?: boolean;
	} = $props();

	type UserState = {
		name: string;
		email: string;
		avatar: string;
		groups: string[];
		entraGroups: string[];
		role: string;
	};

	let user = $state<UserState | null>(null);
	let loading = $state(true);

	$effect(() => {
		if (open && !user && browser) {
			fetchUserData();
		}
	});

	const fetchUserData = async () => {
		loading = true;
		try {
			const response = await fetch('/api/auth/me', {
				credentials: 'include'
			});

			if (response.ok) {
				const data = await response.json();
				const email = data.email || '';
				user = {
					name: data.name || email || 'User',
					email,
					// Backend resolves picture: Microsoft Graph data URL when the user
					// has an EntraID photo, else Gravatar URL derived from email.
					avatar: data.picture || '',
					groups: Array.isArray(data.groups) ? data.groups : [],
					entraGroups: Array.isArray(data.entra_groups) ? data.entra_groups : [],
					role: data.role || ''
				};
			}
		} catch (error) {
			console.error('Failed to fetch user data:', error);
		} finally {
			loading = false;
		}
	};

	const groupLabel = (slug: string) => {
		switch (slug) {
			case 'admin':
				return 'Admin';
			case 'global_reader':
				return 'Global Reader';
			case 'default':
				return 'Default';
			default:
				return slug;
		}
	};

	const handleLogout = async () => {
		try {
			const response = await fetch('/api/auth/logout', {
				method: 'POST',
				credentials: 'include'
			});

			if (response.ok || response.status === 204) {
				if (browser) {
					goto('/auth/login');
				}
			}
		} catch (error) {
			console.error('Logout failed:', error);
		}
	};
</script>

<Dialog bind:open>
	<!-- Content -->
	<div class="relative flex w-full flex-col overflow-y-auto px-4 text-sm p-8 md:p-8">
		<div class="border-b border-[var(--hover-bg)] py-3">
			<h3 class="text-lg font-normal text-[var(--text-bright)]">Account</h3>
		</div>

		{#if loading}
			<div class="flex items-center justify-center py-12">
				<div class="text-sm text-[var(--text-secondary)]">Loading...</div>
			</div>
		{:else if user}
			<!-- User Info Section -->
			<div class="space-y-6 py-6">
				<!-- Avatar -->
				<div class="flex justify-center">
					<div class="relative">
						{#if user.avatar}
							<img
								src={user.avatar}
								alt={user.name}
								referrerpolicy="no-referrer"
								class="h-24 w-24 rounded-full border-2 border-[var(--hover-bg)] object-cover"
							/>
						{:else}
							<div class="flex h-24 w-24 items-center justify-center rounded-full border-2 border-[var(--hover-bg)] bg-[var(--hover-bg)] text-2xl font-medium text-[var(--text-bright)]">
								{(user.name || user.email || '?').slice(0, 1).toUpperCase()}
							</div>
						{/if}
					</div>
				</div>

				<!-- User Details -->
				<div class="space-y-4">
					<div class="rounded-lg border border-[var(--hover-bg)] bg-[var(--card-bg)]/40 p-4">
						<div class="flex items-center gap-3">
							<div class="flex h-10 w-10 items-center justify-center rounded-full bg-[var(--hover-bg)]">
								<User size={18} class="text-[var(--text-bright)]" />
							</div>
							<div class="flex-1 min-w-0">
								<div class="text-xs text-[var(--text-quaternary)] mb-1">Name</div>
								<div class="text-sm font-medium text-[var(--text-bright)] truncate">{user.name}</div>
							</div>
						</div>
					</div>

					<div class="rounded-lg border border-[var(--hover-bg)] bg-[var(--card-bg)]/40 p-4">
						<div class="flex items-center gap-3">
							<div class="flex h-10 w-10 items-center justify-center rounded-full bg-[var(--hover-bg)]">
								<Mail size={18} class="text-[var(--text-bright)]" />
							</div>
							<div class="flex-1 min-w-0">
								<div class="text-xs text-[var(--text-quaternary)] mb-1">Email</div>
								<div class="text-sm font-medium text-[var(--text-bright)] truncate">{user.email}</div>
							</div>
						</div>
					</div>

					<div class="rounded-lg border border-[var(--hover-bg)] bg-[var(--card-bg)]/40 p-4">
						<div class="flex items-start gap-3">
							<div class="flex h-10 w-10 items-center justify-center rounded-full bg-[var(--hover-bg)]">
								<Users size={18} class="text-[var(--text-bright)]" />
							</div>
							<div class="flex-1 min-w-0">
								<div class="text-xs text-[var(--text-quaternary)] mb-2">Groups</div>
								{#if user.groups.length > 0}
									<div class="flex flex-wrap gap-1.5">
										{#each user.groups as slug (slug)}
											<span class="inline-flex items-center rounded-full border border-[var(--hover-bg)] bg-[var(--hover-bg)]/40 px-2.5 py-0.5 text-xs font-medium text-[var(--text-bright)]">
												{groupLabel(slug)}
											</span>
										{/each}
									</div>
								{:else}
									<div class="text-sm text-[var(--text-secondary)]">No groups</div>
								{/if}
							</div>
						</div>
					</div>

					{#if user.entraGroups.length > 0}
						<div class="rounded-lg border border-[var(--hover-bg)] bg-[var(--card-bg)]/40 p-4">
							<div class="flex items-start gap-3">
								<div class="flex h-10 w-10 items-center justify-center rounded-full bg-[var(--hover-bg)]">
									<Building2 size={18} class="text-[var(--text-bright)]" />
								</div>
								<div class="flex-1 min-w-0">
									<div class="text-xs text-[var(--text-quaternary)] mb-2">EntraID Groups ({user.entraGroups.length})</div>
									<div class="max-h-48 overflow-y-auto pr-1">
										<div class="flex flex-wrap gap-1.5">
											{#each user.entraGroups as name (name)}
												<span class="inline-flex items-center rounded-full border border-[var(--hover-bg)] bg-[var(--hover-bg)]/40 px-2.5 py-0.5 text-xs font-medium text-[var(--text-bright)]">
													{name}
												</span>
											{/each}
										</div>
									</div>
								</div>
							</div>
						</div>
					{/if}
				</div>
			</div>

			<!-- Logout Button -->
			<div class="border-t border-[var(--hover-bg)] pt-4 mt-auto">
				<button 
					type="button"
					class="flex w-full items-center justify-center gap-3 rounded-full bg-[var(--error)]/10 px-5 py-3 text-base font-medium text-[var(--error)] transition-all duration-200 hover:bg-[var(--error)]/20"
					onclick={handleLogout}
				>
					<LogOut size={20} />
					<span>Log Out</span>
				</button>
			</div>
		{:else}
			<div class="flex items-center justify-center py-12">
				<div class="text-sm text-[var(--text-secondary)]">Failed to load user data</div>
			</div>
		{/if}
	</div>
</Dialog>
