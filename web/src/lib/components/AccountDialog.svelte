<script lang="ts">
	import Dialog from './Dialog.svelte';
	import { User, Mail, LogOut, X } from 'lucide-svelte';
	import { browser } from '$app/environment';
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	let { 
		open = $bindable(false)
	}: {
		open?: boolean;
	} = $props();

	// User data state
	let user = $state<{
		name: string;
		email: string;
		avatar: string;
	} | null>(null);

	let loading = $state(true);

	// Fetch user data when dialog opens
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
				// Extract user data from the response
				user = {
					name: data.name || data.email || 'User',
					email: data.email || '',
					avatar: `https://api.dicebear.com/7.x/avataaars/svg?seed=${encodeURIComponent(data.email || 'user')}`
				};
			}
		} catch (error) {
			console.error('Failed to fetch user data:', error);
		} finally {
			loading = false;
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
						<img 
							src={user.avatar} 
							alt={user.name}
							class="h-24 w-24 rounded-full border-2 border-[var(--hover-bg)]"
						/>
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
