<script lang="ts">
	import { browser } from '$app/environment';
	import type { Snippet } from 'svelte';
	import HoverCard from './HoverCard.svelte';

	export type User = {
		login?: string;
		name?: string;
		email?: string;
		avatar_url?: string;
		profile_url?: string;
	};

	interface Props {
		user: User;
		children: Snippet;
	}

	let { user, children }: Props = $props();

	let copiedEmail = $state('');
	let copiedTimer: ReturnType<typeof setTimeout> | null = null;

	const copyEmail = async () => {
		if (!user.email || !browser) return;
		await navigator.clipboard.writeText(user.email);
		copiedEmail = user.email;
		if (copiedTimer) clearTimeout(copiedTimer);
		copiedTimer = setTimeout(() => { copiedEmail = ''; }, 1400);
	};
</script>

<HoverCard>
	{@render children()}
	{#snippet content()}
		<button
			type="button"
			class="user-tip-button"
			onclick={copyEmail}
			disabled={!user.email}
		>
			{#if user.avatar_url}
				<img src={user.avatar_url} alt={user.login || user.name || ''} class="mb-2 h-10 w-10 rounded-full" />
			{:else}
				<div class="mb-2 flex h-10 w-10 items-center justify-center rounded-full bg-[var(--hover-bg)] text-sm font-semibold text-[var(--text-secondary)]">
					{(user.login || user.name || '?')[0].toUpperCase()}
				</div>
			{/if}
			<p class="text-[11px] font-semibold text-[var(--text-bright)]">{user.login || user.name || '—'}</p>
			{#if user.name && user.login && user.name !== user.login}
				<p class="text-[10px] text-[var(--text-secondary)]">{user.name}</p>
			{/if}
			{#if user.email}
				<p class="mt-0.5 w-full break-all text-[10px] text-[var(--text-muted)]">{user.email}</p>
				<p class="mt-1 text-[9px] text-[var(--text-tertiary)]">{copiedEmail === user.email ? 'Copied!' : 'Click to copy email'}</p>
			{:else}
				<p class="mt-1 text-[9px] text-[var(--text-muted)]">No email available</p>
			{/if}
		</button>
	{/snippet}
</HoverCard>

<style>
	:global(.user-tip-button) {
		all: unset;
		display: flex;
		flex-direction: column;
		align-items: center;
		width: 100%;
		text-align: center;
		cursor: pointer;
	}

	:global(.user-tip-button:disabled) {
		cursor: default;
	}
</style>
