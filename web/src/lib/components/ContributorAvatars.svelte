<script lang="ts">
	import UserHoverCard, { type User } from './UserHoverCard.svelte';

	export type Contributor = User & { contributions?: number };

	interface Props {
		contributors: Contributor[];
		max?: number;
	}

	let { contributors = [], max = 8 }: Props = $props();
</script>

<div class="flex items-center gap-2">
	<div class="flex -space-x-1.5">
		{#each contributors.slice(0, max) as c, i (i)}
			<UserHoverCard user={c}>
				{#if c.avatar_url}
					<img
						class="h-5 w-5 rounded-full ring-1 ring-[var(--bg-soft)]"
						src={c.avatar_url}
						alt={c.login || c.name || ''}
					/>
				{:else}
					<div class="flex h-5 w-5 items-center justify-center rounded-full bg-[var(--hover-bg)] text-[8px] font-semibold text-[var(--text-muted)] ring-1 ring-[var(--bg-soft)]">
						{(c.login || c.name || '?')[0].toUpperCase()}
					</div>
				{/if}
			</UserHoverCard>
		{/each}
	</div>
	{#if contributors.length <= 3}
		<span class="text-[10px] text-[var(--text-muted)]">{contributors.map(c => c.login || c.name).join(', ')}</span>
	{:else if contributors.length > max}
		<span class="text-[10px] text-[var(--text-muted)]">+{contributors.length - max} more</span>
	{:else}
		<span class="text-[10px] text-[var(--text-muted)]">{contributors[0]?.login || contributors[0]?.name}{contributors.length > 1 ? ` +${contributors.length - 1}` : ''}</span>
	{/if}
</div>
