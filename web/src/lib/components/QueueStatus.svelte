<script lang="ts">
	import { CheckCircle } from 'lucide-svelte';

	type Props = {
		state: { done: boolean; total: number; errors: string[] };
		singular?: string;
		plural?: string;
	};

	let { state, singular = 'item', plural = 'items' }: Props = $props();

	const noun = (n: number) => (n === 1 ? singular : plural);
</script>

<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
	<div class="flex items-center gap-2 text-sm">
		{#if state.done}
			<CheckCircle class="h-4 w-4 shrink-0 text-[var(--success)]" />
			<span class="text-[var(--text-secondary)]">Added {state.total} {noun(state.total)} to queue</span>
		{:else}
			<div class="h-4 w-4 shrink-0 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
			<span class="text-[var(--text-secondary)]">Adding {state.total > 0 ? state.total + ' ' : ''}{noun(state.total)} to queue…</span>
		{/if}
	</div>
	{#if state.errors.length > 0}
		<div class="mt-3 space-y-1">
			<p class="text-xs font-medium text-[var(--error)]">{state.errors.length} errors:</p>
			{#each state.errors.slice(0, 5) as error}
				<p class="text-xs text-[var(--error)]">{error}</p>
			{/each}
			{#if state.errors.length > 5}
				<p class="text-xs text-[var(--text-muted)]">... and {state.errors.length - 5} more</p>
			{/if}
		</div>
	{/if}
</div>
