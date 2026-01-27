<script lang="ts">
	interface Props {
		page: number;
		totalCount?: number;
		pageSize: number;
		hasNextPage: boolean;
		loading: boolean;
		onPrevious: () => void;
		onNext: () => void;
	}

	let { page, totalCount = 0, pageSize, hasNextPage, loading, onPrevious, onNext }: Props = $props();

	const totalPages = $derived(totalCount > 0 ? Math.ceil(totalCount / pageSize) : 0);
</script>

<div class="flex items-center justify-between pt-2">
	<p class="text-xs text-[var(--text-muted)]">
		Page {page}
		{#if totalPages > 0}
			of {totalPages}
		{:else if totalCount > 0}
			({totalCount} total)
		{/if}
	</p>
	<div class="flex gap-2">
		<button
			type="button"
			class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
			disabled={page <= 1 || loading}
			onclick={onPrevious}
		>
			Previous
		</button>
		<button
			type="button"
			class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
			disabled={!hasNextPage || loading}
			onclick={onNext}
		>
			Next
		</button>
	</div>
</div>
