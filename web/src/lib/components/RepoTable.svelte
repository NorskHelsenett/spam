<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		columns: { key: string; label: string; align?: 'left' | 'center' | 'right' }[];
		children: Snippet;
	}

	let { columns, children }: Props = $props();
</script>

<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
	<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
		<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
			<tr>
				{#each columns as col}
					<th
						class="px-5 py-3"
						class:text-left={col.align === 'left' || !col.align}
						class:text-center={col.align === 'center'}
						class:text-right={col.align === 'right'}
					>
						{col.label}
					</th>
				{/each}
			</tr>
		</thead>
		<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
			{@render children()}
		</tbody>
	</table>
</div>
