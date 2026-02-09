<script lang="ts">
	import type { Snippet } from 'svelte';

	interface Props {
		columns: { key: string; label: string; align?: 'left' | 'center' | 'right'; sortable?: boolean }[];
		children: Snippet;
		sortColumn?: string;
		sortDirection?: 'asc' | 'desc';
		onSort?: (column: string) => void;
	}

	let { columns, children, sortColumn, sortDirection, onSort }: Props = $props();
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
						class:cursor-pointer={col.sortable !== false && col.key !== 'actions' && col.key !== 'status'}
						class:hover:text-[var(--text-secondary)]={col.sortable !== false && col.key !== 'actions' && col.key !== 'status'}
						class:transition={col.sortable !== false && col.key !== 'actions' && col.key !== 'status'}
						onclick={() => col.sortable !== false && col.key !== 'actions' && col.key !== 'status' && onSort?.(col.key)}
					>
						{#if col.sortable !== false && col.key !== 'actions' && col.key !== 'status'}
							<span 
								class="inline-flex items-center gap-1"
								class:justify-center={col.align === 'center'}
								class:justify-end={col.align === 'right'}
							>
								{col.label}
								<span class="w-3 text-center" class:text-[var(--accent)]={sortColumn === col.key} class:text-transparent={sortColumn !== col.key}>
									{sortColumn === col.key ? (sortDirection === 'asc' ? '↑' : '↓') : '↑'}
								</span>
							</span>
						{:else}
							{col.label}
						{/if}
					</th>
				{/each}
			</tr>
		</thead>
		<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
			{@render children()}
		</tbody>
	</table>
</div>
