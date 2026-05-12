<script lang="ts" context="module">
	export type RunTableBadge = {
		label: string;
		tone?: 'neutral' | 'success' | 'warning' | 'danger' | 'info';
		title?: string;
	};

	export type RunTableItem = {
		id: string;
		href: string;
		status: string;
		started_at?: string;
		finished_at?: string;
		duration_ms?: number;
		commit_sha?: string;
		badges?: RunTableBadge[];
	};
</script>

<script lang="ts">
	import { goto } from '$app/navigation';
	import { Loader2 } from 'lucide-svelte';

	let {
		runs = []
	}: {
		runs: RunTableItem[];
	} = $props();

	const statusClass = (status: string) => {
		switch (status?.toUpperCase()) {
			case 'SUCCEEDED': return 'border-green-500/30 bg-green-500/10 text-green-400';
			case 'FAILED':    return 'border-red-500/30 bg-red-500/10 text-red-400';
			case 'RUNNING':   return 'border-blue-500/30 bg-blue-500/10 text-blue-400';
			case 'PENDING':   return 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400';
			default:          return 'border-[var(--border-color)] bg-[var(--hover-bg)] text-[var(--text-tertiary)]';
		}
	};

	const badgeClass = (tone: RunTableBadge['tone'] = 'neutral') => {
		switch (tone) {
			case 'success': return 'border-green-500/25 bg-green-500/10 text-green-400';
			case 'warning': return 'border-amber-500/25 bg-amber-500/10 text-amber-300';
			case 'danger':  return 'border-red-500/25 bg-red-500/10 text-red-400';
			case 'info':    return 'border-blue-500/25 bg-blue-500/10 text-blue-400';
			default:        return 'border-[var(--border-color)]/60 bg-[var(--hover-bg)] text-[var(--text-secondary)]';
		}
	};

	const formatDateTime = (iso: string | undefined) => {
		if (!iso) return '—';
		const d = new Date(iso);
		if (Number.isNaN(d.getTime())) return '—';
		return d.toLocaleString();
	};

	const formatDurationMs = (ms: number | undefined) => {
		if (!ms || ms <= 0) return '';
		const secs = Math.floor(ms / 1000);
		if (secs < 60) return `${secs}s`;
		const mins = Math.floor(secs / 60);
		if (mins < 60) return `${mins}m ${secs % 60}s`;
		const hours = Math.floor(mins / 60);
		return `${hours}h ${mins % 60}m`;
	};

	const formatDuration = (run: RunTableItem) => {
		const fromMs = formatDurationMs(run.duration_ms);
		if (fromMs) return fromMs;
		if (!run.started_at || !run.finished_at) return '—';
		const start = new Date(run.started_at).getTime();
		const end = new Date(run.finished_at).getTime();
		if (Number.isNaN(start) || Number.isNaN(end) || end < start) return '—';
		return formatDurationMs(end - start) || '—';
	};
</script>

<div class="overflow-hidden rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
	<table class="min-w-full table-fixed divide-y divide-[var(--border-color)]/40 text-sm">
		<thead class="text-[10px] uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
			<tr>
				<th class="w-[18%] px-4 py-2.5 text-left">Status</th>
				<th class="w-[22%] px-4 py-2.5 text-left">Started</th>
				<th class="w-[14%] px-4 py-2.5 text-left">Duration</th>
				<th class="w-[18%] px-4 py-2.5 text-left">Commit</th>
				<th class="px-4 py-2.5 text-left">Artifacts</th>
			</tr>
		</thead>
		<tbody class="divide-y divide-[var(--border-color)]/25 text-[var(--text-secondary)]">
			{#each runs as run (run.id)}
				<!-- svelte-ignore a11y_no_static_element_interactions -->
				<tr class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)]" onclick={() => goto(run.href)}>
					<td class="px-4 py-3">
						<span class="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium {statusClass(run.status)}">
							{#if run.status?.toUpperCase() === 'RUNNING'}
								<Loader2 class="h-3 w-3 animate-spin" />
							{/if}
							{run.status || 'UNKNOWN'}
						</span>
					</td>
					<td class="px-4 py-3 text-xs text-[var(--text-tertiary)]">{formatDateTime(run.started_at || run.finished_at)}</td>
					<td class="px-4 py-3 text-xs text-[var(--text-tertiary)]">{formatDuration(run)}</td>
					<td class="px-4 py-3">
						{#if run.commit_sha}
							<span class="font-mono text-xs text-[var(--accent)]">{run.commit_sha.slice(0, 7)}</span>
						{:else}
							<span class="text-xs text-[var(--text-muted)]">—</span>
						{/if}
					</td>
					<td class="px-4 py-3">
						{#if run.badges && run.badges.length > 0}
							<div class="flex flex-wrap gap-1.5">
								{#each run.badges as badge}
									<span class="rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-wide {badgeClass(badge.tone)}" title={badge.title}>
										{badge.label}
									</span>
								{/each}
							</div>
						{:else}
							<span class="text-xs text-[var(--text-muted)]">—</span>
						{/if}
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
</div>
