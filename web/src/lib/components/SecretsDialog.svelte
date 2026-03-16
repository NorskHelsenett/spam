<script lang="ts">
	import { FileWarning, X, Shield } from 'lucide-svelte';

	type SecretFinding = {
		rule_id: string;
		description: string;
		file: string;
		start_line: number;
		match: string;
	};

	let {
		open = $bindable(false),
		loading = false,
		data = []
	}: {
		open: boolean;
		loading: boolean;
		data: SecretFinding[];
	} = $props();
</script>

{#if open}
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div
		class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 pt-16 backdrop-blur-sm"
		onkeydown={(e) => e.key === 'Escape' && (open = false)}
		onclick={(e) => e.target === e.currentTarget && (open = false)}
	>
		<div class="w-full max-w-4xl">
			<section class="overflow-hidden rounded-2xl border border-[var(--border-color)] bg-[var(--bg)] shadow-2xl">
				<div class="flex items-center justify-between px-6 py-4">
					<div class="flex items-center gap-3">
						<FileWarning class="h-5 w-5 text-red-400" />
						<h2 class="text-base font-semibold text-[var(--text-bright)]">Secrets & Issues</h2>
						{#if !loading && data.length > 0}
							<span class="rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs text-[var(--text-muted)]">
								{data.length}
							</span>
						{/if}
					</div>
					<button
						type="button"
						class="rounded-lg p-1.5 text-[var(--text-muted)] transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-secondary)]"
						onclick={() => (open = false)}
					>
						<X class="h-4 w-4" />
					</button>
				</div>

				<div class="max-h-[65vh] overflow-y-auto">
					{#if loading}
						<div class="flex items-center justify-center py-20">
							<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
						</div>
					{:else if data.length === 0}
						<div class="flex flex-col items-center justify-center py-16 text-center">
							<Shield class="mb-3 h-10 w-10 text-[var(--text-muted)]" />
							<p class="text-sm font-medium text-[var(--text-secondary)]">No secrets found</p>
							<p class="mt-1 text-xs text-[var(--text-muted)]">No BetterLeaks findings.</p>
						</div>
					{:else}
						<div class="space-y-1 p-2">
							{#each data as s}
								<article class="rounded-xl px-5 py-4 transition-colors hover:bg-[var(--hover-bg-subtle)]">
									<div class="flex items-start gap-4">
										<div class="w-40 shrink-0 pt-0.5">
											<span class="inline-flex items-center gap-1 rounded-full border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-xs font-semibold text-red-400">
												<FileWarning class="h-3 w-3" />
												<span class="truncate">{s.rule_id || 'unknown'}</span>
											</span>
										</div>
										<div class="min-w-0 flex-1 space-y-1.5">
											{#if s.description}
												<p class="text-sm text-[var(--text-secondary)]">{s.description}</p>
											{/if}
											{#if s.file}
												<p class="font-mono text-xs text-[var(--text-muted)]">{s.file}{s.start_line ? `:${s.start_line}` : ''}</p>
											{/if}
											{#if s.match}
												<div class="break-all rounded bg-[var(--card-bg)] px-2 py-1.5 font-mono text-xs text-[var(--text-muted)]">{s.match}</div>
											{/if}
										</div>
									</div>
								</article>
							{/each}
						</div>
					{/if}
				</div>
			</section>
		</div>
	</div>
{/if}
