<script lang="ts">
	import { FileWarning, X } from 'lucide-svelte';

	type Finding = {
		rule_id: string;
		description: string;
		file: string;
		start_line: number;
		match: string;
	};

	let {
		repoId,
		secretType,
		repoName,
		onClose = () => {}
	}: {
		repoId: string;
		secretType: string;
		repoName: string;
		onClose?: () => void;
	} = $props();

	let findings: Finding[] = $state([]);
	let loading = $state(false);

	$effect(() => {
		if (repoId && secretType) load();
	});

	const load = async () => {
		loading = true;
		findings = [];
		try {
			const params = new URLSearchParams({ repo_id: repoId, secret_type: secretType });
			const res = await fetch(`/api/secrets/findings?${params}`, { credentials: 'include' });
			if (res.ok) findings = await res.json();
		} catch {
			// ignore
		} finally {
			loading = false;
		}
	};
</script>

<div class="flex h-full flex-col overflow-hidden rounded-l-[10px] bg-[var(--bg-soft)]">
	<!-- Header -->
	<div class="shrink-0 border-b border-[var(--border-color)] p-5">
		<div class="flex items-start gap-3">
			<FileWarning class="mt-0.5 h-5 w-5 shrink-0 text-red-400" />
			<div class="min-w-0 flex-1">
				<h2 class="truncate text-base font-semibold text-[var(--text-bright)]">{repoName}</h2>
				<div class="mt-1.5 flex items-center gap-2">
					<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs">
						{secretType}
					</span>
					{#if !loading}
						<span class="text-[11px] text-[var(--text-muted)]">
							{findings.length} finding{findings.length !== 1 ? 's' : ''}
						</span>
					{/if}
				</div>
			</div>
			<button
				type="button"
				class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition hover:bg-[var(--hover-bg)]"
				onclick={onClose}
				aria-label="Close"
			>
				<X size={18} stroke-width={2} />
			</button>
		</div>
	</div>

	<!-- Body -->
	{#if loading}
		<div class="flex flex-1 items-center justify-center p-8">
			<div class="h-6 w-6 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
		</div>
	{:else if findings.length === 0}
		<div class="flex flex-1 items-center justify-center p-8 text-center">
			<p class="text-sm text-[var(--text-muted)]">No findings for this type.</p>
		</div>
	{:else}
		<div class="flex-1 overflow-y-auto">
			<div class="space-y-1 p-2">
				{#each findings as f}
					<article class="rounded-xl px-5 py-4 transition-colors hover:bg-[var(--hover-bg-subtle)]">
						<div class="flex items-start gap-4">
							<div class="w-40 shrink-0 pt-0.5">
								<span class="inline-flex items-center gap-1 rounded-full border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-xs font-semibold text-red-400">
									<FileWarning class="h-3 w-3 shrink-0" />
									<span class="truncate">{f.rule_id || 'unknown'}</span>
								</span>
							</div>
							<div class="min-w-0 flex-1 space-y-1.5">
								{#if f.description}
									<p class="text-sm text-[var(--text-secondary)]">{f.description}</p>
								{/if}
								{#if f.file}
									<p class="font-mono text-xs text-[var(--text-muted)]">{f.file}{f.start_line ? `:${f.start_line}` : ''}</p>
								{/if}
								{#if f.match}
									<div class="break-all rounded bg-[var(--card-bg)] px-2 py-1.5 font-mono text-xs text-[var(--text-muted)]">{f.match}</div>
								{/if}
							</div>
						</div>
					</article>
				{/each}
			</div>
		</div>
	{/if}
</div>
