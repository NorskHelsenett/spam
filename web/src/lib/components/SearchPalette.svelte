<script lang="ts">
	import { browser } from '$app/environment';
	import { goto } from '$app/navigation';
	import { Search, GitBranch, Loader } from 'lucide-svelte';

	type RepoResult = {
		id: string;
		provider: string;
		org: string;
		slug: string;
		score: number;
	};

	let open = $state(false);
	let query = $state('');
	let results = $state<RepoResult[]>([]);
	let loading = $state(false);
	let selectedIndex = $state(0);
	let inputEl: HTMLInputElement | undefined = $state();
	let debounceTimer: ReturnType<typeof setTimeout>;

	const close = () => {
		open = false;
		query = '';
		results = [];
		selectedIndex = 0;
	};

	const search = async (q: string) => {
		if (!q.trim()) {
			results = [];
			return;
		}
		loading = true;
		try {
			const res = await fetch(`/api/repos/search?q=${encodeURIComponent(q)}&limit=15`);
			if (res.ok) {
				const data = await res.json();
				results = data.results ?? [];
				selectedIndex = 0;
			}
		} finally {
			loading = false;
		}
	};

	const handleInput = () => {
		clearTimeout(debounceTimer);
		debounceTimer = setTimeout(() => search(query), 200);
	};

	const selectRepo = (result: RepoResult) => {
		goto(`/app/providers/repo?repo_id=${result.provider}:${result.org}:${result.slug}`);
		close();
	};

	const handleKeydown = (e: KeyboardEvent) => {
		if (!open) return;
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			selectedIndex = Math.min(selectedIndex + 1, results.length - 1);
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			selectedIndex = Math.max(selectedIndex - 1, 0);
		} else if (e.key === 'Enter' && results[selectedIndex]) {
			selectRepo(results[selectedIndex]);
		}
	};

	const handleGlobalKeydown = (e: KeyboardEvent) => {
		if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
			e.preventDefault();
			if (open) {
				close();
			} else {
				open = true;
			}
		} else if (e.key === 'Escape' && open) {
			close();
		}
	};

	const handleBackdrop = (e: MouseEvent) => {
		if (e.target === e.currentTarget) close();
	};

	$effect(() => {
		if (!browser) return;
		document.addEventListener('keydown', handleGlobalKeydown);
		return () => document.removeEventListener('keydown', handleGlobalKeydown);
	});

	$effect(() => {
		if (open) {
			setTimeout(() => inputEl?.focus(), 10);
		}
	});

	const providerLabel = (p: string) => {
		const map: Record<string, string> = {
			github: 'GitHub',
			gitlab: 'GitLab',
			gitea: 'Gitea',
			forgejo: 'Forgejo'
		};
		return map[p] ?? p;
	};
</script>

{#if open}
	<!-- Backdrop -->
	<div
		class="fixed inset-0 z-50 bg-black/40 backdrop-blur-[2px]"
		onclick={handleBackdrop}
		role="presentation"
	>
		<!-- Palette -->
		<div
			class="fixed left-1/2 top-[20%] z-50 w-[95vw] max-w-xl -translate-x-1/2 overflow-hidden rounded-2xl border border-[var(--border-color)] bg-[var(--main-content-bg)] shadow-2xl"
			role="dialog"
			aria-modal="true"
			aria-label="Search repositories"
		>
			<!-- Input row -->
			<div class="flex items-center gap-3 border-b border-[var(--border-color)] px-4 py-3">
				{#if loading}
					<Loader size={16} class="shrink-0 animate-spin text-[var(--accent)]" />
				{:else}
					<Search size={16} class="shrink-0 text-[var(--text-secondary)]" />
				{/if}
				<input
					bind:this={inputEl}
					bind:value={query}
					oninput={handleInput}
					onkeydown={handleKeydown}
					type="text"
					placeholder="Search repositories..."
					class="flex-1 bg-transparent text-sm text-[var(--text-primary)] placeholder-[var(--text-secondary)] outline-none"
				/>
				<kbd class="hidden rounded border border-[var(--border-color)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)] sm:block">
					Esc
				</kbd>
			</div>

			<!-- Results -->
			{#if results.length > 0}
				<ul class="max-h-72 overflow-y-auto py-1" role="listbox">
					{#each results as result, i}
						<li role="option" aria-selected={i === selectedIndex}>
							<button
								type="button"
								class="flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors
									{i === selectedIndex
										? 'bg-[var(--hover-bg)] text-[var(--text-bright)]'
										: 'text-[var(--text-primary)] hover:bg-[var(--hover-bg-subtle)]'}"
								onclick={() => selectRepo(result)}
								onmouseenter={() => (selectedIndex = i)}
							>
								<GitBranch size={14} class="shrink-0 text-[var(--accent)]" />
								<span class="min-w-0 flex-1">
									<span class="block truncate text-sm font-medium">{result.org}<span class="text-[var(--text-secondary)]">/</span>{result.slug}</span>
								</span>
								<span class="shrink-0 rounded border border-[var(--border-color)] px-1.5 py-0.5 text-[10px] text-[var(--text-secondary)]">
									{providerLabel(result.provider)}
								</span>
							</button>
						</li>
					{/each}
				</ul>
			{:else if query.trim() && !loading}
				<p class="px-4 py-6 text-center text-sm text-[var(--text-secondary)]">No repositories found</p>
			{:else if !query.trim()}
				<p class="px-4 py-6 text-center text-sm text-[var(--text-secondary)]">
					Type to search across all providers
				</p>
			{/if}

			<!-- Footer hint -->
			<div class="flex items-center gap-3 border-t border-[var(--border-color)] px-4 py-2 text-[10px] text-[var(--text-secondary)]">
				<span><kbd class="rounded border border-[var(--border-color)] px-1 py-0.5">↑↓</kbd> navigate</span>
				<span><kbd class="rounded border border-[var(--border-color)] px-1 py-0.5">↵</kbd> open</span>
				<span><kbd class="rounded border border-[var(--border-color)] px-1 py-0.5">Esc</kbd> close</span>
				<span class="ml-auto opacity-60">⌘K to toggle</span>
			</div>
		</div>
	</div>
{/if}
