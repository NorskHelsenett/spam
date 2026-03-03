<script lang="ts">
	import { browser } from '$app/environment';
	import { goto } from '$app/navigation';
	import { Search, GitBranch, Box, ShieldCheck, Play, ArrowRight, Package, Codesandbox } from 'lucide-svelte';

	type RepoResult = {
		id: string;
		provider: string;
		org: string;
		slug: string;
		score: number;
		provider_id?: string;
		base_url?: string;
	};

	type ComponentResult = {
		name: string;
		ecosystem: string;
		purl?: string;
		sources: string[];
		version_count: number;
		sbom_count: number;
		repo_count: number;
		has_direct: boolean;
	};

	type SearchItem =
		| { kind: 'repo'; data: RepoResult }
		| { kind: 'component'; data: ComponentResult };

	type Contributor = {
		login?: string;
		name?: string;
		email?: string;
		avatar_url?: string;
		profile_url?: string;
		contributions: number;
	};

	type RepoPreview = {
		repo: { provider: string; org: string; slug: string; updated_at?: string };
		latest_commit?: { sha: string; committed_at?: string };
		runs: { total: number; latest?: { status: string; finished_at?: string } };
		sbom: { latest?: { component_count: number; format: string } };
		dependencies: { total: number };
		secrets: { latest_count: number };
	};

	let open = $state(false);
	let query = $state('');
	let repoResults = $state<RepoResult[]>([]);
	let componentResults = $state<ComponentResult[]>([]);
	let loading = $state(false);
	let selectedIndex = $state(0);
	let repoPreview = $state<RepoPreview | null>(null);
	let contributors = $state<Contributor[]>([]);
	let previewLoading = $state(false);
	let inputEl: HTMLInputElement | undefined = $state();

	const previewCache = new Map<string, RepoPreview>();
	const contributorsCache = new Map<string, Contributor[]>();
	let searchTimer: ReturnType<typeof setTimeout>;
	let previewTimer: ReturnType<typeof setTimeout>;
	let contributorsTimer: ReturnType<typeof setTimeout>;

	const flatItems = $derived<SearchItem[]>([
		...repoResults.map((d) => ({ kind: 'repo' as const, data: d })),
		...componentResults.map((d) => ({ kind: 'component' as const, data: d }))
	]);

	const hasResults = $derived(flatItems.length > 0);

	const close = () => {
		open = false;
		query = '';
		repoResults = [];
		componentResults = [];
		repoPreview = null;
		contributors = [];
		selectedIndex = 0;
	};

	const search = async (q: string) => {
		if (!q.trim()) {
			repoResults = [];
			componentResults = [];
			repoPreview = null;
			return;
		}
		loading = true;
		try {
			const [repoRes, compRes] = await Promise.all([
				fetch(`/api/repos/search?q=${encodeURIComponent(q)}&limit=8`),
				fetch(`/api/dependencies?q=${encodeURIComponent(q)}&per_page=8`)
			]);
			if (repoRes.ok) {
				const data = await repoRes.json();
				repoResults = data.results ?? [];
			}
			if (compRes.ok) {
				const data = await compRes.json();
				componentResults = data.dependencies ?? [];
			}
			selectedIndex = 0;
		} finally {
			loading = false;
		}
	};

	const fetchRepoPreview = (result: RepoResult) => {
		const key = `${result.provider}:${result.org}:${result.slug}`;
		if (previewCache.has(key)) {
			repoPreview = previewCache.get(key)!;
		} else {
			clearTimeout(previewTimer);
			previewLoading = true;
			previewTimer = setTimeout(async () => {
				try {
					const res = await fetch(`/api/repos/metadata?repo_id=${encodeURIComponent(key)}`);
					if (res.ok) {
						const data = await res.json();
						previewCache.set(key, data);
						repoPreview = data;
					}
				} finally {
					previewLoading = false;
				}
			}, 120);
		}
		// Contributors fetched in parallel, slightly longer debounce
		if (contributorsCache.has(key)) {
			contributors = contributorsCache.get(key)!;
		} else {
			contributors = [];
			clearTimeout(contributorsTimer);
			contributorsTimer = setTimeout(async () => {
				const res = await fetch(`/api/repos/contributors?repo_id=${encodeURIComponent(key)}`);
				if (res.ok) {
					const data = await res.json();
					const list = data.contributors ?? [];
					contributorsCache.set(key, list);
					contributors = list;
				}
			}, 200);
		}
	};

	$effect(() => {
		const item = flatItems[selectedIndex];
		if (!item) { repoPreview = null; contributors = []; return; }
		if (item.kind === 'repo') fetchRepoPreview(item.data);
		else { repoPreview = null; contributors = []; clearTimeout(previewTimer); clearTimeout(contributorsTimer); previewLoading = false; }
	});

	const handleInput = () => {
		clearTimeout(searchTimer);
		searchTimer = setTimeout(() => search(query), 180);
	};

	const selectItem = (item: SearchItem) => {
		if (item.kind === 'repo') {
			const d = item.data;
			const params = new URLSearchParams({
				provider: d.provider,
				path: d.org + '/' + d.slug
			});
			if (d.provider_id) params.set('provider_id', d.provider_id);
			if (d.base_url) params.set('base_url', d.base_url);
			goto(`/app/providers/repo?${params}`);
		} else {
			goto(`/app/components?q=${encodeURIComponent(item.data.name)}&ecosystem=${encodeURIComponent(item.data.ecosystem)}`);
		}
		close();
	};

	const handleKeydown = (e: KeyboardEvent) => {
		if (!open) return;
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			selectedIndex = Math.min(selectedIndex + 1, flatItems.length - 1);
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			selectedIndex = Math.max(selectedIndex - 1, 0);
		} else if (e.key === 'Enter' && flatItems[selectedIndex]) {
			selectItem(flatItems[selectedIndex]);
		}
	};

	const handleGlobalKeydown = (e: KeyboardEvent) => {
		if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
			e.preventDefault();
			if (open) {
				inputEl?.focus();
			} else {
				open = true;
			}
		} else if (e.key === 'Escape' && open) {
			close();
		}
	};

	$effect(() => {
		if (!browser) return;
		document.addEventListener('keydown', handleGlobalKeydown);
		return () => document.removeEventListener('keydown', handleGlobalKeydown);
	});

	$effect(() => {
		if (open) setTimeout(() => inputEl?.focus(), 10);
	});

	const providerLabel = (p: string) =>
		({ github: 'GitHub', gitlab: 'GitLab', gitea: 'Gitea', forgejo: 'Forgejo' })[p] ?? p;

	const providerIcons: Record<string, string> = {
		github: `<svg width="11" height="11" viewBox="0 0 98 96" fill="currentColor" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0"><path fill-rule="evenodd" clip-rule="evenodd" d="M48.854 0C21.839 0 0 22 0 49.217c0 21.756 13.993 40.172 33.405 46.69 2.427.49 3.316-1.059 3.316-2.362 0-1.141-.08-5.052-.08-9.127-13.59 2.934-16.42-5.867-16.42-5.867-2.184-5.704-5.42-7.17-5.42-7.17-4.448-3.015.324-3.015.324-3.015 4.934.326 7.523 5.052 7.523 5.052 4.367 7.496 11.404 5.378 14.235 4.074.404-3.178 1.699-5.378 3.074-6.6-10.839-1.141-22.243-5.378-22.243-24.283 0-5.378 1.94-9.778 5.014-13.2-.485-1.222-2.184-6.275.486-13.038 0 0 4.125-1.304 13.426 5.052a46.97 46.97 0 0 1 12.214-1.63c4.125 0 8.33.571 12.213 1.63 9.302-6.356 13.427-5.052 13.427-5.052 2.67 6.763.97 11.816.485 13.038 3.155 3.422 5.015 7.822 5.015 13.2 0 18.905-11.404 23.06-22.324 24.283 1.78 1.548 3.316 4.481 3.316 9.126 0 6.6-.08 11.897-.08 13.526 0 1.304.89 2.853 3.316 2.364 19.412-6.52 33.405-24.935 33.405-46.691C97.707 22 75.788 0 48.854 0z"/></svg>`,
		gitlab: `<svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0"><path d="M22.65 14.39L12 22.13 1.35 14.39a.84.84 0 0 1-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 0 1 4.82 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0 1 18.6 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.51L22.95 13.45a.84.84 0 0 1-.3.94z"/></svg>`,
		gitea: `<svg width="11" height="11" viewBox="0 0 32 32" fill="currentColor" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0"><path d="M5.583 7.229c-2.464-0.005-5.755 1.557-5.573 5.479 0.281 6.125 6.557 6.693 9.068 6.745 0.271 1.146 3.224 5.109 5.411 5.318h9.573c5.74-0.38 10.036-17.365 6.854-17.427-5.271 0.25-8.396 0.375-11.073 0.396v5.297l-0.839-0.365-0.005-4.932c-3.073 0-5.781-0.141-10.917-0.396-0.646-0.005-1.542-0.115-2.5-0.115zM5.927 9.396h0.297c0.349 3.141 0.917 4.974 2.068 7.781-2.938-0.349-5.432-1.198-5.891-4.38-0.24-1.646 0.563-3.365 3.526-3.401zM17.339 12.479c0.198 0.005 0.406 0.042 0.594 0.13l1 0.432-0.714 1.302c-0.109 0-0.219 0.016-0.323 0.052-0.464 0.151-0.708 0.604-0.542 1.021 0.036 0.083 0.089 0.161 0.151 0.229l-1.234 2.25c-0.099 0-0.203 0.016-0.297 0.052-0.464 0.146-0.708 0.604-0.542 1.016 0.172 0.417 0.682 0.63 1.151 0.479 0.464-0.146 0.703-0.604 0.536-1.021-0.047-0.109-0.115-0.208-0.208-0.292l1.203-2.188c0.13 0.010 0.26 0 0.391-0.042 0.104-0.031 0.198-0.083 0.281-0.151 0.464 0.198 0.844 0.354 1.12 0.49 0.406 0.203 0.552 0.339 0.599 0.49 0.042 0.146-0.005 0.427-0.24 0.922-0.172 0.37-0.458 0.896-0.797 1.51-0.115 0-0.229 0.016-0.333 0.052-0.469 0.151-0.708 0.604-0.542 1.021 0.167 0.411 0.682 0.625 1.146 0.479 0.469-0.151 0.708-0.604 0.542-1.021-0.042-0.099-0.104-0.193-0.182-0.271 0.333-0.609 0.62-1.135 0.807-1.526 0.25-0.536 0.38-0.938 0.266-1.323s-0.469-0.635-0.932-0.865c-0.307-0.151-0.693-0.313-1.146-0.505 0.005-0.109-0.010-0.214-0.052-0.318s-0.109-0.198-0.193-0.281l0.703-1.281 3.901 1.682c0.703 0.307 0.995 1.057 0.651 1.682l-2.682 4.906c-0.339 0.625-1.182 0.885-1.885 0.578l-5.516-2.38c-0.703-0.307-0.995-1.057-0.656-1.682l2.682-4.906c0.234-0.432 0.708-0.688 1.208-0.708h0.083z"/></svg>`,
		forgejo: `<svg width="11" height="11" viewBox="0 0 32 32" fill="currentColor" xmlns="http://www.w3.org/2000/svg" style="flex-shrink:0"><path d="M5.583 7.229c-2.464-0.005-5.755 1.557-5.573 5.479 0.281 6.125 6.557 6.693 9.068 6.745 0.271 1.146 3.224 5.109 5.411 5.318h9.573c5.74-0.38 10.036-17.365 6.854-17.427-5.271 0.25-8.396 0.375-11.073 0.396v5.297l-0.839-0.365-0.005-4.932c-3.073 0-5.781-0.141-10.917-0.396-0.646-0.005-1.542-0.115-2.5-0.115zM5.927 9.396h0.297c0.349 3.141 0.917 4.974 2.068 7.781-2.938-0.349-5.432-1.198-5.891-4.38-0.24-1.646 0.563-3.365 3.526-3.401zM17.339 12.479c0.198 0.005 0.406 0.042 0.594 0.13l1 0.432-0.714 1.302c-0.109 0-0.219 0.016-0.323 0.052-0.464 0.151-0.708 0.604-0.542 1.021 0.036 0.083 0.089 0.161 0.151 0.229l-1.234 2.25c-0.099 0-0.203 0.016-0.297 0.052-0.464 0.146-0.708 0.604-0.542 1.016 0.172 0.417 0.682 0.63 1.151 0.479 0.464-0.146 0.703-0.604 0.536-1.021-0.047-0.109-0.115-0.208-0.208-0.292l1.203-2.188c0.13 0.010 0.26 0 0.391-0.042 0.104-0.031 0.198-0.083 0.281-0.151 0.464 0.198 0.844 0.354 1.12 0.49 0.406 0.203 0.552 0.339 0.599 0.49 0.042 0.146-0.005 0.427-0.24 0.922-0.172 0.37-0.458 0.896-0.797 1.51-0.115 0-0.229 0.016-0.333 0.052-0.469 0.151-0.708 0.604-0.542 1.021 0.167 0.411 0.682 0.625 1.146 0.479 0.469-0.151 0.708-0.604 0.542-1.021-0.042-0.099-0.104-0.193-0.182-0.271 0.333-0.609 0.62-1.135 0.807-1.526 0.25-0.536 0.38-0.938 0.266-1.323s-0.469-0.635-0.932-0.865c-0.307-0.151-0.693-0.313-1.146-0.505 0.005-0.109-0.010-0.214-0.052-0.318s-0.109-0.198-0.193-0.281l0.703-1.281 3.901 1.682c0.703 0.307 0.995 1.057 0.651 1.682l-2.682 4.906c-0.339 0.625-1.182 0.885-1.885 0.578l-5.516-2.38c-0.703-0.307-0.995-1.057-0.656-1.682l2.682-4.906c0.234-0.432 0.708-0.688 1.208-0.708h0.083z"/></svg>`,
	};

	const repoGrouped = $derived(() => {
		const map = new Map<string, RepoResult[]>();
		for (const r of repoResults) {
			const list = map.get(r.provider) ?? [];
			list.push(r);
			map.set(r.provider, list);
		}
		return map;
	});

	const statusColor = (status: string) => {
		if (status === 'SUCCEEDED') return 'var(--success)';
		if (status === 'FAILED') return 'var(--error)';
		if (status === 'RUNNING') return 'var(--info)';
		if (status === 'CANCELLED') return 'var(--text-muted)';
		return 'var(--warning)';
	};

	const relativeTime = (iso: string | undefined) => {
		if (!iso) return '—';
		const diff = Date.now() - new Date(iso).getTime();
		const mins = Math.floor(diff / 60000);
		if (mins < 1) return 'just now';
		if (mins < 60) return `${mins}m ago`;
		const hrs = Math.floor(mins / 60);
		if (hrs < 24) return `${hrs}h ago`;
		return `${Math.floor(hrs / 24)}d ago`;
	};

	const shortDate = (iso: string | undefined) => {
		if (!iso) return '';
		return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
	};

	const selectedItem = $derived(flatItems[selectedIndex] ?? null);
</script>

{#if open}
	<div
		class="fixed inset-0 z-50 bg-black/55"
		onclick={(e) => { if (e.target === e.currentTarget) close(); }}
		role="presentation"
	>
		<div
			class="fixed left-1/2 top-[16%] z-50 w-[95vw] max-w-2xl -translate-x-1/2 overflow-hidden rounded-2xl shadow-2xl"
			style="background: var(--bg-soft); border: 1px solid var(--bg2);"
			role="dialog"
			aria-modal="true"
			aria-label="Search"
		>
			<!-- Search bar -->
			<div class="flex items-center gap-3 px-5 py-4">
				<Search
					size={17}
					style="color: var(--text-muted); flex-shrink: 0; opacity: {loading ? 0.35 : 1}; transition: opacity 200ms;"
				/>
				<input
					bind:this={inputEl}
					bind:value={query}
					oninput={handleInput}
					onkeydown={handleKeydown}
					type="text"
					placeholder="Search…"
					style="flex: 1; background: transparent; color: var(--text-bright); caret-color: var(--accent); font-size: 1rem; font-weight: 500; outline: none;"
					class="placeholder:font-normal placeholder:text-[var(--text-muted)]"
				/>
				{#if query}
					<button
						type="button"
						onclick={() => { query = ''; repoResults = []; componentResults = []; repoPreview = null; inputEl?.focus(); }}
						style="color: var(--text-muted); background: var(--bg1); border-radius: 999px; width: 18px; height: 18px; font-size: 9px; display: flex; align-items: center; justify-content: center; flex-shrink: 0;"
						aria-label="Clear"
					>✕</button>
				{/if}
			</div>

			<!-- Two-panel body -->
			{#if hasResults}
				<div class="flex">

					<!-- Left: results list -->
					<div class="w-52 shrink-0 overflow-y-auto" style="background: var(--bg-soft);">

						{#if repoResults.length > 0}
							{#each [...repoGrouped()] as [provider, repos]}
								<div class="flex items-center gap-1.5 px-4 pb-1 pt-3" style="color: var(--text-muted);">
									{@html providerIcons[provider] ?? ''}
									<span class="text-[9px] font-semibold uppercase tracking-[0.18em]">{providerLabel(provider)}</span>
								</div>
								{#each repos as result}
									{@const flatIdx = flatItems.findIndex(i => i.kind === 'repo' && i.data === result)}
									<button
										type="button"
										onclick={() => selectItem({ kind: 'repo', data: result })}
										onmouseenter={() => (selectedIndex = flatIdx)}
										class="flex w-full items-center gap-2.5 px-4 py-2 text-left transition-colors"
										style="background: {flatIdx === selectedIndex ? 'var(--bg1)' : 'transparent'};"
									>
										<GitBranch size={12} style="flex-shrink:0; color: {flatIdx === selectedIndex ? 'var(--accent)' : 'var(--bg4)'};" />
										<span class="min-w-0 flex-1 truncate text-[13px]" style="color: {flatIdx === selectedIndex ? 'var(--text-bright)' : 'var(--text-secondary)'}; font-weight: {flatIdx === selectedIndex ? '500' : '400'};">
											{result.slug}
										</span>
									</button>
								{/each}
							{/each}
						{/if}

						{#if componentResults.length > 0}
							<p class="px-4 pb-1 pt-3 text-[9px] font-semibold uppercase tracking-[0.18em]" style="color: var(--text-muted);">
								Components
							</p>
							{#each componentResults as result}
								{@const flatIdx = flatItems.findIndex(i => i.kind === 'component' && i.data === result)}
								<button
									type="button"
									onclick={() => selectItem({ kind: 'component', data: result })}
									onmouseenter={() => (selectedIndex = flatIdx)}
									class="flex w-full items-center gap-2.5 px-4 py-2 text-left transition-colors"
									style="background: {flatIdx === selectedIndex ? 'var(--bg1)' : 'transparent'};"
								>
									<Package size={12} style="flex-shrink:0; color: {flatIdx === selectedIndex ? 'var(--accent)' : 'var(--bg4)'};" />
									<span class="min-w-0 flex-1 truncate text-[13px]" style="color: {flatIdx === selectedIndex ? 'var(--text-bright)' : 'var(--text-secondary)'}; font-weight: {flatIdx === selectedIndex ? '500' : '400'};">
										{result.name}
									</span>
								</button>
							{/each}
						{/if}
					</div>

					<!-- Right: preview panel -->
					<div class="flex min-w-0 flex-1 flex-col overflow-y-auto" style="background: var(--bg-soft); min-height: 25em; padding: 4em;">

						{#if selectedItem?.kind === 'repo'}
							{#if previewLoading}
								<div class="space-y-3 pt-1">
									<div class="h-4 w-3/4 rounded-lg" style="background: var(--bg1);"></div>
									<div class="h-3 w-1/2 rounded-lg" style="background: var(--bg1);"></div>
									<div class="mt-4 space-y-2">
										{#each [1,2,3,4] as _}
											<div class="h-3 w-full rounded" style="background: var(--bg1);"></div>
										{/each}
									</div>
								</div>
							{:else if repoPreview}
								<div class="mb-4">
									<div class="flex items-center gap-1.5" style="color: var(--text-muted);">
										{@html providerIcons[repoPreview.repo.provider] ?? ''}
										<span class="text-[10px] uppercase tracking-widest">{providerLabel(repoPreview.repo.provider)}</span>
									</div>
									<p class="mt-0.5 truncate text-sm font-semibold" style="color: var(--text-bright);">
										{repoPreview.repo.org}<span style="color: var(--text-muted);">/</span>{repoPreview.repo.slug}
									</p>
									{#if repoPreview.latest_commit}
										<p class="mt-1 text-[10px]" style="color: var(--text-muted);">
											Last commit
											<span title={repoPreview.latest_commit.sha} style="cursor: default;">
												{relativeTime(repoPreview.latest_commit.committed_at)}
											</span>
											<span style="opacity: 0.6;">· {shortDate(repoPreview.latest_commit.committed_at)}</span>
											<span style="font-family: monospace; opacity: 0.5;">{repoPreview.latest_commit.sha.slice(0, 7)}</span>
										</p>
									{:else if repoPreview.repo.updated_at}
										<p class="mt-1 text-[10px]" style="color: var(--text-muted);">
											Last activity
											<span>{relativeTime(repoPreview.repo.updated_at)}</span>
											<span style="opacity: 0.6;">· {shortDate(repoPreview.repo.updated_at)}</span>
										</p>
									{/if}
								</div>
								<div class="space-y-2.5">
									<div class="flex items-center gap-2.5">
										<Box size={13} style="color: var(--text-muted); flex-shrink:0;" />
										<span class="text-[11px]" style="color: var(--text-muted);">Dependencies</span>
										<span class="ml-auto text-[11px] font-medium" style="color: var(--text-primary);">
											{repoPreview.dependencies.total > 0 ? repoPreview.dependencies.total : '—'}
										</span>
									</div>
									{#if repoPreview.sbom.latest}
										<div class="flex items-center gap-2.5">
											<ShieldCheck size={13} style="color: var(--text-muted); flex-shrink:0;" />
											<span class="text-[11px]" style="color: var(--text-muted);">SBOM</span>
											<span class="ml-auto text-[11px] font-medium" style="color: var(--text-primary);">
												{repoPreview.sbom.latest.format} · {repoPreview.sbom.latest.component_count} components
											</span>
										</div>
									{/if}
									<div class="flex items-center gap-2.5">
										<ShieldCheck size={13} style="color: {repoPreview.secrets.latest_count > 0 ? 'var(--error)' : 'var(--text-muted)'}; flex-shrink:0;" />
										<span class="text-[11px]" style="color: var(--text-muted);">Secrets</span>
										<span class="ml-auto text-[11px] font-medium" style="color: {repoPreview.secrets.latest_count > 0 ? 'var(--error)' : 'var(--text-primary)'};">
											{repoPreview.secrets.latest_count > 0 ? `${repoPreview.secrets.latest_count} found` : 'None found'}
										</span>
									</div>
									{#if repoPreview.runs.latest}
										<div class="flex items-center gap-2.5">
											<Play size={12} style="color: var(--text-muted); flex-shrink:0;" />
											<span class="text-[11px]" style="color: var(--text-muted);">Last run</span>
											<span class="ml-auto flex items-center gap-1.5 text-[11px] font-medium">
												<span style="color: {statusColor(repoPreview.runs.latest.status)};">●</span>
												<span style="color: var(--text-primary);">{repoPreview.runs.latest.status}</span>
												<span style="color: var(--text-muted);">{relativeTime(repoPreview.runs.latest.finished_at)}</span>
											</span>
										</div>
									{:else}
										<div class="flex items-center gap-2.5">
											<Play size={12} style="color: var(--text-muted); flex-shrink:0;" />
											<span class="text-[11px]" style="color: var(--text-muted);">Last run</span>
											<span class="ml-auto text-[11px]" style="color: var(--text-muted);">Never scanned</span>
										</div>
									{/if}
									<div class="flex items-center gap-2.5">
										<Play size={12} style="color: var(--text-muted); flex-shrink:0;" />
										<span class="text-[11px]" style="color: var(--text-muted);">Total scans</span>
										<span class="ml-auto text-[11px] font-medium" style="color: var(--text-primary);">{repoPreview.runs.total}</span>
									</div>
								</div>

								{#if contributors.length > 0}
									<div class="mt-4">
										<p class="mb-2 text-[9px] font-semibold uppercase tracking-[0.18em]" style="color: var(--text-muted);">Contributors</p>
										<div class="grid grid-cols-2 gap-x-3 gap-y-2.5">
											{#each contributors.slice(0, 5) as c}
												<div class="flex min-w-0 items-center gap-2">
													{#if c.avatar_url}
														<img
															src={c.avatar_url}
															alt={c.login ?? c.name ?? ''}
															class="h-6 w-6 flex-shrink-0 rounded-full"
															style="background: var(--bg2);"
														/>
													{:else}
														<div class="flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-full text-[9px] font-semibold" style="background: var(--bg2); color: var(--text-muted);">
															{(c.login ?? c.name ?? '?')[0].toUpperCase()}
														</div>
													{/if}
													<div class="min-w-0 flex-1">
														<p class="truncate text-[11px] font-medium leading-tight" style="color: var(--text-primary);">{c.login ?? c.name ?? '—'}</p>
														{#if c.email}
															<p class="truncate text-[9px] leading-tight" style="color: var(--text-muted);">{c.email}</p>
														{/if}
													</div>
												</div>
											{/each}
										</div>
									</div>
								{/if}

								<button
									type="button"
									onclick={() => selectItem(selectedItem)}
									class="mt-auto flex items-center gap-1.5 pt-5 text-[11px] font-medium transition-opacity hover:opacity-70"
									style="color: var(--accent);"
								>
									Open repository <ArrowRight size={11} />
								</button>
							{/if}

						{:else if selectedItem?.kind === 'component'}
							{@const c = selectedItem.data}
							<div class="mb-4">
								<p class="text-[10px] uppercase tracking-widest" style="color: var(--text-muted);">{c.ecosystem}</p>
								<p class="mt-0.5 truncate text-sm font-semibold" style="color: var(--text-bright);">{c.name}</p>
							</div>
							<div class="space-y-2.5">
								<div class="flex items-center gap-2.5">
									<Package size={13} style="color: var(--text-muted); flex-shrink:0;" />
									<span class="text-[11px]" style="color: var(--text-muted);">Versions</span>
									<span class="ml-auto text-[11px] font-medium" style="color: var(--text-primary);">{c.version_count}</span>
								</div>
								<div class="flex items-center gap-2.5">
									<GitBranch size={13} style="color: var(--text-muted); flex-shrink:0;" />
									<span class="text-[11px]" style="color: var(--text-muted);">Repositories</span>
									<span class="ml-auto text-[11px] font-medium" style="color: var(--text-primary);">{c.repo_count}</span>
								</div>
								<div class="flex items-center gap-2.5">
									<ShieldCheck size={13} style="color: var(--text-muted); flex-shrink:0;" />
									<span class="text-[11px]" style="color: var(--text-muted);">SBOMs</span>
									<span class="ml-auto text-[11px] font-medium" style="color: var(--text-primary);">{c.sbom_count}</span>
								</div>
								<div class="flex items-center gap-2.5">
									<Box size={13} style="color: var(--text-muted); flex-shrink:0;" />
									<span class="text-[11px]" style="color: var(--text-muted);">Sources</span>
									<span class="ml-auto text-[11px] font-medium" style="color: var(--text-primary);">{c.sources.join(', ')}</span>
								</div>
							</div>
							<button
								type="button"
								onclick={() => selectItem(selectedItem)}
								class="mt-auto flex items-center gap-1.5 pt-5 text-[11px] font-medium transition-opacity hover:opacity-70"
								style="color: var(--accent);"
							>
								View component <ArrowRight size={11} />
							</button>

						{:else}
							<div class="flex flex-col items-center justify-center gap-2 py-10 text-center">
								<Search size={28} style="color: var(--bg3);" />
								<p class="text-[11px]" style="color: var(--text-muted);">Select a result to preview</p>
							</div>
						{/if}
					</div>
				</div>

			{:else if query.trim() && !loading}
				<div style="border-top: 1px solid rgba(80, 73, 69, 0); background: var(--bg-soft); min-height: 25em; padding: 4em; display: flex; align-items: center; justify-content: center;">
					<p class="text-sm" style="color: var(--text-muted);">No results for <span style="color: var(--text-primary);">"{query}"</span></p>
				</div>

			{:else if !query.trim()}
				<div style="border-top: 1px solid rgba(80, 73, 69, 0); background: var(--bg-soft); min-height: 25em; padding: 4em; display: flex; align-items: center; justify-content: center;">
					<div style="display: flex; flex-direction: column; gap: 2em; width: 100%;">
						<div style="display: flex; align-items: center; gap: 1.5em;">
							<Codesandbox size={28} style="color: var(--text-muted); flex-shrink: 0;" />
							<div>
								<p style="color: var(--text-primary); font-size: 1em; font-weight: 500;">Repositories</p>
								<p style="color: var(--text-muted); font-size: 0.85em; margin-top: 0.3em;">GitHub · GitLab · Gitea · Forgejo</p>
							</div>
						</div>
						<div style="display: flex; align-items: center; gap: 1.5em;">
							<Package size={28} style="color: var(--text-muted); flex-shrink: 0;" />
							<div>
								<p style="color: var(--text-primary); font-size: 1em; font-weight: 500;">Components</p>
								<p style="color: var(--text-muted); font-size: 0.85em; margin-top: 0.3em;">npm · Maven · PyPI · NuGet · Go</p>
							</div>
						</div>
					</div>
				</div>
			{/if}
		</div>
	</div>
{/if}
