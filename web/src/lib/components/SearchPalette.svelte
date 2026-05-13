<script lang="ts">
	import { browser } from '$app/environment';
	import { goto } from '$app/navigation';
	import { Search, SearchX, GitBranch, Box, ShieldCheck, Play, ArrowRight, Package, Codesandbox, Github, Gitlab, Microscope, Container } from 'lucide-svelte';
	import Gitea from '$lib/components/icons/Gitea.svelte';
	import VulnBadges from '$lib/components/VulnBadges.svelte';

	type RepoResult = {
		id: string;
		provider: string;
		org: string;
		slug: string;
		score: number;
		provider_id?: string;
		base_url?: string;
		owner_path?: string;
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

	type ImageResult = {
		image_id: string;
		title: string;   // "registry/repository"
		value?: string;  // digest (sha256:…)
		org?: string;    // registry (or linked repo org)
		slug?: string;   // repository (or linked repo slug)
	};

	type SearchItem =
		| { kind: 'repo'; data: RepoResult }
		| { kind: 'component'; data: ComponentResult }
		| { kind: 'image'; data: ImageResult };

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
		vulnerabilities?: { summary?: { critical: number; high: number; medium: number; low: number } };
	};

	type ImagePreview = {
		id: string;
		registry: string;
		repository: string;
		digest: string;
		linked_repo?: { provider?: string; org?: string; slug?: string };
		vuln_severity?: { critical: number; high: number; medium: number; low: number; unknown: number; total: number };
		secret_count: number;
		cluster_usage?: { cluster: string }[];
	};

	let open = $state(false);
	let query = $state('');
	let repoResults = $state<RepoResult[]>([]);
	let componentResults = $state<ComponentResult[]>([]);
	let imageResults = $state<ImageResult[]>([]);
	let loading = $state(false);
	let loadingMore = $state(false);
	let hasMore = $state(false);
	let repoOffset = $state(0);
	let selectedIndex = $state(0);
	let repoPreview = $state<RepoPreview | null>(null);
	let contributors = $state<Contributor[]>([]);
	let imagePreview = $state<ImagePreview | null>(null);
	let previewLoading = $state(false);
	let inputEl: HTMLInputElement | undefined = $state();
	let resultsListEl: HTMLDivElement | undefined = $state();

	const previewCache = new Map<string, RepoPreview>();
	const contributorsCache = new Map<string, Contributor[]>();
	const imagePreviewCache = new Map<string, ImagePreview>();
	let searchTimer: ReturnType<typeof setTimeout>;
	let previewTimer: ReturnType<typeof setTimeout>;
	let contributorsTimer: ReturnType<typeof setTimeout>;
	let imagePreviewTimer: ReturnType<typeof setTimeout>;

	const flatItems = $derived.by<SearchItem[]>(() => {
		const items: SearchItem[] = [];
		for (const [, group] of repoGrouped) {
			for (const r of group.repos) {
				items.push({ kind: 'repo', data: r });
			}
		}
		for (const img of imageResults) {
			items.push({ kind: 'image', data: img });
		}
		for (const d of componentResults) {
			items.push({ kind: 'component', data: d });
		}
		return items;
	});

	const hasResults = $derived(flatItems.length > 0);

	const LIMIT = 30;

	const close = () => {
		open = false;
		query = '';
		repoResults = [];
		componentResults = [];
		imageResults = [];
		repoPreview = null;
		contributors = [];
		imagePreview = null;
		selectedIndex = 0;
		hasMore = false;
		repoOffset = 0;
	};

	const search = async (q: string) => {
		if (!q.trim()) {
			repoResults = [];
			componentResults = [];
			imageResults = [];
			repoPreview = null;
			hasMore = false;
			repoOffset = 0;
			return;
		}
		loading = true;
		repoOffset = 0;
		try {
			const [repoRes, compRes, imgRes] = await Promise.all([
				fetch(`/api/repos/search?q=${encodeURIComponent(q)}&limit=${LIMIT}&offset=0`),
				fetch(`/api/dependencies?q=${encodeURIComponent(q)}&per_page=20`),
				// Reuse the advanced-search endpoint for images so the palette
				// matches on registry, repository, or sha256 digest without
				// a new backend route.
				fetch(`/api/search/advanced?q=${encodeURIComponent(q)}&target=image&per_page=15`)
			]);
			if (repoRes.ok) {
				const data = await repoRes.json();
				repoResults = data.results ?? [];
				hasMore = data.has_more ?? false;
				repoOffset = repoResults.length;
			}
			if (compRes.ok) {
				const data = await compRes.json();
				componentResults = data.dependencies ?? [];
			}
			if (imgRes.ok) {
				const data = await imgRes.json();
				imageResults = (data.results ?? [])
					.filter((r: { image_id?: string }) => !!r.image_id)
					.map((r: { image_id: string; title: string; value?: string; org?: string; slug?: string }) => ({
						image_id: r.image_id,
						title: r.title,
						value: r.value,
						org: r.org,
						slug: r.slug,
					}));
			}
			selectedIndex = 0;
		} finally {
			loading = false;
		}
	};

	const loadMore = async () => {
		if (loadingMore || !hasMore || !query.trim()) return;
		loadingMore = true;
		try {
			const res = await fetch(`/api/repos/search?q=${encodeURIComponent(query)}&limit=${LIMIT}&offset=${repoOffset}`);
			if (res.ok) {
				const data = await res.json();
				repoResults = [...repoResults, ...(data.results ?? [])];
				hasMore = data.has_more ?? false;
				repoOffset += data.results?.length ?? 0;
			}
		} finally {
			loadingMore = false;
		}
	};

	const handleResultsScroll = () => {
		if (!resultsListEl || loadingMore || !hasMore) return;
		const { scrollTop, scrollHeight, clientHeight } = resultsListEl;
		if (scrollHeight - scrollTop - clientHeight < 80) {
			loadMore();
		}
	};

	// Trigger load more when keyboard navigation reaches near the end of results
	$effect(() => {
		if (hasMore && !loadingMore && selectedIndex >= flatItems.length - 5) {
			loadMore();
		}
	});

	const fetchRepoPreview = (result: RepoResult) => {
		const key = result.id;
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

	const fetchImagePreview = (result: ImageResult) => {
		const key = result.value;
		if (!key) return;
		if (imagePreviewCache.has(key)) {
			imagePreview = imagePreviewCache.get(key)!;
			return;
		}
		imagePreview = null;
		clearTimeout(imagePreviewTimer);
		previewLoading = true;
		imagePreviewTimer = setTimeout(async () => {
			try {
				const res = await fetch(`/api/images/${encodeURIComponent(key)}`);
				if (res.ok) {
					const data = (await res.json()) as ImagePreview;
					imagePreviewCache.set(key, data);
					imagePreview = data;
				}
			} finally {
				previewLoading = false;
			}
		}, 120);
	};

	$effect(() => {
		const item = flatItems[selectedIndex];
		if (!item) {
			repoPreview = null; contributors = []; imagePreview = null;
			return;
		}
		if (item.kind === 'repo') {
			imagePreview = null;
			fetchRepoPreview(item.data);
		} else if (item.kind === 'image') {
			repoPreview = null; contributors = [];
			clearTimeout(previewTimer); clearTimeout(contributorsTimer);
			fetchImagePreview(item.data);
		} else {
			repoPreview = null; contributors = []; imagePreview = null;
			clearTimeout(previewTimer); clearTimeout(contributorsTimer); clearTimeout(imagePreviewTimer);
			previewLoading = false;
		}
	});

	$effect(() => {
		if (!browser) return;
		document.querySelector(`[data-search-idx="${selectedIndex}"]`)?.scrollIntoView({ block: 'nearest' });
	});

	const handleInput = () => {
		clearTimeout(searchTimer);
		searchTimer = setTimeout(() => search(query), 180);
	};

	const selectItem = (item: SearchItem, opts?: { remote?: boolean }) => {
		if (item.kind === 'repo') {
			const d = item.data;
			if (opts?.remote) {
				openRemoteRepo(d);
				return;
			}
			const params = new URLSearchParams({ provider: d.provider, path: d.org + '/' + d.slug });
			if (d.id) params.set('repo_id', d.id);
			if (d.provider_id) params.set('provider_id', d.provider_id);
			else if (d.base_url) params.set('base_url', d.base_url);
			goto(`/providers/repo?${params}`);
		} else if (item.kind === 'image') {
			goto(`/images/${encodeURIComponent(item.data.value ?? '')}`);
		} else {
			goto(`/components?q=${encodeURIComponent(item.data.name)}&ecosystem=${encodeURIComponent(item.data.ecosystem)}`);
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
			selectItem(flatItems[selectedIndex], { remote: e.shiftKey });
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

	const providerDisplay = (base_url: string, owner_path?: string) =>
		base_url.replace(/^https?:\/\//, '') + (owner_path ? '/' + owner_path : '');

	const providerUrl = (r: RepoResult) => {
		if (r.base_url && r.owner_path) {
			return `${r.base_url}/${r.owner_path}/${r.slug}`;
		}
		if (r.base_url) {
			return `${r.base_url}/${r.org}/${r.slug}`;
		}
		const domain = { github: 'github.com', gitlab: 'gitlab.com' }[r.provider];
		if (domain) return `https://${domain}/${r.org}/${r.slug}`;
		return `https://${r.org}/${r.slug}`;
	};

	const advancedSearchUrl = () => {
		const q = query.trim();
		return q ? `/search?q=${encodeURIComponent(q)}` : '/search';
	};

	const openRemoteRepo = (repo: RepoResult) => {
		if (!browser) return;
		window.open(providerUrl(repo), '_blank', 'noopener,noreferrer');
		close();
	};


	const repoGrouped = $derived.by(() => {
		const map = new Map<string, { provider: string; base_url: string; label: string; repos: RepoResult[] }>();
		for (const r of repoResults) {
			const key = r.provider_id || r.provider;
			const existing = map.get(key);
			if (existing) {
				existing.repos.push(r);
			} else {
				map.set(key, { provider: r.provider, base_url: r.base_url || '', label: providerDisplay(r.base_url || '', r.owner_path), repos: [r] });
			}
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

	const fmt = (n: number | null | undefined) => (n ?? 0).toLocaleString('en-US').replace(/,/g, '\u202f');

	const selectedItem = $derived(flatItems[selectedIndex] ?? null);
</script>

{#if open}
	<div
		class="fixed inset-0 z-50 bg-black/55"
		onclick={(e) => { if (e.target === e.currentTarget) close(); }}
		role="presentation"
	>
		<div
			class="fixed left-1/2 top-[16%] z-50 w-[95vw] max-w-4xl -translate-x-1/2 overflow-hidden rounded-2xl shadow-2xl"
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
					<div bind:this={resultsListEl} onscroll={handleResultsScroll} class="w-72 shrink-0 overflow-y-auto" style="background: var(--bg-soft); max-height: 25em;">

						{#if repoResults.length > 0}
							{#each [...repoGrouped] as [, group]}
								<div class="flex flex-col gap-0.5 px-4 pb-1 pt-3">
									<span class="text-[9px] font-semibold uppercase tracking-[0.18em]" style="color: var(--text-secondary);">{providerLabel(group.provider)}</span>
									{#if group.label}
										<span class="truncate text-[8px]" style="color: var(--text-muted); opacity: 0.7;">{group.label}</span>
									{/if}
								</div>
								{#each group.repos as result}
									{@const flatIdx = flatItems.findIndex(i => i.kind === 'repo' && i.data === result)}
									<button
										type="button"
										data-search-idx={flatIdx}
										onclick={() => selectItem({ kind: 'repo', data: result })}
										onmouseenter={() => (selectedIndex = flatIdx)}
										class="flex w-full items-center gap-2.5 px-4 py-2 text-left transition-colors"
									>
										{#if result.provider === 'github'}
											<Github size={12} style="flex-shrink:0; color: {flatIdx === selectedIndex ? 'var(--accent)' : 'var(--text-muted)'};" />
										{:else if result.provider === 'gitlab'}
											<Gitlab size={12} style="flex-shrink:0; color: {flatIdx === selectedIndex ? 'var(--accent)' : 'var(--text-muted)'};" />
										{:else}
											<Gitea size={12} />
										{/if}
										<span class="min-w-0 flex-1 truncate text-[13px]" style="color: {flatIdx === selectedIndex ? 'var(--accent)' : 'var(--text-muted)'}; font-weight: {flatIdx === selectedIndex ? '500' : '400'};">
											{result.slug}
										</span>
									</button>
								{/each}
							{/each}
						{/if}

						{#if imageResults.length > 0}
							<p class="px-4 pb-1 pt-3 text-[9px] font-semibold uppercase tracking-[0.18em]" style="color: var(--text-muted);">
								Images
							</p>
							{#each imageResults as result}
								{@const flatIdx = flatItems.findIndex(i => i.kind === 'image' && i.data === result)}
								<button
									type="button"
									data-search-idx={flatIdx}
									onclick={() => selectItem({ kind: 'image', data: result })}
									onmouseenter={() => (selectedIndex = flatIdx)}
									class="flex w-full items-center gap-2.5 px-4 py-2 text-left transition-colors"
								>
									<Container size={12} style="flex-shrink:0; color: {flatIdx === selectedIndex ? 'var(--accent)' : 'var(--text-muted)'};" />
									<span class="min-w-0 flex-1 truncate text-[13px]" style="color: {flatIdx === selectedIndex ? 'var(--accent)' : 'var(--text-muted)'}; font-weight: {flatIdx === selectedIndex ? '500' : '400'};">
										{result.title}
									</span>
									{#if result.value}
										<span class="shrink-0 font-mono text-[10px]" style="color: var(--text-muted); opacity: 0.6;">
											{result.value.startsWith('sha256:') ? result.value.slice(7, 19) : result.value.slice(0, 12)}
										</span>
									{/if}
								</button>
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
									data-search-idx={flatIdx}
									onclick={() => selectItem({ kind: 'component', data: result })}
									onmouseenter={() => (selectedIndex = flatIdx)}
									class="flex w-full items-center gap-2.5 px-4 py-2 text-left transition-colors"
								>
									<Package size={12} style="flex-shrink:0; color: {flatIdx === selectedIndex ? 'var(--accent)' : 'var(--text-muted)'};" />
									<span class="min-w-0 flex-1 truncate text-[13px]" style="color: {flatIdx === selectedIndex ? 'var(--accent)' : 'var(--text-muted)'}; font-weight: {flatIdx === selectedIndex ? '500' : '400'};">
										{result.name}
									</span>
								</button>
							{/each}
						{/if}

					</div>

					<!-- Right: preview panel -->
					<div class="flex min-w-0 flex-1 flex-col overflow-y-auto" style="background: var(--bg-soft); min-height: 25em; padding: 0em 2em; margin-top: 0.5em;">

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
										{#if selectedItem?.kind === 'repo'}
											{#if selectedItem.data.provider === 'github'}
												<Github size={12} style="flex-shrink:0" />
											{:else if selectedItem.data.provider === 'gitlab'}
												<Gitlab size={12} style="flex-shrink:0" />
											{:else}
												<Gitea size={12} />
											{/if}
											<span class="text-[10px] uppercase tracking-widest">{providerLabel(selectedItem.data.provider)}</span>
											{#if selectedItem.data.base_url}
												<span class="truncate text-[9px]" style="opacity: 0.6;">{providerDisplay(selectedItem.data.base_url, selectedItem.data.owner_path)}</span>
											{/if}
										{/if}
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
								{#if repoPreview.vulnerabilities?.summary && (repoPreview.vulnerabilities.summary.critical > 0 || repoPreview.vulnerabilities.summary.high > 0 || repoPreview.vulnerabilities.summary.medium > 0 || repoPreview.vulnerabilities.summary.low > 0)}
									<div class="mb-4 pb-1">
										<VulnBadges
											critical={repoPreview.vulnerabilities.summary.critical}
											high={repoPreview.vulnerabilities.summary.high}
											medium={repoPreview.vulnerabilities.summary.medium}
											low={repoPreview.vulnerabilities.summary.low}
										/>
									</div>
								{/if}
								<div class="space-y-2.5">
									<div class="flex items-center gap-2.5">
										<Box size={13} style="color: var(--text-muted); flex-shrink:0;" />
										<span class="text-[11px]" style="color: var(--text-muted);">Dependencies</span>
										<span class="ml-auto text-[11px] font-medium" style="color: var(--text-primary);">
											{repoPreview.dependencies.total > 0 ? fmt(repoPreview.dependencies.total) : '—'}
										</span>
									</div>
									{#if repoPreview.sbom.latest}
										<div class="flex items-center gap-2.5">
											<ShieldCheck size={13} style="color: var(--text-muted); flex-shrink:0;" />
											<span class="text-[11px]" style="color: var(--text-muted);">SBOM</span>
											<span class="ml-auto text-[11px] font-medium" style="color: var(--text-primary);">
												{repoPreview.sbom.latest.format} · {fmt(repoPreview.sbom.latest.component_count)} components
											</span>
										</div>
									{/if}
									<div class="flex items-center gap-2.5">
										<ShieldCheck size={13} style="color: {repoPreview.secrets.latest_count > 0 ? 'var(--error)' : 'var(--text-muted)'}; flex-shrink:0;" />
										<span class="text-[11px]" style="color: var(--text-muted);">Secrets</span>
										<span class="ml-auto text-[11px] font-medium" style="color: {repoPreview.secrets.latest_count > 0 ? 'var(--error)' : 'var(--text-primary)'};">
											{repoPreview.secrets.latest_count > 0 ? `${fmt(repoPreview.secrets.latest_count)} found` : 'None found'}
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
										<span class="ml-auto text-[11px] font-medium" style="color: var(--text-primary);">{fmt(repoPreview.runs.total)}</span>
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
									class="mt-auto mb-4 ml-auto flex items-center gap-1.5 pt-5 text-[11px] font-medium transition-opacity hover:opacity-70"
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

						{:else if selectedItem?.kind === 'image'}
							{@const img = selectedItem.data}
							<div class="mb-4">
								<p class="text-[10px] uppercase tracking-widest" style="color: var(--text-muted);">Container image</p>
								<p class="mt-0.5 truncate text-sm font-semibold" style="color: var(--text-bright);">{img.title}</p>
							</div>
							{#if img.value}
								<div class="mb-3">
									<p class="text-[10px] uppercase tracking-widest" style="color: var(--text-muted);">Digest</p>
									<p class="mt-0.5 truncate font-mono text-[11px]" style="color: var(--text-primary);">{img.value}</p>
								</div>
							{/if}
							{#if previewLoading && !imagePreview}
								<div class="space-y-2">
									{#each [1, 2, 3, 4] as _}
										<div class="h-3 w-full rounded" style="background: var(--bg1);"></div>
									{/each}
								</div>
							{:else if imagePreview}
								{@const clusterCount = new Set((imagePreview.cluster_usage ?? []).map((c) => c.cluster)).size}
								{@const repoCount = imagePreview.linked_repo ? 1 : 0}
								{@const vulnTotal = imagePreview.vuln_severity?.total ?? 0}
								<div class="space-y-2.5">
									<div class="flex items-center gap-2.5">
										<GitBranch size={13} style="color: var(--text-muted); flex-shrink:0;" />
										<span class="text-[11px]" style="color: var(--text-muted);">Linked repo</span>
										<span class="ml-auto truncate text-[11px] font-medium" style="color: var(--text-primary);">
											{#if repoCount > 0 && imagePreview.linked_repo?.org}
												{imagePreview.linked_repo.org}/{imagePreview.linked_repo.slug}
											{:else}
												—
											{/if}
										</span>
									</div>
									<div class="flex items-center gap-2.5">
										<Box size={13} style="color: var(--text-muted); flex-shrink:0;" />
										<span class="text-[11px]" style="color: var(--text-muted);">Clusters</span>
										<span class="ml-auto text-[11px] font-medium" style="color: {clusterCount > 0 ? 'var(--text-primary)' : 'var(--text-muted)'};">
											{clusterCount > 0 ? clusterCount : '—'}
										</span>
									</div>
									<div class="flex items-center gap-2.5">
										<Microscope size={13} style="color: var(--text-muted); flex-shrink:0;" />
										<span class="text-[11px]" style="color: var(--text-muted);">Vulnerabilities</span>
										<span class="ml-auto text-[11px] font-medium" style="color: {vulnTotal > 0 ? 'var(--red)' : 'var(--text-muted)'};">
											{#if vulnTotal > 0 && imagePreview.vuln_severity}
												{imagePreview.vuln_severity.critical}C · {imagePreview.vuln_severity.high}H · {imagePreview.vuln_severity.medium}M · {imagePreview.vuln_severity.low}L
											{:else}
												—
											{/if}
										</span>
									</div>
									<div class="flex items-center gap-2.5">
										<ShieldCheck size={13} style="color: var(--text-muted); flex-shrink:0;" />
										<span class="text-[11px]" style="color: var(--text-muted);">Secrets</span>
										<span class="ml-auto text-[11px] font-medium" style="color: {imagePreview.secret_count > 0 ? 'var(--red)' : 'var(--text-muted)'};">
											{imagePreview.secret_count > 0 ? imagePreview.secret_count : '—'}
										</span>
									</div>
								</div>
							{/if}
							<button
								type="button"
								onclick={() => selectItem(selectedItem)}
								class="mt-auto flex items-center gap-1.5 pt-5 text-[11px] font-medium transition-opacity hover:opacity-70"
								style="color: var(--accent);"
							>
								Open image <ArrowRight size={11} />
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
					<div class="flex flex-col items-center gap-3 text-center">
						<SearchX size={32} style="color: var(--bg3);" />
						<p class="text-sm font-medium" style="color: var(--text-primary);">No results found</p>
						<p class="text-[11px]" style="color: var(--text-muted);">No results for <span style="color: var(--text-secondary);">"{query}"</span></p>
					</div>
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
							<button
								type="button"
								onclick={() => {
									close();
									goto(advancedSearchUrl());
								}}
								class="-mx-3 flex w-[calc(100%+1.5rem)] items-center justify-between gap-6 rounded-xl px-3 py-2 text-left transition-colors duration-150 hover:bg-[var(--hover-bg)]"
							>
							<div style="display: flex; align-items: center; gap: 1.5em;">
								<Microscope size={20} style="color: var(--accent); flex-shrink: 0; margin-left: 0.5em;" />
								<div class="ml-[0.2em]">
									<p style="color: var(--text-primary); font-size: 0.92em; font-weight: 500;">Advanced search</p>
									<p style="color: var(--text-muted); font-size: 0.78em; margin-top: 0.3em;">Search manifests, SBOMs, secrets, contributors, languages, commits, repos, and README</p>
								</div>
							</div>
							<ArrowRight size={14} style="color: var(--accent); flex-shrink: 0;" />
						</button>
					</div>
				</div>
			{/if}
		</div>
	</div>
{/if}
