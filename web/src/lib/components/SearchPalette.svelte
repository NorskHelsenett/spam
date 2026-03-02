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
	};

	type Preview = {
		repo: { provider: string; org: string; slug: string };
		runs: {
			total: number;
			latest?: { status: string; finished_at?: string; commit_sha?: string };
		};
		sbom: { latest?: { component_count: number; format: string; created_at: string } };
		dependencies: { total: number; from_sbom: number; from_manifest: number };
		secrets: { latest_count: number; latest_run_id?: string };
	};

	let open = $state(false);
	let query = $state('');
	let results = $state<RepoResult[]>([]);
	let loading = $state(false);
	let selectedIndex = $state(0);
	let preview = $state<Preview | null>(null);
	let previewLoading = $state(false);
	let inputEl: HTMLInputElement | undefined = $state();

	const previewCache = new Map<string, Preview>();
	let searchTimer: ReturnType<typeof setTimeout>;
	let previewTimer: ReturnType<typeof setTimeout>;

	const close = () => {
		open = false;
		query = '';
		results = [];
		preview = null;
		selectedIndex = 0;
	};

	const search = async (q: string) => {
		if (!q.trim()) {
			results = [];
			preview = null;
			return;
		}
		loading = true;
		try {
			const res = await fetch(`/api/repos/search?q=${encodeURIComponent(q)}&limit=12`);
			if (res.ok) {
				const data = await res.json();
				results = data.results ?? [];
				selectedIndex = 0;
			}
		} finally {
			loading = false;
		}
	};

	const fetchPreview = (result: RepoResult) => {
		const key = `${result.provider}:${result.org}:${result.slug}`;
		if (previewCache.has(key)) {
			preview = previewCache.get(key)!;
			return;
		}
		clearTimeout(previewTimer);
		previewLoading = true;
		previewTimer = setTimeout(async () => {
			try {
				const res = await fetch(`/api/repos/metadata?repo_id=${encodeURIComponent(key)}`);
				if (res.ok) {
					const data = await res.json();
					previewCache.set(key, data);
					preview = data;
				}
			} finally {
				previewLoading = false;
			}
		}, 120);
	};

	$effect(() => {
		const result = results[selectedIndex];
		if (result) fetchPreview(result);
		else preview = null;
	});

	const handleInput = () => {
		clearTimeout(searchTimer);
		searchTimer = setTimeout(() => search(query), 180);
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
			open ? close() : (open = true);
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

	// Group results by provider for category headers
	const grouped = $derived(() => {
		const map = new Map<string, RepoResult[]>();
		for (const r of results) {
			const list = map.get(r.provider) ?? [];
			list.push(r);
			map.set(r.provider, list);
		}
		return map;
	});

	// Flat index lookup per result (for selectedIndex tracking across groups)
	const flatResults = $derived(results);

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
</script>

{#if open}
	<!-- Backdrop -->
	<div
		class="fixed inset-0 z-50 bg-black/55"
		onclick={(e) => { if (e.target === e.currentTarget) close(); }}
		role="presentation"
	>
		<!-- Palette shell -->
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
					style="color: var(--text-muted); flex-shrink: 0; {loading ? 'opacity: 0.35' : 'opacity: 1'}; transition: opacity 200ms;"
				/>
				<input
					bind:this={inputEl}
					bind:value={query}
					oninput={handleInput}
					onkeydown={handleKeydown}
					type="text"
					placeholder="Search repositories…"
					style="flex: 1; background: transparent; color: var(--text-bright); caret-color: var(--accent); font-size: 1rem; font-weight: 500; outline: none;"
					class="placeholder:font-normal placeholder:text-[var(--text-muted)]"
				/>
				{#if query}
					<button
						type="button"
						onclick={() => { query = ''; results = []; preview = null; inputEl?.focus(); }}
						style="color: var(--text-muted); background: var(--bg1); border-radius: 999px; width: 18px; height: 18px; font-size: 9px; display: flex; align-items: center; justify-content: center; flex-shrink: 0;"
						aria-label="Clear"
					>✕</button>
				{/if}
			</div>

			<!-- Two-panel body -->
			{#if results.length > 0}
				<div class="flex" style="border-top: 1px solid var(--bg2);">

					<!-- Left: results list -->
					<div
						class="w-52 shrink-0 overflow-y-auto"
						style="background: var(--bg-hard); border-right: 1px solid var(--bg2);"
					>
						{#each [...grouped()] as [provider, repos]}
							<!-- Category header -->
							<p
								class="px-4 pb-1 pt-3 text-[9px] font-semibold uppercase tracking-[0.18em]"
								style="color: var(--text-muted);"
							>{providerLabel(provider)}</p>

							{#each repos as result}
								{@const flatIdx = flatResults.indexOf(result)}
								<button
									type="button"
									onclick={() => selectRepo(result)}
									onmouseenter={() => (selectedIndex = flatIdx)}
									class="flex w-full items-center gap-2.5 px-4 py-2 text-left transition-colors"
									style="background: {flatIdx === selectedIndex ? 'var(--bg1)' : 'transparent'};"
								>
									<GitBranch
										size={12}
										style="flex-shrink:0; color: {flatIdx === selectedIndex ? 'var(--accent)' : 'var(--bg4)'};"
									/>
									<span class="min-w-0 flex-1 truncate text-[13px]" style="color: {flatIdx === selectedIndex ? 'var(--text-bright)' : 'var(--text-secondary)'}; font-weight: {flatIdx === selectedIndex ? '500' : '400'};">
										{result.slug}
									</span>
								</button>
							{/each}
						{/each}
					</div>

					<!-- Right: preview panel -->
					<div class="flex min-w-0 flex-1 flex-col overflow-y-auto" style="border-top: 1px solid rgba(80, 73, 69, 0); background: var(--bg-soft); min-height: 25em; padding: 4em;">
						{#if previewLoading}
							<!-- Skeleton -->
							<div class="space-y-3 pt-1">
								<div class="h-4 w-3/4 rounded-lg" style="background: var(--bg1);"></div>
								<div class="h-3 w-1/2 rounded-lg" style="background: var(--bg1);"></div>
								<div class="mt-4 space-y-2">
									{#each [1,2,3,4] as _}
										<div class="h-3 w-full rounded" style="background: var(--bg1);"></div>
									{/each}
								</div>
							</div>
						{:else if preview}
							<!-- Repo title -->
							<div class="mb-4">
								<p class="text-[10px] uppercase tracking-widest" style="color: var(--text-muted);">{providerLabel(preview.repo.provider)}</p>
								<p class="mt-0.5 truncate text-sm font-semibold" style="color: var(--text-bright);">
									{preview.repo.org}<span style="color: var(--text-muted);">/</span>{preview.repo.slug}
								</p>
							</div>

							<!-- Metadata rows -->
							<div class="space-y-2.5">
								<!-- Dependencies -->
								<div class="flex items-center gap-2.5">
									<Box size={13} style="color: var(--text-muted); flex-shrink:0;" />
									<span class="text-[11px]" style="color: var(--text-muted);">Dependencies</span>
									<span class="ml-auto text-[11px] font-medium" style="color: var(--text-primary);">
										{preview.dependencies.total > 0 ? preview.dependencies.total : '—'}
									</span>
								</div>

								<!-- SBOM -->
								{#if preview.sbom.latest}
									<div class="flex items-center gap-2.5">
										<ShieldCheck size={13} style="color: var(--text-muted); flex-shrink:0;" />
										<span class="text-[11px]" style="color: var(--text-muted);">SBOM</span>
										<span class="ml-auto text-[11px] font-medium" style="color: var(--text-primary);">
											{preview.sbom.latest.format} · {preview.sbom.latest.component_count} components
										</span>
									</div>
								{/if}

								<!-- Secrets -->
								<div class="flex items-center gap-2.5">
									<ShieldCheck size={13} style="color: {preview.secrets.latest_count > 0 ? 'var(--error)' : 'var(--text-muted)'}; flex-shrink:0;" />
									<span class="text-[11px]" style="color: var(--text-muted);">Secrets</span>
									<span class="ml-auto text-[11px] font-medium" style="color: {preview.secrets.latest_count > 0 ? 'var(--error)' : 'var(--text-primary)'};">
										{preview.secrets.latest_count > 0 ? `${preview.secrets.latest_count} found` : 'None found'}
									</span>
								</div>

								<!-- Latest run -->
								{#if preview.runs.latest}
									<div class="flex items-center gap-2.5">
										<Play size={12} style="color: var(--text-muted); flex-shrink:0;" />
										<span class="text-[11px]" style="color: var(--text-muted);">Last run</span>
										<span class="ml-auto flex items-center gap-1.5 text-[11px] font-medium">
											<span style="color: {statusColor(preview.runs.latest.status)};">●</span>
											<span style="color: var(--text-primary);">{preview.runs.latest.status}</span>
											<span style="color: var(--text-muted);">{relativeTime(preview.runs.latest.finished_at)}</span>
										</span>
									</div>
								{:else}
									<div class="flex items-center gap-2.5">
										<Play size={12} style="color: var(--text-muted); flex-shrink:0;" />
										<span class="text-[11px]" style="color: var(--text-muted);">Last run</span>
										<span class="ml-auto text-[11px]" style="color: var(--text-muted);">Never scanned</span>
									</div>
								{/if}

								<!-- Scan count -->
								<div class="flex items-center gap-2.5">
									<Play size={12} style="color: var(--text-muted); flex-shrink:0;" />
									<span class="text-[11px]" style="color: var(--text-muted);">Total scans</span>
									<span class="ml-auto text-[11px] font-medium" style="color: var(--text-primary);">{preview.runs.total}</span>
								</div>
							</div>

							<!-- Open button -->
							<button
								type="button"
								onclick={() => selectRepo(results[selectedIndex])}
								class="mt-auto flex items-center gap-1.5 pt-5 text-[11px] font-medium transition-opacity hover:opacity-70"
								style="color: var(--accent);"
							>
								Open repository <ArrowRight size={11} />
							</button>
						{:else}
							<!-- Empty preview state -->
							<div class="flex flex-col items-center justify-center gap-2 py-10 text-center">
								<GitBranch size={28} style="color: var(--bg3);" />
								<p class="text-[11px]" style="color: var(--text-muted);">Select a repository to preview</p>
							</div>
						{/if}
					</div>
				</div>

			{:else if query.trim() && !loading}
				<!-- No results -->
				<div style="border-top: 1px solid rgba(80, 73, 69, 0); background: var(--bg-soft); min-height: 25em; padding: 4em; display: flex; align-items: center; justify-content: center;">
					<p class="text-sm" style="color: var(--text-muted);">No repositories found for <span style="color: var(--text-primary);">"{query}"</span></p>
				</div>

			{:else if !query.trim()}
				<!-- Idle hint panel -->
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
