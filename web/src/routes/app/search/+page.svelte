<script lang="ts">
	import { browser } from '$app/environment';
	import { onMount } from 'svelte';
	import { tick } from 'svelte';
	import { goto } from '$app/navigation';
	import { Search, ArrowRight, GitBranch, FileCode2, ShieldAlert, Users, Braces, Hash, BookOpen, Boxes, FolderGit2, Eye, ChevronUp, ChevronDown, Github, Gitlab } from 'lucide-svelte';
	import Select from '$lib/components/Select.svelte';
	import Dialog from '$lib/components/Dialog.svelte';
	import Gitea from '$lib/components/icons/Gitea.svelte';

	type AdvancedSearchType = 'manifest' | 'sbom' | 'secret' | 'contributor' | 'language' | 'commit' | 'repo' | 'readme';

	type AdvancedSearchResult = {
		type: AdvancedSearchType;
		source_ref?: string;
		repo_id: string;
		provider: string;
		provider_id?: string;
		base_url?: string;
		owner_path?: string;
		org: string;
		slug: string;
		title: string;
		value?: string;
		snippet?: string;
		created_at?: string;
	};

	type AdvancedPreview = {
		type: AdvancedSearchType;
		raw: string;
		metadata: Record<string, string>;
		repo_id?: string;
		provider?: string;
		org?: string;
		slug?: string;
		source_ref?: string;
	};

	let loading = $state(false);
	let error = $state('');
	let query = $state('');
	let target = $state('all');
	let hasMore = $state(false);
	let results = $state<AdvancedSearchResult[]>([]);
	let searchTimeout: ReturnType<typeof setTimeout> | null = null;

	let previewOpen = $state(false);
	let previewLoading = $state(false);
	let previewError = $state('');
	let previewData = $state<AdvancedPreview | null>(null);
	let previewSearch = $state('');
	let previewFrom = $state<AdvancedSearchResult | null>(null);
	let previewRawEl: HTMLDivElement | undefined = $state();
	let previewFindingCount = $state(0);
	let activeFindingIndex = $state(0);

	const targetOptions = [
		{ value: 'all', label: 'All targets' },
		{ value: 'repo', label: 'Repositories' },
		{ value: 'commit', label: 'Commits' },
		{ value: 'manifest', label: 'Manifest files' },
		{ value: 'sbom', label: 'SBOM files' },
		{ value: 'secret', label: 'Secrets' },
		{ value: 'contributor', label: 'Contributors' },
		{ value: 'language', label: 'Languages' },
		{ value: 'readme', label: 'README files' }
	];

	const iconForType = (type: AdvancedSearchType) => {
		switch (type) {
			case 'repo':
				return FolderGit2;
			case 'commit':
				return Hash;
			case 'manifest':
				return FileCode2;
			case 'sbom':
				return Boxes;
			case 'secret':
				return ShieldAlert;
			case 'contributor':
				return Users;
			case 'language':
				return Braces;
			case 'readme':
				return BookOpen;
			default:
				return GitBranch;
		}
	};

	const labelForType = (type: AdvancedSearchType) => {
		switch (type) {
			case 'repo': return 'Repository';
			case 'commit': return 'Commit';
			case 'manifest': return 'Manifest';
			case 'sbom': return 'SBOM';
			case 'secret': return 'Secret';
			case 'contributor': return 'Contributor';
			case 'language': return 'Language';
			case 'readme': return 'README';
		}
	};

	const providerLabel = (p: string) =>
		({ github: 'GitHub', gitlab: 'GitLab', gitea: 'Gitea', forgejo: 'Forgejo' })[p] ?? p;

	const providerDisplay = (provider: string, baseURL?: string, ownerPath?: string) => {
		let base = (baseURL || '').replace(/^https?:\/\//, '');
		if (!base) {
			if (provider === 'github') base = 'github.com';
			else if (provider === 'gitlab') base = 'gitlab.com';
		}
		if (!base) return '';
		return ownerPath ? `${base}/${ownerPath}` : base;
	};

	const escapeRegex = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

	const splitHighlighted = (text: string | undefined, q: string) => {
		const source = text ?? '';
		const term = q.trim();
		if (!source || !term) {
			return [{ text: source, match: false }];
		}
		const pattern = new RegExp(`(${escapeRegex(term)})`, 'gi');
		return source
			.split(pattern)
			.filter((part) => part.length > 0)
			.map((part) => ({ text: part, match: part.toLowerCase() === term.toLowerCase() }));
	};

	const loadResults = async () => {
		if (!query.trim()) {
			results = [];
			error = '';
			hasMore = false;
			return;
		}
		loading = true;
		error = '';
		try {
			const params = new URLSearchParams({ q: query.trim(), per_page: '120' });
			if (target !== 'all') params.set('target', target);
			const res = await fetch(`/api/search/advanced?${params}`, { credentials: 'include' });
			if (!res.ok) {
				error = res.status === 401 ? 'Please log in.' : 'Failed to run advanced search.';
				results = [];
				return;
			}
			const data = await res.json();
			results = data.results || [];
			hasMore = !!data.has_more;
		} catch {
			error = 'Failed to run advanced search.';
			results = [];
		} finally {
			loading = false;
		}
	};

	const scheduleSearch = () => {
		if (searchTimeout) clearTimeout(searchTimeout);
		searchTimeout = setTimeout(() => {
			loadResults();
		}, 220);
	};

	const openRepo = (r: AdvancedSearchResult) => {
		const params = new URLSearchParams({ provider: r.provider, path: `${r.org}/${r.slug}` });
		if (r.repo_id) params.set('repo_id', r.repo_id);
		if (r.provider_id) params.set('provider_id', r.provider_id);
		else if (r.base_url) params.set('base_url', r.base_url);
		goto(`/app/providers/repo?${params.toString()}`);
	};

	const openPreview = async (r: AdvancedSearchResult) => {
		if (!r.source_ref) return;
		previewOpen = true;
		previewLoading = true;
		previewError = '';
		previewData = null;
		previewFrom = r;
		previewSearch = query;
		try {
			const params = new URLSearchParams({
				type: r.type,
				source_ref: r.source_ref,
				repo_id: r.repo_id
			});
			const res = await fetch(`/api/search/preview?${params}`, { credentials: 'include' });
			if (!res.ok) {
				previewError = res.status === 404 ? 'Preview not found.' : 'Failed to load preview.';
				return;
			}
			previewData = await res.json();
		} catch {
			previewError = 'Failed to load preview.';
		} finally {
			previewLoading = false;
		}
	};

	const previewMetadataRows = $derived.by(() => {
		if (!previewData?.metadata) return [] as Array<[string, string]>;
		return Object.entries(previewData.metadata)
			.filter(([, v]) => (v ?? '').toString().trim().length > 0)
			.sort((a, b) => a[0].localeCompare(b[0]));
	});

	const syncPreviewFindings = async () => {
		await tick();
		if (!previewRawEl) {
			previewFindingCount = 0;
			activeFindingIndex = 0;
			return;
		}
		const marks = Array.from(previewRawEl.querySelectorAll('mark[data-preview-hit="1"]')) as HTMLElement[];
		previewFindingCount = marks.length;
		if (marks.length === 0) {
			activeFindingIndex = 0;
			return;
		}
		if (activeFindingIndex < 1 || activeFindingIndex > marks.length) {
			activeFindingIndex = 1;
		}
		marks.forEach((m, idx) => {
			if (idx === activeFindingIndex - 1) {
				m.style.outline = '1px solid var(--accent)';
				m.style.boxShadow = '0 0 0 1px color-mix(in srgb, var(--accent) 28%, transparent)';
			} else {
				m.style.outline = '';
				m.style.boxShadow = '';
			}
		});
		marks[activeFindingIndex - 1]?.scrollIntoView({ block: 'center', behavior: 'smooth' });
	};

	const gotoPrevFinding = () => {
		if (previewFindingCount === 0) return;
		activeFindingIndex = activeFindingIndex <= 1 ? previewFindingCount : activeFindingIndex - 1;
		void syncPreviewFindings();
	};

	const gotoNextFinding = () => {
		if (previewFindingCount === 0) return;
		activeFindingIndex = activeFindingIndex >= previewFindingCount ? 1 : activeFindingIndex + 1;
		void syncPreviewFindings();
	};

	$effect(() => {
		void previewSearch;
		void previewData?.raw;
		void previewOpen;
		if (!previewOpen) {
			previewFindingCount = 0;
			activeFindingIndex = 0;
			return;
		}
		void syncPreviewFindings();
	});

	onMount(() => {
		if (!browser) return;
		const q = new URLSearchParams(window.location.search).get('q');
		if (q) {
			query = q;
			loadResults();
		}
	});
</script>

<svelte:head>
	<title>Advanced Search - SPAM</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface flex h-[calc(100vh-7rem)] flex-col gap-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-2">
			<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Advanced Search</h1>
			<p class="text-sm text-[var(--text-tertiary)]">Search inside manifests, SBOMs, secrets, contributors, languages, commit IDs, repositories, and README files.</p>
		</header>

		<div class="grid grid-cols-1 gap-3 sm:grid-cols-[1fr_auto]">
			<div class="relative">
				<Search class="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-tertiary)]" />
				<input
					type="text"
					bind:value={query}
					oninput={scheduleSearch}
					placeholder="Search for java, pom.xml, commit SHA, secrets, contributor email, README text..."
					class="h-11 w-full rounded-full border border-[var(--border-color)] bg-[var(--card-bg)] pl-11 pr-4 text-sm text-[var(--text-primary)] outline-none transition placeholder:text-[var(--text-tertiary)] focus:border-[var(--accent)]"
				/>
			</div>
			<Select value={target} options={targetOptions} onchange={() => loadResults()} class="w-full sm:w-[13rem]" />
		</div>

		{#if error}
			<div class="rounded-xl border border-[var(--error)]/40 bg-[var(--error)]/10 px-4 py-3 text-sm text-[var(--error)]">{error}</div>
		{/if}

		<div class="relative flex min-h-0 flex-1 flex-col overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
			{#if loading}
				<div class="flex h-full items-center justify-center text-sm text-[var(--text-muted)]">Searching...</div>
			{:else if !query.trim()}
				<div class="flex h-full items-center justify-center px-6 text-center text-sm text-[var(--text-muted)]">Enter a query to run advanced search across all indexed repository data.</div>
			{:else if results.length === 0}
				<div class="flex h-full items-center justify-center px-6 text-center text-sm text-[var(--text-muted)]">No advanced search matches for "{query}".</div>
			{:else}
				<div class="flex-1 overflow-y-auto">
					<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
						<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
							<tr>
								<th class="px-5 py-3 text-left">Type</th>
								<th class="px-5 py-3 text-left">Repository</th>
								<th class="px-5 py-3 text-left">Match</th>
								<th class="px-5 py-3 text-right">Actions</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
							{#each results as r}
								{@const Icon = iconForType(r.type)}
								<tr class="transition hover:bg-[var(--hover-bg-subtle)]">
									<td class="px-5 py-3 align-top">
										<div class="inline-flex items-center gap-2 rounded-full bg-[var(--hover-bg)] px-2.5 py-1 text-xs text-[var(--text-secondary)]">
											<Icon class="h-3.5 w-3.5" />
											<span>{labelForType(r.type)}</span>
										</div>
									</td>
									<td class="px-5 py-3 align-top text-[var(--text-primary)]">
										{#each splitHighlighted(`${r.org}/${r.slug}`, query) as part}
											{#if part.match}
												<mark class="rounded bg-[var(--yellow-dim)] px-1 text-[var(--text-bright)]">{part.text}</mark>
											{:else}
												{part.text}
											{/if}
										{/each}
									</td>
									<td class="px-5 py-3 align-top">
										<p class="font-semibold text-[var(--text-bright)]">
											{#each splitHighlighted(r.title, query) as part}
												{#if part.match}
													<mark class="rounded bg-[var(--yellow-dim)] px-1 text-[var(--text-bright)]">{part.text}</mark>
												{:else}
													{part.text}
												{/if}
											{/each}
										</p>
										{#if r.value}
											<p class="mt-1 font-mono text-xs text-[var(--text-muted)]">
												{#each splitHighlighted(r.value, query) as part}
													{#if part.match}
														<mark class="rounded bg-[var(--yellow-dim)] px-1 text-[var(--text-bright)]">{part.text}</mark>
													{:else}
														{part.text}
													{/if}
												{/each}
											</p>
										{/if}
										<p class="mt-1 line-clamp-2 text-xs text-[var(--text-tertiary)]">
											{#each splitHighlighted(r.snippet || `${r.title} ${r.value || ''}`, query) as part}
												{#if part.match}
													<mark class="rounded bg-[var(--yellow-dim)] px-1 text-[var(--text-bright)]">{part.text}</mark>
												{:else}
													{part.text}
												{/if}
											{/each}
										</p>
									</td>
										<td class="px-5 py-3 align-middle text-right">
											<div class="flex h-full items-center justify-end gap-3">
											<button
												type="button"
												onclick={() => openPreview(r)}
												disabled={!r.source_ref}
												class="inline-flex items-center gap-1 rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
											>
													<Eye class="h-3.5 w-3.5" /> Preview
												</button>
											<button
												type="button"
												onclick={() => openRepo(r)}
												class="inline-flex items-center gap-1.5 text-[11px] font-medium transition-opacity hover:opacity-70"
												style="color: var(--accent);"
											>
												Open repository <ArrowRight class="h-3.5 w-3.5" />
											</button>
										</div>
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</div>

		{#if hasMore}
			<p class="text-xs text-[var(--text-muted)]">Showing the top matches only. Narrow your query or target for more precise results.</p>
		{/if}
	</section>
</div>

<Dialog bind:open={previewOpen} maxWidth="max-w-6xl" onClose={() => { previewData = null; previewError = ''; previewFrom = null; }}>
	<div class="flex min-h-[70vh] w-full flex-col overflow-hidden">
		<div class="border-b border-[var(--border-color)] px-6 py-4">
			<div class="flex flex-wrap items-start justify-between gap-3">
				<div>
					<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">RAW Preview</p>
					<h3 class="text-lg font-semibold text-[var(--text-bright)]">
						{previewFrom ? `${previewFrom.org}/${previewFrom.slug}` : 'Preview'}
					</h3>
					{#if previewFrom}
						<p class="mt-1 flex items-center gap-1.5 text-xs text-[var(--text-muted)]">
							{#if previewFrom.provider === 'github'}
								<Github class="h-3.5 w-3.5" />
							{:else if previewFrom.provider === 'gitlab'}
								<Gitlab class="h-3.5 w-3.5" />
							{:else}
								<Gitea size={14} />
							{/if}
							<span>{providerLabel(previewFrom.provider)}:</span>
							<span>{providerDisplay(previewFrom.provider, previewFrom.base_url, previewFrom.owner_path) || `${previewFrom.org}/${previewFrom.slug}`}</span>
						</p>
					{/if}
				</div>
				{#if previewFrom}
					<button
						type="button"
						onclick={() => openRepo(previewFrom)}
						class="inline-flex shrink-0 items-center gap-1.5 pt-1 text-[11px] font-medium transition-opacity hover:opacity-70"
						style="color: var(--accent);"
					>
						Open repository <ArrowRight class="h-3.5 w-3.5" />
					</button>
				{/if}
			</div>

			{#if previewFrom}
				<div class="mt-3 flex flex-wrap gap-2">
					<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-2 py-0.5 text-[10px] text-[var(--text-secondary)]">type: {previewFrom.type}</span>
					{#if previewFrom.title}<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-2 py-0.5 text-[10px] text-[var(--text-secondary)]">title: {previewFrom.title}</span>{/if}
					{#if previewFrom.value}<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-2 py-0.5 text-[10px] text-[var(--text-secondary)]">value: {previewFrom.value}</span>{/if}
				</div>
			{/if}
		</div>

		<div class="min-h-0 flex-1 overflow-auto bg-[var(--main-content-bg)] p-4">
			<p class="mb-2 text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Metadata</p>
			{#if previewLoading}
				<p class="text-xs text-[var(--text-muted)]">Loading preview...</p>
			{:else if previewError}
				<p class="text-xs text-[var(--error)]">{previewError}</p>
			{:else if previewData}
				<div class="mb-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
					{#each previewMetadataRows as [k, v]}
						<div class="rounded-lg border border-[var(--border-color)]/60 bg-[var(--card-bg)]/50 p-2">
							<p class="text-[10px] uppercase tracking-[0.16em] text-[var(--text-muted)]">{k}</p>
							<p class="mt-1 break-all text-xs text-[var(--text-secondary)]">{v}</p>
						</div>
					{/each}
				</div>
				<div bind:this={previewRawEl}>
					<div class="sticky top-2 z-10 mb-3 flex justify-end pe-6">
						<div class="pointer-events-auto w-full max-w-sm rounded-full border border-[var(--border-color)] bg-[var(--card-bg)] shadow-lg">
						<div class="flex items-center">
							<div class="relative min-w-0 flex-1">
								<Search class="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-[var(--text-tertiary)]" />
								<input
									type="text"
									bind:value={previewSearch}
									placeholder="Find in preview..."
									class="h-9 w-full rounded-l-full bg-transparent pl-9 pr-3 text-xs text-[var(--text-primary)] outline-none"
								/>
							</div>
							<div class="h-5 w-px bg-[var(--border-color)]/80"></div>
							<button
								type="button"
								class="inline-flex h-7 w-7 items-center justify-center rounded-full text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
								onclick={gotoPrevFinding}
								disabled={previewFindingCount === 0}
								aria-label="Previous finding"
							>
								<ChevronUp class="h-3.5 w-3.5" />
							</button>
							<button
								type="button"
								class="inline-flex h-7 w-7 items-center justify-center rounded-full text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
								onclick={gotoNextFinding}
								disabled={previewFindingCount === 0}
								aria-label="Next finding"
							>
								<ChevronDown class="h-3.5 w-3.5" />
							</button>
							<span class="min-w-10 pe-2 text-right tabular-nums text-xs text-[var(--text-muted)]">
								{#if previewFindingCount > 0}{activeFindingIndex}/{previewFindingCount}{:else}0/0{/if}
							</span>
						</div>
					</div>
					</div>
					<pre class="whitespace-pre-wrap break-words rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/35 p-4 pt-2 font-mono text-xs leading-relaxed text-[var(--text-secondary)]">{#each splitHighlighted(previewData.raw || '', previewSearch) as part}{#if part.match}<mark data-preview-hit="1" class="rounded bg-[var(--yellow-dim)] px-1 text-[var(--text-bright)]">{part.text}</mark>{:else}{part.text}{/if}{/each}</pre>
				</div>
			{:else}
				<p class="text-sm text-[var(--text-muted)]">No content to preview.</p>
			{/if}
		</div>
	</div>
</Dialog>
