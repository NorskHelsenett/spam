<script lang="ts">
	import { onMount, onDestroy } from 'svelte';
	import { browser } from '$app/environment';
	import { goto } from '$app/navigation';
	import { get } from 'svelte/store';
	import { Search, GitBranch, Folder, ChevronRight, ExternalLink, Archive, GitFork, Lock, Plus, X, Globe, Loader2 } from 'lucide-svelte';
	import { providersState, type ProvidersState } from '$lib/stores/providersState';

	type RepoData = {
		external_id: string;
		name: string;
		full_path: string;
		description: string;
		html_url: string;
		default_branch: string;
		language: string;
		is_private: boolean;
		is_archived: boolean;
		is_fork: boolean;
		topics: string[];
		created_at: string;
		updated_at: string;
		pushed_at: string;
	};

	type GroupData = {
		external_id: string;
		name: string;
		path: string;
		full_path: string;
		description: string;
		html_url: string;
		parent_id: string;
		visibility: string;
	};

	type GitHubResponse = {
		repos: RepoData[];
		total_count: number;
		page: number;
		page_size: number;
		has_next_page: boolean;
		next_page: number;
	};

	type GitLabProjectsResponse = {
		projects: RepoData[];
		total_count: number;
		page: number;
		page_size: number;
		has_next_page: boolean;
		next_page: number;
	};

	type GitLabGroupsResponse = {
		groups: GroupData[];
		total_count: number;
		page: number;
		page_size: number;
		has_next_page: boolean;
		next_page: number;
	};

	type CustomProvider = {
		id: string;
		name: string;
		type: 'gitlab' | 'gitea' | 'forgejo';
		baseUrl: string;
	};

	const STORAGE_KEY = 'spam-custom-providers';

	// Tab state
	let activeTab: string = $state('github');
	let showAddForm = $state(false);

	// Custom providers from localStorage
	let customProviders: CustomProvider[] = $state([]);

	// New provider form
	let newProviderUrl = $state('');
	let detecting = $state(false);
	let detectError = $state('');

	// GitHub state
	let ghOwner = $state('NorskHelsenett');
	let ghRepos: RepoData[] = $state([]);
	let ghLoading = $state(false);
	let ghError = $state('');
	let ghPage = $state(1);
	let ghHasNextPage = $state(false);
	let ghTotalCount = $state(0);

	// GitLab state
	let glGroup = $state('gitlab-org');
	let glProjects: RepoData[] = $state([]);
	let glSubgroups: GroupData[] = $state([]);
	let glLoading = $state(false);
	let glError = $state('');
	let glPage = $state(1);
	let glHasNextPage = $state(false);
	let glTotalCount = $state(0);
	let glIncludeSubgroups = $state(false);
	let glGroupPath: string[] = $state([]);

	// Custom provider state (for active custom tab)
	let cpGroup = $state('');
	let cpProjects: RepoData[] = $state([]);
	let cpSubgroups: GroupData[] = $state([]);
	let cpLoading = $state(false);
	let cpError = $state('');
	let cpPage = $state(1);
	let cpHasNextPage = $state(false);
	let cpTotalCount = $state(0);
	let cpIncludeSubgroups = $state(false);
	let cpGroupPath: string[] = $state([]);

	const pageSize = 30;

	// Save state to store when navigating away
	const saveState = () => {
		providersState.set({
			activeTab,
			ghOwner,
			ghRepos,
			ghPage,
			ghHasNextPage,
			ghTotalCount,
			glGroup,
			glProjects,
			glSubgroups,
			glPage,
			glHasNextPage,
			glTotalCount,
			glIncludeSubgroups,
			glGroupPath,
			cpGroup,
			cpProjects,
			cpSubgroups,
			cpPage,
			cpHasNextPage,
			cpTotalCount,
			cpIncludeSubgroups,
			cpGroupPath,
			customProviders,
			lastUpdated: Date.now()
		});
	};

	// Restore state from store
	const restoreState = () => {
		const state = get(providersState);
		// Only restore if state was saved recently (within 30 minutes)
		if (state.lastUpdated && Date.now() - state.lastUpdated < 30 * 60 * 1000) {
			activeTab = state.activeTab;
			ghOwner = state.ghOwner;
			ghRepos = state.ghRepos;
			ghPage = state.ghPage;
			ghHasNextPage = state.ghHasNextPage;
			ghTotalCount = state.ghTotalCount;
			glGroup = state.glGroup;
			glProjects = state.glProjects;
			glSubgroups = state.glSubgroups;
			glPage = state.glPage;
			glHasNextPage = state.glHasNextPage;
			glTotalCount = state.glTotalCount;
			glIncludeSubgroups = state.glIncludeSubgroups;
			glGroupPath = state.glGroupPath;
			cpGroup = state.cpGroup;
			cpProjects = state.cpProjects;
			cpSubgroups = state.cpSubgroups;
			cpPage = state.cpPage;
			cpHasNextPage = state.cpHasNextPage;
			cpTotalCount = state.cpTotalCount;
			cpIncludeSubgroups = state.cpIncludeSubgroups;
			cpGroupPath = state.cpGroupPath;
			if (state.customProviders.length > 0) {
				customProviders = state.customProviders;
			}
			return true; // State was restored
		}
		return false; // No valid state to restore
	};

	// Load custom providers from localStorage
	const loadCustomProviders = () => {
		if (!browser) return;
		try {
			const stored = localStorage.getItem(STORAGE_KEY);
			if (stored) {
				customProviders = JSON.parse(stored);
			}
		} catch {
			customProviders = [];
		}
	};

	// Save custom providers to localStorage
	const saveCustomProviders = () => {
		if (!browser) return;
		localStorage.setItem(STORAGE_KEY, JSON.stringify(customProviders));
	};

	// Normalize URL: add https://, convert SSH to HTTPS
	const normalizeUrl = (input: string): string => {
		let url = input.trim().replace(/\/+$/, '');

		// Handle SSH format: git@host:path -> https://host
		if (url.startsWith('git@')) {
			const match = url.match(/^git@([^:]+):/);
			if (match) {
				url = match[1];
			}
		}

		// Remove .git suffix if present
		url = url.replace(/\.git$/, '');

		// Add https:// if no protocol specified
		if (!url.includes('://')) {
			url = 'https://' + url;
		}

		// Extract just the origin (protocol + host)
		try {
			const parsed = new URL(url);
			return `${parsed.protocol}//${parsed.host}`;
		} catch {
			return url;
		}
	};

	// Detect and add a new custom provider
	const detectAndAddProvider = async () => {
		if (!newProviderUrl.trim()) return;

		detecting = true;
		detectError = '';

		try {
			const url = normalizeUrl(newProviderUrl);
			const params = new URLSearchParams({ url });

			const response = await fetch(`/api/providers/detect?${params}`, {
				credentials: 'include'
			});

			if (!response.ok) {
				detectError = 'Failed to detect provider type.';
				return;
			}

			const data = await response.json();

			if (data.type === 'unknown') {
				detectError = 'Could not detect provider type. Make sure the URL is a GitLab or Gitea/Forgejo instance.';
				return;
			}

			const provider: CustomProvider = {
				id: crypto.randomUUID(),
				name: data.name,
				type: data.type,
				baseUrl: url
			};

			customProviders = [...customProviders, provider];
			saveCustomProviders();

			// Reset form
			newProviderUrl = '';
			showAddForm = false;

			// Switch to the new provider tab
			activeTab = provider.id;
			cpGroup = '';
			fetchCustomProjects(provider, 1);
			fetchCustomSubgroups(provider);
		} catch {
			detectError = 'Failed to connect to the URL.';
		} finally {
			detecting = false;
		}
	};

	// Remove a custom provider
	const removeCustomProvider = (id: string) => {
		customProviders = customProviders.filter(p => p.id !== id);
		saveCustomProviders();
		if (activeTab === id) {
			activeTab = 'github';
		}
	};

	// Get active custom provider
	const getActiveCustomProvider = (): CustomProvider | undefined => {
		return customProviders.find(p => p.id === activeTab);
	};

	const handleAddUrlKeydown = (e: KeyboardEvent) => {
		if (e.key === 'Enter') detectAndAddProvider();
		if (e.key === 'Escape') {
			showAddForm = false;
			newProviderUrl = '';
			detectError = '';
		}
	};

	// GitHub functions
	const fetchGitHubRepos = async (page = 1) => {
		if (!ghOwner.trim()) return;

		ghLoading = true;
		ghError = '';

		try {
			const params = new URLSearchParams({
				page: String(page),
				page_size: String(pageSize)
			});

			const response = await fetch(`/api/providers/github/${encodeURIComponent(ghOwner)}/repos?${params}`, {
				credentials: 'include'
			});

			if (!response.ok) {
				if (response.status === 404) {
					ghError = `Owner "${ghOwner}" not found on GitHub.`;
				} else if (response.status === 429) {
					ghError = 'Rate limited by GitHub API. Try again later.';
				} else if (response.status === 401) {
					ghError = 'Please log in to access this feature.';
				} else {
					ghError = `Failed to fetch repositories (${response.status}).`;
				}
				ghRepos = [];
				return;
			}

			const data: GitHubResponse = await response.json();
			ghRepos = data.repos || [];
			ghPage = page;
			ghHasNextPage = data.has_next_page;
			ghTotalCount = data.total_count;
		} catch (err) {
			ghError = 'Failed to connect to API.';
			ghRepos = [];
		} finally {
			ghLoading = false;
		}
	};

	// GitLab functions
	const fetchGitLabProjects = async (page = 1) => {
		if (!glGroup.trim()) return;

		glLoading = true;
		glError = '';

		try {
			const params = new URLSearchParams({
				page: String(page),
				page_size: String(pageSize),
				include_subgroups: String(glIncludeSubgroups)
			});

			const response = await fetch(`/api/providers/gitlab/${encodeURIComponent(glGroup)}/projects?${params}`, {
				credentials: 'include'
			});

			if (!response.ok) {
				if (response.status === 404) {
					glError = `Group "${glGroup}" not found on GitLab.`;
				} else if (response.status === 429) {
					glError = 'Rate limited by GitLab API. Try again later.';
				} else if (response.status === 401) {
					glError = 'Please log in to access this feature.';
				} else {
					glError = `Failed to fetch projects (${response.status}).`;
				}
				glProjects = [];
				return;
			}

			const data: GitLabProjectsResponse = await response.json();
			glProjects = data.projects || [];
			glPage = page;
			glHasNextPage = data.has_next_page;
			glTotalCount = data.total_count;
		} catch (err) {
			glError = 'Failed to connect to API.';
			glProjects = [];
		} finally {
			glLoading = false;
		}
	};

	const fetchGitLabSubgroups = async () => {
		try {
			const params = new URLSearchParams({
				page: '1',
				page_size: '50'
			});

			const response = await fetch(`/api/providers/gitlab/${encodeURIComponent(glGroup)}/subgroups?${params}`, {
				credentials: 'include'
			});

			if (response.ok) {
				const data: GitLabGroupsResponse = await response.json();
				glSubgroups = data.groups || [];
			} else {
				glSubgroups = [];
			}
		} catch {
			glSubgroups = [];
		}
	};

	// Custom provider functions
	const fetchCustomProjects = async (provider: CustomProvider, page = 1) => {
		cpLoading = true;
		cpError = '';

		try {
			const params = new URLSearchParams({
				page: String(page),
				page_size: String(pageSize),
				base_url: provider.baseUrl
			});

			const groupPath = cpGroup.trim();
			let url: string;

			if (provider.type === 'gitlab') {
				params.set('include_subgroups', String(cpIncludeSubgroups));
				url = groupPath
					? `/api/providers/gitlab/${encodeURIComponent(groupPath)}/projects?${params}`
					: `/api/providers/gitlab/projects?${params}`;
			} else {
				// Gitea/Forgejo (both use the same API)
				url = groupPath
					? `/api/providers/gitea/${encodeURIComponent(groupPath)}/repos?${params}`
					: `/api/providers/gitea/repos?${params}`;
			}

			const response = await fetch(url, {
				credentials: 'include'
			});

			if (!response.ok) {
				if (response.status === 404) {
					cpError = `"${cpGroup}" not found.`;
				} else if (response.status === 429) {
					cpError = 'Rate limited. Try again later.';
				} else if (response.status === 401) {
					cpError = 'Please log in to access this feature.';
				} else {
					cpError = `Failed to fetch projects (${response.status}).`;
				}
				cpProjects = [];
				return;
			}

			const data = await response.json();
			cpProjects = data.projects || data.repos || [];
			cpPage = page;
			cpHasNextPage = data.has_next_page;
			cpTotalCount = data.total_count;
		} catch (err) {
			cpError = 'Failed to connect to API.';
			cpProjects = [];
		} finally {
			cpLoading = false;
		}
	};

	const fetchCustomSubgroups = async (provider: CustomProvider) => {
		// Gitea/Forgejo don't have subgroups like GitLab
		if (provider.type !== 'gitlab') {
			cpSubgroups = [];
			return;
		}

		try {
			const params = new URLSearchParams({
				page: '1',
				page_size: '50',
				base_url: provider.baseUrl
			});

			const groupPath = cpGroup.trim();
			const url = groupPath
				? `/api/providers/gitlab/${encodeURIComponent(groupPath)}/subgroups?${params}`
				: `/api/providers/gitlab/subgroups?${params}`;

			const response = await fetch(url, {
				credentials: 'include'
			});

			if (response.ok) {
				const data: GitLabGroupsResponse = await response.json();
				cpSubgroups = data.groups || [];
			} else {
				cpSubgroups = [];
			}
		} catch {
			cpSubgroups = [];
		}
	};

	const navigateToSubgroup = (group: GroupData) => {
		glGroupPath = [...glGroupPath, glGroup];
		glGroup = group.full_path;
		glPage = 1;
		fetchGitLabProjects(1);
		fetchGitLabSubgroups();
	};

	const navigateBack = (index?: number) => {
		if (index !== undefined) {
			glGroup = glGroupPath[index];
			glGroupPath = glGroupPath.slice(0, index);
		} else if (glGroupPath.length > 0) {
			glGroup = glGroupPath.pop()!;
			glGroupPath = [...glGroupPath];
		}
		glPage = 1;
		fetchGitLabProjects(1);
		fetchGitLabSubgroups();
	};

	const navigateToCustomSubgroup = (provider: CustomProvider, group: GroupData) => {
		cpGroupPath = [...cpGroupPath, cpGroup];
		cpGroup = group.full_path;
		cpPage = 1;
		fetchCustomProjects(provider, 1);
		fetchCustomSubgroups(provider);
	};

	const navigateCustomBack = (provider: CustomProvider, index?: number) => {
		if (index !== undefined) {
			cpGroup = cpGroupPath[index];
			cpGroupPath = cpGroupPath.slice(0, index);
		} else if (cpGroupPath.length > 0) {
			cpGroup = cpGroupPath.pop()!;
			cpGroupPath = [...cpGroupPath];
		}
		cpPage = 1;
		fetchCustomProjects(provider, 1);
		fetchCustomSubgroups(provider);
	};

	const handleGitHubSearch = () => {
		ghPage = 1;
		fetchGitHubRepos(1);
	};

	const handleGitLabSearch = () => {
		glPage = 1;
		glGroupPath = [];
		fetchGitLabProjects(1);
		fetchGitLabSubgroups();
	};

	const handleCustomSearch = (provider: CustomProvider) => {
		cpPage = 1;
		cpGroupPath = [];
		fetchCustomProjects(provider, 1);
		fetchCustomSubgroups(provider);
	};

	const handleGitHubKeydown = (e: KeyboardEvent) => {
		if (e.key === 'Enter') handleGitHubSearch();
	};

	const handleGitLabKeydown = (e: KeyboardEvent) => {
		if (e.key === 'Enter') handleGitLabSearch();
	};

	const handleCustomKeydown = (e: KeyboardEvent, provider: CustomProvider) => {
		if (e.key === 'Enter') handleCustomSearch(provider);
	};

	const formatDate = (dateStr: string) => {
		if (!dateStr) return '';
		const date = new Date(dateStr);
		return date.toLocaleDateString('en-US', {
			year: 'numeric',
			month: 'short',
			day: 'numeric'
		});
	};

	// Navigate to repo details page
	const goToRepoDetails = (provider: string, path: string, baseUrl?: string) => {
		// Save state before navigating
		saveState();
		const params = new URLSearchParams({ provider, path });
		if (baseUrl) params.set('base_url', baseUrl);
		goto(`/app/providers/repo?${params}`);
	};

	const switchToCustomTab = (provider: CustomProvider) => {
		activeTab = provider.id;
		cpGroup = '';
		cpProjects = [];
		cpSubgroups = [];
		cpGroupPath = [];
		cpPage = 1;
		cpError = '';
		fetchCustomProjects(provider, 1);
		fetchCustomSubgroups(provider);
	};

	onMount(() => {
		if (browser) {
			loadCustomProviders();
			// Try to restore state from store (when coming back from repo details)
			const restored = restoreState();
			if (!restored) {
				// No state to restore, fetch initial data
				fetchGitHubRepos(1);
			}
		}
	});
</script>

<svelte:head>
	<title>Providers - SPAM</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Git Providers</h1>
			<p class="text-sm text-[var(--text-tertiary)]">Browse public repositories from GitHub, GitLab, and custom instances.</p>
		</header>

		<!-- Tabs -->
		<div class="flex flex-wrap items-center gap-2 border-b border-[var(--border-color)]">
			<button
				type="button"
				class="px-4 py-2 text-sm font-medium transition {activeTab === 'github'
					? 'border-b-2 border-[var(--accent)] text-[var(--accent)]'
					: 'text-[var(--text-secondary)] hover:text-[var(--text-bright)]'}"
				onclick={() => { activeTab = 'github'; showAddForm = false; if (ghRepos.length === 0) fetchGitHubRepos(1); }}
			>
				GitHub
			</button>
			<button
				type="button"
				class="px-4 py-2 text-sm font-medium transition {activeTab === 'gitlab'
					? 'border-b-2 border-[var(--accent)] text-[var(--accent)]'
					: 'text-[var(--text-secondary)] hover:text-[var(--text-bright)]'}"
				onclick={() => { activeTab = 'gitlab'; showAddForm = false; if (glProjects.length === 0) { fetchGitLabProjects(1); fetchGitLabSubgroups(); } }}
			>
				GitLab
			</button>
			{#each customProviders as provider}
				<div class="relative flex items-center">
					<button
						type="button"
						class="px-4 py-2 text-sm font-medium transition {activeTab === provider.id
							? 'border-b-2 border-[var(--accent)] text-[var(--accent)]'
							: 'text-[var(--text-secondary)] hover:text-[var(--text-bright)]'}"
						onclick={() => { switchToCustomTab(provider); showAddForm = false; }}
					>
						{provider.name}
						<span class="ml-1 text-[10px] text-[var(--text-muted)]">({provider.type})</span>
					</button>
					<button
						type="button"
						class="ml-1 rounded p-1 text-[var(--text-muted)] hover:bg-[var(--hover-bg)] hover:text-[var(--error)]"
						title="Remove provider"
						onclick={() => removeCustomProvider(provider.id)}
					>
						<X class="h-3 w-3" />
					</button>
				</div>
			{/each}
			<button
				type="button"
				class="flex items-center gap-1 px-3 py-2 text-sm font-medium transition {showAddForm
					? 'text-[var(--accent)]'
					: 'text-[var(--text-secondary)] hover:text-[var(--accent)]'}"
				onclick={() => { showAddForm = !showAddForm; activeTab = 'add'; }}
				title="Add custom provider"
			>
				<Plus class="h-4 w-4" />
				<span>Add</span>
			</button>
		</div>

		<!-- GitHub Tab Content -->
		{#if activeTab === 'github' && !showAddForm}
			<div class="space-y-4">
				<div class="flex flex-col gap-4 sm:flex-row sm:items-center">
					<div class="relative flex-1">
						<Search class="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-tertiary)]" />
						<input
							type="text"
							placeholder="Organization or username (e.g., NorskHelsenett)"
							class="w-full rounded-2xl border border-[var(--border-color)] bg-transparent py-3 pl-11 pr-4 text-sm text-[var(--text-secondary)] placeholder-[var(--text-muted)] transition focus:border-[var(--accent)] focus:outline-none"
							bind:value={ghOwner}
							onkeydown={handleGitHubKeydown}
						/>
					</div>
					<button
						type="button"
						class="rounded-2xl border border-[var(--accent)] bg-[var(--accent)]/10 px-6 py-3 text-sm font-medium text-[var(--accent)] transition hover:bg-[var(--accent)]/20 disabled:opacity-50"
						onclick={handleGitHubSearch}
						disabled={ghLoading || !ghOwner.trim()}
					>
						{ghLoading ? 'Loading...' : 'Fetch Repos'}
					</button>
				</div>

				{#if ghError}
					<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">{ghError}</div>
				{/if}

				{#if ghLoading}
					<p class="text-sm text-[var(--text-secondary)]">Loading repositories...</p>
				{:else if ghRepos.length === 0 && !ghError}
					<p class="text-sm text-[var(--text-secondary)]">No repositories found.</p>
				{:else if ghRepos.length > 0}
					<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
						<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
							<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
								<tr>
									<th class="px-5 py-3 text-left">Repository</th>
									<th class="px-5 py-3 text-left">Language</th>
									<th class="px-5 py-3 text-left">Last Updated</th>
									<th class="px-5 py-3 text-center">Status</th>
									<th class="px-5 py-3 text-right"></th>
								</tr>
							</thead>
							<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
								{#each ghRepos as repo}
									<tr
										class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)]"
										ondblclick={() => goToRepoDetails('github', repo.full_path)}
									>
										<td class="px-5 py-3">
											<button
												type="button"
												class="flex items-center gap-2 text-left"
												onclick={() => goToRepoDetails('github', repo.full_path)}
											>
												<GitBranch class="h-4 w-4 text-[var(--accent)]" />
												<span class="font-semibold text-[var(--text-bright)] hover:text-[var(--accent)] hover:underline">{repo.name}</span>
											</button>
											{#if repo.description}
												<p class="mt-0.5 line-clamp-1 text-xs text-[var(--text-muted)]" title={repo.description}>{repo.description}</p>
											{/if}
											{#if repo.topics && repo.topics.length > 0}
												<div class="mt-1 flex flex-wrap gap-1">
													{#each repo.topics.slice(0, 3) as topic}
														<span class="rounded-full bg-[var(--accent)]/10 px-2 py-0.5 text-[10px] text-[var(--accent)]">{topic}</span>
													{/each}
													{#if repo.topics.length > 3}
														<span class="text-[10px] text-[var(--text-muted)]">+{repo.topics.length - 3} more</span>
													{/if}
												</div>
											{/if}
										</td>
										<td class="px-5 py-3">
											{#if repo.language}
												<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs">{repo.language}</span>
											{:else}
												<span class="text-[var(--text-muted)]">—</span>
											{/if}
										</td>
										<td class="px-5 py-3 text-xs">{formatDate(repo.pushed_at || repo.updated_at)}</td>
										<td class="px-5 py-3 text-center">
											<div class="flex items-center justify-center gap-1">
												{#if repo.is_archived}<span title="Archived" class="text-[var(--text-muted)]"><Archive class="h-3.5 w-3.5" /></span>{/if}
												{#if repo.is_fork}<span title="Fork" class="text-[var(--text-muted)]"><GitFork class="h-3.5 w-3.5" /></span>{/if}
												{#if repo.is_private}<span title="Private" class="text-[var(--text-muted)]"><Lock class="h-3.5 w-3.5" /></span>{/if}
												{#if !repo.is_archived && !repo.is_fork && !repo.is_private}<span class="text-[var(--text-muted)]">—</span>{/if}
											</div>
										</td>
										<td class="px-5 py-3 text-right">
											<a href={repo.html_url} target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1 text-xs text-[var(--accent)] hover:underline" onclick={(e) => e.stopPropagation()}>
												View <ExternalLink class="h-3 w-3" />
											</a>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>

					<div class="flex items-center justify-between pt-2">
						<p class="text-xs text-[var(--text-muted)]">Page {ghPage} {ghTotalCount > 0 ? `of ${Math.ceil(ghTotalCount / pageSize)}` : ''}</p>
						<div class="flex gap-2">
							<button type="button" class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50" disabled={ghPage <= 1 || ghLoading} onclick={() => fetchGitHubRepos(ghPage - 1)}>Previous</button>
							<button type="button" class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50" disabled={!ghHasNextPage || ghLoading} onclick={() => fetchGitHubRepos(ghPage + 1)}>Next</button>
						</div>
					</div>
				{/if}
			</div>
		{/if}

		<!-- GitLab Tab Content -->
		{#if activeTab === 'gitlab' && !showAddForm}
			<div class="space-y-4">
				<div class="flex flex-col gap-4 sm:flex-row sm:items-center">
					<div class="relative flex-1">
						<Search class="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-tertiary)]" />
						<input type="text" placeholder="Group path (e.g., gitlab-org)" class="w-full rounded-2xl border border-[var(--border-color)] bg-transparent py-3 pl-11 pr-4 text-sm text-[var(--text-secondary)] placeholder-[var(--text-muted)] transition focus:border-[var(--accent)] focus:outline-none" bind:value={glGroup} onkeydown={handleGitLabKeydown} />
					</div>
					<label class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
						<input type="checkbox" bind:checked={glIncludeSubgroups} class="rounded border-[var(--border-color)]" />
						Include subgroups
					</label>
					<button type="button" class="rounded-2xl border border-[var(--accent)] bg-[var(--accent)]/10 px-6 py-3 text-sm font-medium text-[var(--accent)] transition hover:bg-[var(--accent)]/20 disabled:opacity-50" onclick={handleGitLabSearch} disabled={glLoading || !glGroup.trim()}>
						{glLoading ? 'Loading...' : 'Fetch Projects'}
					</button>
				</div>

				{#if glGroupPath.length > 0}
					<div class="flex items-center gap-1 text-sm text-[var(--text-secondary)]">
						{#each glGroupPath as pathPart, i}
							<button type="button" class="text-[var(--accent)] hover:underline" onclick={() => navigateBack(i)}>{pathPart.split('/').pop()}</button>
							<ChevronRight class="h-4 w-4 text-[var(--text-muted)]" />
						{/each}
						<span class="text-[var(--text-bright)]">{glGroup.split('/').pop()}</span>
					</div>
				{/if}

				{#if glError}
					<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">{glError}</div>
				{/if}

				{#if glSubgroups.length > 0}
					<div class="space-y-2">
						<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Subgroups</h3>
						<div class="flex flex-wrap gap-2">
							{#each glSubgroups as group}
								<button type="button" class="inline-flex items-center gap-2 rounded-xl border border-[var(--border-color)] bg-[var(--card-bg)]/40 px-3 py-2 text-sm text-[var(--text-secondary)] transition hover:border-[var(--accent)] hover:text-[var(--text-bright)]" onclick={() => navigateToSubgroup(group)}>
									<Folder class="h-4 w-4 text-[var(--accent)]" />
									{group.name}
									<ChevronRight class="h-3 w-3 text-[var(--text-muted)]" />
								</button>
							{/each}
						</div>
					</div>
				{/if}

				{#if glLoading}
					<p class="text-sm text-[var(--text-secondary)]">Loading projects...</p>
				{:else if glProjects.length === 0 && !glError}
					<p class="text-sm text-[var(--text-secondary)]">No projects found.</p>
				{:else if glProjects.length > 0}
					<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
						<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
							<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
								<tr>
									<th class="px-5 py-3 text-left">Project</th>
									<th class="px-5 py-3 text-left">Path</th>
									<th class="px-5 py-3 text-left">Last Activity</th>
									<th class="px-5 py-3 text-center">Status</th>
									<th class="px-5 py-3 text-right"></th>
								</tr>
							</thead>
							<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
								{#each glProjects as project}
									<tr
										class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)]"
										ondblclick={() => goToRepoDetails('gitlab', project.full_path)}
									>
										<td class="px-5 py-3">
											<button
												type="button"
												class="flex items-center gap-2 text-left"
												onclick={() => goToRepoDetails('gitlab', project.full_path)}
											>
												<GitBranch class="h-4 w-4 text-[var(--accent)]" />
												<span class="font-semibold text-[var(--text-bright)] hover:text-[var(--accent)] hover:underline">{project.name}</span>
											</button>
											{#if project.description}
												<p class="mt-0.5 line-clamp-1 text-xs text-[var(--text-muted)]" title={project.description}>{project.description}</p>
											{/if}
										</td>
										<td class="px-5 py-3"><span class="text-xs text-[var(--text-muted)]">{project.full_path}</span></td>
										<td class="px-5 py-3 text-xs">{formatDate(project.updated_at)}</td>
										<td class="px-5 py-3 text-center">
											<div class="flex items-center justify-center gap-1">
												{#if project.is_archived}<span title="Archived" class="text-[var(--text-muted)]"><Archive class="h-3.5 w-3.5" /></span>{/if}
												{#if project.is_fork}<span title="Fork" class="text-[var(--text-muted)]"><GitFork class="h-3.5 w-3.5" /></span>{/if}
												{#if project.is_private}<span title="Private" class="text-[var(--text-muted)]"><Lock class="h-3.5 w-3.5" /></span>{/if}
												{#if !project.is_archived && !project.is_fork && !project.is_private}<span class="text-[var(--text-muted)]">—</span>{/if}
											</div>
										</td>
										<td class="px-5 py-3 text-right">
											<a href={project.html_url} target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1 text-xs text-[var(--accent)] hover:underline" onclick={(e) => e.stopPropagation()}>View <ExternalLink class="h-3 w-3" /></a>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>

					<div class="flex items-center justify-between pt-2">
						<p class="text-xs text-[var(--text-muted)]">Page {glPage} {glTotalCount > 0 ? `(${glTotalCount} total)` : ''}</p>
						<div class="flex gap-2">
							<button type="button" class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50" disabled={glPage <= 1 || glLoading} onclick={() => fetchGitLabProjects(glPage - 1)}>Previous</button>
							<button type="button" class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50" disabled={!glHasNextPage || glLoading} onclick={() => fetchGitLabProjects(glPage + 1)}>Next</button>
						</div>
					</div>
				{/if}
			</div>
		{/if}

		<!-- Add Provider Form -->
		{#if showAddForm}
			<div class="flex flex-col items-center justify-center py-16">
				<div class="flex h-20 w-20 items-center justify-center rounded-2xl bg-[var(--accent)]/10 text-[var(--accent)]">
					<Globe class="h-10 w-10" />
				</div>
				<h2 class="mt-6 text-lg font-semibold text-[var(--text-bright)]">Add Custom Instance</h2>
				<p class="mt-2 text-sm text-[var(--text-secondary)]">Enter the URL of a GitLab or Gitea/Forgejo instance</p>

				<div class="mt-6 w-full max-w-md">
					<div class="flex gap-2">
						<input
							type="url"
							placeholder="https://gitlab.example.com"
							class="flex-1 rounded-xl border border-[var(--border-color)] bg-transparent px-4 py-3 text-sm text-[var(--text-secondary)] placeholder-[var(--text-muted)] transition focus:border-[var(--accent)] focus:outline-none"
							bind:value={newProviderUrl}
							onkeydown={handleAddUrlKeydown}
							disabled={detecting}
						/>
						<button
							type="button"
							class="flex items-center gap-2 rounded-xl border border-[var(--accent)] bg-[var(--accent)]/10 px-5 py-3 text-sm font-medium text-[var(--accent)] transition hover:bg-[var(--accent)]/20 disabled:opacity-50"
							onclick={detectAndAddProvider}
							disabled={detecting || !newProviderUrl.trim()}
						>
							{#if detecting}
								<Loader2 class="h-4 w-4 animate-spin" />
								Detecting...
							{:else}
								Add
							{/if}
						</button>
					</div>
					{#if detectError}
						<p class="mt-3 text-sm text-[var(--error)]">{detectError}</p>
					{/if}
					<p class="mt-4 text-center text-xs text-[var(--text-muted)]">
						The provider type (GitLab/Gitea/Forgejo) will be detected automatically.
					</p>
				</div>
			</div>
		{/if}

		<!-- Custom Provider Tab Content -->
		{#if getActiveCustomProvider() && !showAddForm}
			{@const provider = getActiveCustomProvider()!}
			<div class="space-y-4">
				<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-3">
					<p class="text-xs text-[var(--text-muted)]">
						<span class="font-medium text-[var(--text-secondary)]">{provider.type === 'gitlab' ? 'GitLab' : provider.type === 'forgejo' ? 'Forgejo' : 'Gitea'}</span> instance at
						<span class="font-mono text-[var(--accent)]">{provider.baseUrl}</span>
					</p>
				</div>

				<div class="flex flex-col gap-4 sm:flex-row sm:items-center">
					<div class="relative flex-1">
						<Search class="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-tertiary)]" />
						<input type="text" placeholder="Group/organization path" class="w-full rounded-2xl border border-[var(--border-color)] bg-transparent py-3 pl-11 pr-4 text-sm text-[var(--text-secondary)] placeholder-[var(--text-muted)] transition focus:border-[var(--accent)] focus:outline-none" bind:value={cpGroup} onkeydown={(e) => handleCustomKeydown(e, provider)} />
					</div>
					{#if provider.type === 'gitlab'}
						<label class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
							<input type="checkbox" bind:checked={cpIncludeSubgroups} class="rounded border-[var(--border-color)]" />
							Include subgroups
						</label>
					{/if}
					<button type="button" class="rounded-2xl border border-[var(--accent)] bg-[var(--accent)]/10 px-6 py-3 text-sm font-medium text-[var(--accent)] transition hover:bg-[var(--accent)]/20 disabled:opacity-50" onclick={() => handleCustomSearch(provider)} disabled={cpLoading}>
						{cpLoading ? 'Loading...' : cpGroup.trim() ? 'Search' : 'Browse All'}
					</button>
				</div>

				{#if cpGroupPath.length > 0}
					<div class="flex items-center gap-1 text-sm text-[var(--text-secondary)]">
						{#each cpGroupPath as pathPart, i}
							<button type="button" class="text-[var(--accent)] hover:underline" onclick={() => navigateCustomBack(provider, i)}>{pathPart.split('/').pop()}</button>
							<ChevronRight class="h-4 w-4 text-[var(--text-muted)]" />
						{/each}
						<span class="text-[var(--text-bright)]">{cpGroup.split('/').pop()}</span>
					</div>
				{/if}

				{#if cpError}
					<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">{cpError}</div>
				{/if}

				{#if cpSubgroups.length > 0}
					<div class="space-y-2">
						<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Subgroups</h3>
						<div class="flex flex-wrap gap-2">
							{#each cpSubgroups as group}
								<button type="button" class="inline-flex items-center gap-2 rounded-xl border border-[var(--border-color)] bg-[var(--card-bg)]/40 px-3 py-2 text-sm text-[var(--text-secondary)] transition hover:border-[var(--accent)] hover:text-[var(--text-bright)]" onclick={() => navigateToCustomSubgroup(provider, group)}>
									<Folder class="h-4 w-4 text-[var(--accent)]" />
									{group.name}
									<ChevronRight class="h-3 w-3 text-[var(--text-muted)]" />
								</button>
							{/each}
						</div>
					</div>
				{/if}

				{#if cpLoading}
					<p class="text-sm text-[var(--text-secondary)]">Loading projects...</p>
				{:else if cpProjects.length === 0 && !cpError}
					<p class="text-sm text-[var(--text-secondary)]">No public projects found.</p>
				{:else if cpProjects.length > 0}
					<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
						<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
							<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
								<tr>
									<th class="px-5 py-3 text-left">Project</th>
									<th class="px-5 py-3 text-left">Path</th>
									<th class="px-5 py-3 text-left">Last Activity</th>
									<th class="px-5 py-3 text-center">Status</th>
									<th class="px-5 py-3 text-right"></th>
								</tr>
							</thead>
							<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
								{#each cpProjects as project}
									<tr
										class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)]"
										ondblclick={() => goToRepoDetails(provider.type, project.full_path, provider.baseUrl)}
									>
										<td class="px-5 py-3">
											<button
												type="button"
												class="flex items-center gap-2 text-left"
												onclick={() => goToRepoDetails(provider.type, project.full_path, provider.baseUrl)}
											>
												<GitBranch class="h-4 w-4 text-[var(--accent)]" />
												<span class="font-semibold text-[var(--text-bright)] hover:text-[var(--accent)] hover:underline">{project.name}</span>
											</button>
											{#if project.description}
												<p class="mt-0.5 line-clamp-1 text-xs text-[var(--text-muted)]" title={project.description}>{project.description}</p>
											{/if}
										</td>
										<td class="px-5 py-3"><span class="text-xs text-[var(--text-muted)]">{project.full_path}</span></td>
										<td class="px-5 py-3 text-xs">{formatDate(project.updated_at)}</td>
										<td class="px-5 py-3 text-center">
											<div class="flex items-center justify-center gap-1">
												{#if project.is_archived}<span title="Archived" class="text-[var(--text-muted)]"><Archive class="h-3.5 w-3.5" /></span>{/if}
												{#if project.is_fork}<span title="Fork" class="text-[var(--text-muted)]"><GitFork class="h-3.5 w-3.5" /></span>{/if}
												{#if project.is_private}<span title="Private" class="text-[var(--text-muted)]"><Lock class="h-3.5 w-3.5" /></span>{/if}
												{#if !project.is_archived && !project.is_fork && !project.is_private}<span class="text-[var(--text-muted)]">—</span>{/if}
											</div>
										</td>
										<td class="px-5 py-3 text-right">
											<a href={project.html_url} target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1 text-xs text-[var(--accent)] hover:underline" onclick={(e) => e.stopPropagation()}>View <ExternalLink class="h-3 w-3" /></a>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>

					<div class="flex items-center justify-between pt-2">
						<p class="text-xs text-[var(--text-muted)]">Page {cpPage} {cpTotalCount > 0 ? `(${cpTotalCount} total)` : ''}</p>
						<div class="flex gap-2">
							<button type="button" class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50" disabled={cpPage <= 1 || cpLoading} onclick={() => fetchCustomProjects(provider, cpPage - 1)}>Previous</button>
							<button type="button" class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50" disabled={!cpHasNextPage || cpLoading} onclick={() => fetchCustomProjects(provider, cpPage + 1)}>Next</button>
						</div>
					</div>
				{/if}
			</div>
		{/if}
	</section>
</div>

