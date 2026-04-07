<script lang="ts">
	import { onMount, tick } from 'svelte';
	import { browser } from '$app/environment';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { get } from 'svelte/store';
	import { Search, Folder, ChevronRight, Plus, X, Globe, Loader2, RotateCcw } from 'lucide-svelte';
	import QueueStatus from '$lib/components/QueueStatus.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import { providersState } from '$lib/stores/providersState';
	import RepoTable from '$lib/components/RepoTable.svelte';
	import RepoTableRow from '$lib/components/RepoTableRow.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import Toggle from '$lib/components/Toggle.svelte';
	import type {
		RepoData,
		GroupData,
		GitHubResponse,
		GitLabProjectsResponse,
		GitLabGroupsResponse,
		CustomProvider
	} from '$lib/types/providers';

	const USER_STORAGE_KEY = 'spam-custom-providers';

	// Tab state
	let activeTab: string = $state('github');
	let showAddForm = $state(false);

	// Custom providers from localStorage or admin-managed list
	let customProviders: CustomProvider[] = $state([]);
	let managedProvidersEnabled = $state(false);

	// New provider form
	let newProviderUrl = $state('');
	let detecting = $state(false);
	let detectError = $state('');
	let addProviderInput: HTMLInputElement | undefined = $state();

	// GitHub state
	let ghOwner = $state('NorskHelsenett');
	let ghProviderId = $state<string | null>(null);
	let ghRepos: RepoData[] = $state([]);
	let ghLoading = $state(false);
	let ghError = $state('');
	let ghErrorUrl = $state('');
	let ghPage = $state(1);
	let ghHasNextPage = $state(false);
	let ghTotalCount = $state(0);

	// GitLab state
	let glGroup = $state('gitlab-org');
	let glProjects: RepoData[] = $state([]);
	let glSubgroups: GroupData[] = $state([]);
	let glLoading = $state(false);
	let glError = $state('');
	let glErrorUrl = $state('');
	let glPage = $state(1);
	let glHasNextPage = $state(false);
	let glTotalCount = $state(0);
	let glIncludeSubgroups = $state(true);
	let glGroupPath: string[] = $state([]);

	// Custom provider state (for active custom tab)
	let cpGroup = $state('');
	let cpProjects: RepoData[] = $state([]);
	let cpSubgroups: GroupData[] = $state([]);
	let cpLoading = $state(false);
	let cpError = $state('');
	let cpErrorUrl = $state('');
	let cpPage = $state(1);
	let cpHasNextPage = $state(false);
	let cpTotalCount = $state(0);
	let cpIncludeSubgroups = $state(true);
	let cpGroupPath: string[] = $state([]);

	const pageSize = 30;

	// Client-side filter: when off, show only direct projects of the current group
	const filterDirectProjects = (projects: RepoData[], group: string) => {
		if (!group) return projects;
		const prefix = group.endsWith('/') ? group : group + '/';
		return projects.filter(p => {
			const sub = p.full_path.startsWith(prefix) ? p.full_path.slice(prefix.length) : '';
			return sub !== '' && !sub.includes('/');
		});
	};

	const glFilteredProjects = $derived(
		glIncludeSubgroups ? glProjects : filterDirectProjects(glProjects, glGroup)
	);
	const cpFilteredProjects = $derived(
		cpIncludeSubgroups ? cpProjects : filterDirectProjects(cpProjects, cpGroup)
	);

	// Sorting state
	let sortColumn = $state<string>('');
	let sortDirection = $state<'asc' | 'desc'>('asc');

	// Bulk scan state — keyed by tab ID so multiple providers can queue concurrently
	type TabQueueState = { done: boolean; total: number; errors: string[] };
	let queueStates = $state<Record<string, TabQueueState>>({});
	const isQueueing = (tab: string) => tab in queueStates && !queueStates[tab].done;

	// Table column definitions
	const githubColumns = [
		{ key: 'name', label: 'Repository' },
		{ key: 'language', label: 'Language' },
		{ key: 'updated', label: 'Last Updated' },
		{ key: 'status', label: 'Status', align: 'center' as const },
		{ key: 'actions', label: '', align: 'right' as const }
	];

	const gitlabColumns = [
		{ key: 'name', label: 'Project' },
		{ key: 'path', label: 'Path' },
		{ key: 'language', label: 'Language' },
		{ key: 'updated', label: 'Last Activity' },
		{ key: 'status', label: 'Status', align: 'center' as const },
		{ key: 'actions', label: '', align: 'right' as const }
	];

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
	const restoreState = (useManagedProviders: boolean) => {
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
			if (!useManagedProviders && state.customProviders.length > 0) {
				customProviders = state.customProviders;
			}
			return true; // State was restored
		}
		return false; // No valid state to restore
	};

	// Load custom providers from localStorage or admin-managed list
	const loadCustomProviders = async () => {
		if (!browser) return;
		const managed = await loadManagedProviders();
		if (managed.length > 0) {
			customProviders = managed;
			managedProvidersEnabled = true;
			return;
		}

		managedProvidersEnabled = false;
		ghProviderId = null;
		customProviders = [];
		try {
			const stored = localStorage.getItem(USER_STORAGE_KEY);
			if (stored) {
				customProviders = JSON.parse(stored);
			}
		} catch {
			customProviders = [];
		}
	};

	// Save custom providers to localStorage
	const saveCustomProviders = () => {
		if (!browser || managedProvidersEnabled) return;
		localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(customProviders));
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

	const isProviderType = (value: string): value is CustomProvider['type'] => {
		return value === 'github' || value === 'gitlab' || value === 'gitea' || value === 'forgejo';
	};

	type ManagedProvider = {
		id: string;
		name: string;
		type: CustomProvider['type'];
		base_url: string;
		owner_path?: string;
		is_public: boolean;
	};

	const loadManagedProviders = async (): Promise<CustomProvider[]> => {
		if (!browser) return [];
		try {
			const response = await fetch('/api/providers/instances', { credentials: 'include' });
			if (!response.ok) return [];
			const data: ManagedProvider[] = await response.json();
			if (!Array.isArray(data)) return [];
			return data
				.filter((entry) => entry && isProviderType(entry.type))
				.map((entry) => ({
					id: entry.id,
					name: entry.name,
					type: entry.type,
					baseUrl: entry.base_url,
					ownerPath: entry.owner_path || '',
					isPublic: entry.is_public
				}));
		} catch {
			return [];
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
		if (managedProvidersEnabled) return;
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
		const owner = ghOwner.trim();
		if (!owner) return;

		ghLoading = true;
		ghError = '';
		ghErrorUrl = '';

		try {
			const params = new URLSearchParams({
				page: String(page),
				page_size: String(pageSize)
			});
			// Use explicit provider_id, or resolve from managed providers so the
			// request hits the cache instead of the live GitHub API.
			const resolvedProvider = ghProviderId
				? (customProviders.find(p => p.id === ghProviderId) ?? null)
				: (managedProvidersEnabled
					? (customProviders.find(p => p.type === 'github' && (!p.ownerPath || p.ownerPath === owner)) ?? null)
					: null);
			const resolvedProviderId = resolvedProvider?.id ?? null;
			if (resolvedProviderId) {
				params.set('provider_id', resolvedProviderId);
			}
			if (sortColumn) {
				params.set('sort', sortColumn);
				params.set('order', sortDirection);
			}


			const response = await fetch(`/api/providers/github/${encodeURIComponent(owner)}/repos?${params}`, {
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
				if (resolvedProvider?.baseUrl) {
					ghErrorUrl = `${resolvedProvider.baseUrl}/${owner}`;
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
		glLoading = true;
		glError = '';

		try {
			const params = new URLSearchParams({
				page: String(page),
				page_size: String(pageSize),
				include_subgroups: 'true'
			});
			if (glGroup.trim()) params.set('group', glGroup);
			if (sortColumn) {
				params.set('sort', sortColumn);
				params.set('order', sortDirection);
			}

			const response = await fetch(`/api/providers/gitlab/projects?${params}`, {
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
			if (glGroup.trim()) params.set('group', glGroup);

			const response = await fetch(`/api/providers/gitlab/subgroups?${params}`, {
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
		if (provider.type === 'github') {
			cpProjects = [];
			cpLoading = false;
			cpError = '';
			return;
		}
		cpLoading = true;
		cpError = '';

		try {
			const params = new URLSearchParams({
				page: String(page),
				page_size: String(pageSize),
				base_url: provider.baseUrl
			});
			if (managedProvidersEnabled) {
				params.set('provider_id', provider.id);
			}
			if (sortColumn) {
				params.set('sort', sortColumn);
				params.set('order', sortDirection);
			}

			const groupPath = cpGroup.trim();
			let url: string;

			if (provider.type === 'gitlab') {
				params.set('include_subgroups', 'true');
				if (groupPath) params.set('group', groupPath);
				url = `/api/providers/gitlab/projects?${params}`;
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
				cpErrorUrl = provider.baseUrl;
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
			if (managedProvidersEnabled) {
				params.set('provider_id', provider.id);
			}

			const groupPath = cpGroup.trim();
			if (groupPath) params.set('group', groupPath);
			const url = `/api/providers/gitlab/subgroups?${params}`;

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
		glSearchMode = false;
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
		if (provider.type === 'github') return;
		cpGroupPath = [...cpGroupPath, cpGroup];
		cpGroup = group.full_path;
		cpPage = 1;
		fetchCustomProjects(provider, 1);
		fetchCustomSubgroups(provider);
	};

	const navigateCustomBack = (provider: CustomProvider, index?: number) => {
		if (provider.type === 'github') return;
		cpSearchMode = false;
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
		ghProviderId = null;
		ghPage = 1;
		fetchGitHubRepos(1);
	};

	type SearchGroupResult = { full_path: string; name: string; repo_count: number; provider_id: string };
	let glSearchGroups: SearchGroupResult[] = $state([]);
	let cpSearchGroups: SearchGroupResult[] = $state([]);

	const searchReposDB = async (query: string, providerId?: string): Promise<{ projects: RepoData[]; groups: SearchGroupResult[] }> => {
		const params = new URLSearchParams({ q: query, limit: String(pageSize) });
		if (providerId) params.set('provider_id', providerId);
		const res = await fetch(`/api/repos/search?${params}`, { credentials: 'include' });
		if (!res.ok) return { projects: [], groups: [] };
		const data = await res.json();
		const projects = (data.results || []).map((r: any) => ({
			name: r.slug,
			full_path: r.org + '/' + r.slug,
			description: '',
			html_url: '',
			default_branch: '',
			languages: [],
			is_private: false,
			is_archived: false,
			is_disabled: false,
			is_fork: false,
			topics: [],
			created_at: '',
			updated_at: '',
			pushed_at: ''
		}));
		return { projects, groups: data.groups || [] };
	};

	const handleGitLabSearch = async () => {
		if (!glGroup.trim()) {
			glSearchGroups = [];
			glGroupPath = [];
			fetchGitLabProjects(1);
			fetchGitLabSubgroups();
			return;
		}
		glLoading = true;
		glError = '';
		glPage = 1;
		glGroupPath = [];
		glSubgroups = [];
		try {
			const result = await searchReposDB(glGroup);
			glProjects = result.projects;
			glSearchGroups = result.groups;
			glHasNextPage = false;
			glTotalCount = glProjects.length;
		} catch {
			glError = 'Search failed.';
			glProjects = [];
			glSearchGroups = [];
		} finally {
			glLoading = false;
		}
	};

	const handleCustomSearch = async (provider: CustomProvider) => {
		if (provider.type === 'github') {
			ghProviderId = managedProvidersEnabled ? provider.id : null;
			ghPage = 1;
			ghOwner = provider.ownerPath || ghOwner;
			fetchGitHubRepos(1);
			return;
		}
		if (!cpGroup.trim()) {
			cpSearchGroups = [];
			cpGroupPath = [];
			fetchCustomProjects(provider, 1);
			fetchCustomSubgroups(provider);
			return;
		}
		cpLoading = true;
		cpError = '';
		cpPage = 1;
		cpGroupPath = [];
		cpSubgroups = [];
		try {
			const result = await searchReposDB(cpGroup, managedProvidersEnabled ? provider.id : undefined);
			cpProjects = result.projects;
			cpSearchGroups = result.groups;
			cpHasNextPage = false;
			cpTotalCount = cpProjects.length;
		} catch {
			cpError = 'Search failed.';
			cpProjects = [];
			cpSearchGroups = [];
		} finally {
			cpLoading = false;
		}
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

	// Handle column sorting
	const handleSort = (column: string) => {
		if (sortColumn === column) {
			sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
		} else {
			sortColumn = column;
			sortDirection = 'asc';
		}
		// Reset to page 1 and reload data with new sort
		if (activeTab === 'github' && ghRepos.length > 0) {
			ghPage = 1;
			fetchGitHubRepos(1);
		} else if (activeTab === 'gitlab' && glProjects.length > 0) {
			glPage = 1;
			fetchGitLabProjects(1);
		} else if (getActiveCustomProvider()) {
			const provider = getActiveCustomProvider();
			if (provider?.type === 'github' && ghRepos.length > 0) {
				ghPage = 1;
				fetchGitHubRepos(1);
			} else if (provider && cpProjects.length > 0) {
				cpPage = 1;
				fetchCustomProjects(provider, 1);
			}
		}
	};

	// Navigate to repo details page
	const goToRepoDetails = (provider: string, path: string, baseUrl?: string, providerId?: string) => {
		// Save state before navigating
		saveState();
		const params = new URLSearchParams({ provider, path });
		if (baseUrl) params.set('base_url', baseUrl);
		if (providerId) params.set('provider_id', providerId);
		goto(`/app/providers/repo?${params}`);
	};

	// Trigger SBOM scan for all repos (including paginated results).
	// Streams progress via SSE — the server emits "progress" events per page and a final "done" event.
	// Queue All dialog state
	let queueDialogOpen = $state(false);
	let queueDialogContext = $state<{
		provider: string;
		owner: string;
		group: string;
		baseUrl?: string;
		includeSubgroups: boolean;
		providerId?: string;
	} | null>(null);

	const openQueueDialog = (
		provider: string,
		owner: string,
		group: string,
		baseUrl?: string,
		includeSubgroups: boolean = false,
		providerId?: string
	) => {
		queueDialogContext = { provider, owner, group, baseUrl, includeSubgroups, providerId };
		queueDialogOpen = true;
	};

	const closeQueueDialog = () => {
		queueDialogOpen = false;
		queueDialogContext = null;
	};

	const queueAllRepos = async (
		provider: string,
		owner: string,
		group: string,
		baseUrl?: string,
		includeSubgroups: boolean = false,
		providerId?: string,
		onlyNew: boolean = false
	) => {
		closeQueueDialog();
		const tabId = activeTab;
		if (isQueueing(tabId)) return;

		queueStates[tabId] = { done: false, total: 0, errors: [] };
		await tick(); // flush DOM so spinner renders before the fetch starts

		try {
			const response = await fetch('/api/scan-all', {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					provider,
					owner: owner || undefined,
					group: group || undefined,
					base_url: baseUrl || undefined,
					include_subgroups: includeSubgroups,
					provider_id: providerId || undefined,
					only_new: onlyNew || undefined
				})
			});

			if (!response.ok) {
				const text = await response.text();
				queueStates[tabId] = { ...queueStates[tabId], errors: [text || 'Failed to queue repos'] };
			} else if (response.body) {
				// Read the SSE stream line by line.
				const reader = response.body.getReader();
				const decoder = new TextDecoder();
				let buffer = '';

				while (true) {
					const { done, value } = await reader.read();
					if (done) break;

					buffer += decoder.decode(value, { stream: true });
					const parts = buffer.split('\n\n');
					buffer = parts.pop() ?? '';

					for (const part of parts) {
						let eventType = '';
						let dataStr = '';
						for (const line of part.trim().split('\n')) {
							if (line.startsWith('event: ')) eventType = line.slice(7).trim();
							else if (line.startsWith('data: ')) dataStr = line.slice(6).trim();
						}
						if (!dataStr) continue;
						try {
							const data = JSON.parse(dataStr);
							if (eventType === 'progress') {
								queueStates[tabId] = { ...queueStates[tabId], total: data.queued };
							} else if (eventType === 'done') {
								queueStates[tabId] = { ...queueStates[tabId], total: data.total_queued, errors: data.errors || [] };
							}
						} catch {
							// ignore malformed events
						}
					}
				}
			}
		} catch (err) {
			queueStates[tabId] = { ...queueStates[tabId], errors: [err instanceof Error ? err.message : 'Failed to queue repos'] };
		}

		queueStates[tabId] = { ...queueStates[tabId], done: true };

		// Auto-dismiss after 10 seconds if no errors
		if (queueStates[tabId].errors.length === 0) {
			setTimeout(() => {
				delete queueStates[tabId];
			}, 10000);
		}
	};

	const switchToCustomTab = (provider: CustomProvider) => {
		activeTab = provider.id;
		sortColumn = '';
		sortDirection = 'asc';
		if (provider.type === 'github') {
			ghProviderId = managedProvidersEnabled ? provider.id : null;
			ghOwner = provider.ownerPath || ghOwner;
			ghRepos = [];
			ghPage = 1;
			ghHasNextPage = false;
			ghTotalCount = 0;
			ghError = '';
			if (ghOwner.trim()) {
				fetchGitHubRepos(1);
			}
			return;
		}

		ghProviderId = null;
		cpGroup = provider.ownerPath || '';
		cpProjects = [];
		cpSubgroups = [];
		cpGroupPath = [];
		cpPage = 1;
		cpError = '';
		fetchCustomProjects(provider, 1);
		fetchCustomSubgroups(provider);
	};

	onMount(() => {
		if (!browser) return;
		const init = async () => {
			await loadCustomProviders();

			// Check for ?tab= query param (e.g. linked from run detail page)
			const tabParam = $page.url.searchParams.get('tab');
			if (tabParam) {
				// Try matching a custom/managed provider by ID
				const targetProvider = customProviders.find((p) => p.id === tabParam);
				if (targetProvider) {
					switchToCustomTab(targetProvider);
					return;
				}
				// Try matching a built-in tab
				if (tabParam === 'github' || tabParam === 'gitlab') {
					activeTab = tabParam;
					if (tabParam === 'github') fetchGitHubRepos(1);
					else { fetchGitLabProjects(1); fetchGitLabSubgroups(); }
					return;
				}
			}

			// Try to restore state from store (when coming back from repo details)
			const restored = restoreState(managedProvidersEnabled);
			if (managedProvidersEnabled) {
				const activeProvider = customProviders.find((provider) => provider.id === activeTab);
				if (activeProvider?.type === 'github') {
					ghProviderId = activeProvider.id;
					ghOwner = activeProvider.ownerPath || ghOwner;
				} else {
					ghProviderId = null;
				}
				const activeExists = Boolean(activeProvider);
				if (!activeExists && customProviders.length > 0) {
					switchToCustomTab(customProviders[0]);
				} else if (!restored && customProviders.length > 0) {
					switchToCustomTab(customProviders[0]);
				}
				return;
			}

			if (!restored) {
				// No state to restore, fetch initial data
				fetchGitHubRepos(1);
			}
		};
		init();
	});
</script>

<svelte:head>
	<title>Providers - SPAM</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Git Providers</h1>
			<p class="text-sm text-[var(--text-tertiary)]">Browse repositories from GitHub, GitLab, and custom instances.</p>
		</header>

		<!-- Tabs -->
		<div class="flex flex-wrap items-center gap-2 border-b border-[var(--border-color)]">
			{#if !managedProvidersEnabled}
			<button
				type="button"
				class="px-4 py-2 text-sm font-medium transition {activeTab === 'github'
					? 'border-b-2 border-[var(--accent)] text-[var(--accent)]'
					: 'text-[var(--text-secondary)] hover:text-[var(--text-bright)]'}"
				onclick={() => { activeTab = 'github'; showAddForm = false; sortColumn = ''; sortDirection = 'asc'; ghProviderId = null; if (ghRepos.length === 0) fetchGitHubRepos(1); }}
			>
				GitHub
			</button>
			<button
				type="button"
				class="px-4 py-2 text-sm font-medium transition {activeTab === 'gitlab'
					? 'border-b-2 border-[var(--accent)] text-[var(--accent)]'
					: 'text-[var(--text-secondary)] hover:text-[var(--text-bright)]'}"
				onclick={() => { activeTab = 'gitlab'; showAddForm = false; sortColumn = ''; sortDirection = 'asc'; if (glProjects.length === 0) { fetchGitLabProjects(1); fetchGitLabSubgroups(); } }}
			>
				GitLab
			</button>
			{/if}
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
					{#if !managedProvidersEnabled}
					<button
						type="button"
						class="ml-1 rounded p-1 text-[var(--text-muted)] hover:bg-[var(--hover-bg)] hover:text-[var(--error)]"
						title="Remove provider"
						onclick={() => removeCustomProvider(provider.id)}
					>
						<X class="h-3 w-3" />
					</button>
					{/if}
				</div>
			{/each}
			{#if !managedProvidersEnabled}
				<button
					type="button"
					class="flex items-center gap-1 px-3 py-2 text-sm font-medium transition {showAddForm
						? 'text-[var(--accent)]'
						: 'text-[var(--text-secondary)] hover:text-[var(--accent)]'}"
					onclick={() => { 
						showAddForm = !showAddForm; 
						activeTab = 'add'; 
						if (showAddForm) {
							setTimeout(() => addProviderInput?.focus(), 0);
						}
					}}
					title="Add custom provider"
				>
					<Plus class="h-4 w-4" />
					<span>Add</span>
				</button>
			{/if}
		</div>

		<!-- GitHub Tab Content -->
		{#if !managedProvidersEnabled && activeTab === 'github' && !showAddForm}
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
						class="btn btn-outline"
						onclick={handleGitHubSearch}
						disabled={ghLoading || !ghOwner.trim()}
					>
						{ghLoading ? 'Loading...' : 'Fetch Repos'}
					</button>
					<button
						type="button"
						class="btn btn-primary"
						onclick={() => openQueueDialog('github', ghOwner, '', undefined, false)}
						disabled={isQueueing('github') || !ghOwner.trim()}
						title="Queue SBOM generation for all repositories from {ghOwner}"
					>
						{isQueueing('github') ? 'Queueing...' : 'Queue All'}
					</button>
				</div>

				{#if 'github' in queueStates}
					<QueueStatus state={queueStates['github']} singular="repository" plural="repositories" />
				{/if}

				{#if ghError}
					<div class="flex items-center justify-between rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">
						<span>{ghError}</span>
						{#if ghErrorUrl}
							<a href="{ghErrorUrl}" target="_blank" rel="noopener noreferrer" class="ml-4 shrink-0 text-[var(--accent)] hover:underline">Open provider →</a>
						{/if}
					</div>
				{/if}

				{#if ghRepos.length === 0 && !ghLoading && !ghError}
					<p class="text-sm text-[var(--text-secondary)]">No repositories found.</p>
				{:else if ghRepos.length > 0}
					<RepoTable columns={githubColumns} {sortColumn} {sortDirection} onSort={handleSort}>
						{#each ghRepos as repo}
							<RepoTableRow
								{repo}
								{formatDate}
								onSelect={() => goToRepoDetails('github', repo.full_path)}
							/>
						{/each}
					</RepoTable>

					<Pagination
						page={ghPage}
						totalCount={ghTotalCount}
						{pageSize}
						hasNextPage={ghHasNextPage}
						loading={ghLoading}
						onPrevious={() => fetchGitHubRepos(ghPage - 1)}
						onNext={() => fetchGitHubRepos(ghPage + 1)}
					/>
				{/if}
			</div>
		{/if}

		<!-- GitLab Tab Content -->
		{#if !managedProvidersEnabled && activeTab === 'gitlab' && !showAddForm}
			<div class="space-y-4">
				<div class="flex flex-col gap-4 sm:flex-row sm:items-center">
					<div class="relative flex-1">
						<Search class="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-tertiary)]" />
						<input type="text" placeholder="Search groups and projects..." class="w-full rounded-2xl border border-[var(--border-color)] bg-transparent py-3 pl-11 pr-10 text-sm text-[var(--text-secondary)] placeholder-[var(--text-muted)] transition focus:border-[var(--accent)] focus:outline-none" bind:value={glGroup} onkeydown={handleGitLabKeydown} />
						{#if glGroup}
							<button type="button" class="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)] transition hover:text-[var(--text-primary)]" onclick={() => { glGroup = ''; glSearchGroups = []; glGroupPath = []; fetchGitLabProjects(1); fetchGitLabSubgroups(); }}>
								<X class="h-4 w-4" />
							</button>
						{/if}
					</div>
					<button type="button" class="btn btn-outline" onclick={handleGitLabSearch} disabled={glLoading}>
						{glLoading ? 'Loading...' : glGroup.trim() ? 'Search' : 'Browse All'}
					</button>
					<button
						type="button"
						class="btn btn-primary"
						onclick={() => openQueueDialog('gitlab', '', glGroup, undefined, glIncludeSubgroups)}
						disabled={isQueueing('gitlab')}
						title="Queue SBOM generation for all projects from {glGroup}"
					>
						{isQueueing('gitlab') ? 'Queueing...' : 'Queue All'}
					</button>
				</div>

				{#if 'gitlab' in queueStates}
					<QueueStatus state={queueStates['gitlab']} singular="project" plural="projects" />
				{/if}

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
					<div class="flex items-center justify-between rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">
						<span>{glError}</span>
						{#if glErrorUrl}
							<a href="{glErrorUrl}" target="_blank" rel="noopener noreferrer" class="ml-4 shrink-0 text-[var(--accent)] hover:underline">Open provider →</a>
						{/if}
					</div>
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

				{#if glSearchGroups.length > 0}
					<div class="space-y-2">
						<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Groups</h3>
						<div class="flex flex-wrap gap-2">
							{#each glSearchGroups as group}
								<button type="button" class="inline-flex items-center gap-2 rounded-xl border border-[var(--border-color)] bg-[var(--card-bg)]/40 px-3 py-2 text-sm text-[var(--text-secondary)] transition hover:border-[var(--accent)] hover:text-[var(--text-bright)]" onclick={() => { glGroup = group.full_path; glSearchGroups = []; glGroupPath = []; fetchGitLabProjects(1); fetchGitLabSubgroups(); }}>
									<Folder class="h-4 w-4 text-[var(--accent)]" />
									{group.full_path}
									<span class="text-xs text-[var(--text-muted)]">({group.repo_count})</span>
									<ChevronRight class="h-3 w-3 text-[var(--text-muted)]" />
								</button>
							{/each}
						</div>
					</div>
				{/if}

				{#if glProjects.length > 0}
					<div class="flex items-center gap-3">
						<Toggle bind:checked={glIncludeSubgroups} label="Include subgroup projects" />
						<span class="shrink-0 text-xs text-[var(--text-muted)]">{glFilteredProjects.length} of {glProjects.length}</span>
					</div>
				{/if}
				{#if glFilteredProjects.length === 0 && !glLoading && !glError}
					<p class="text-sm text-[var(--text-secondary)]">No projects found.</p>
				{:else if glFilteredProjects.length > 0}
					<RepoTable columns={gitlabColumns} {sortColumn} {sortDirection} onSort={handleSort}>
						{#each glFilteredProjects as project}
							<RepoTableRow
								repo={project}
								showPath
								{formatDate}
								onSelect={() => goToRepoDetails('gitlab', project.full_path)}
							/>
						{/each}
					</RepoTable>

					<Pagination
						page={glPage}
						totalCount={glTotalCount}
						{pageSize}
						hasNextPage={glHasNextPage}
						loading={glLoading}
						onPrevious={() => fetchGitLabProjects(glPage - 1)}
						onNext={() => fetchGitLabProjects(glPage + 1)}
					/>
				{/if}
			</div>
		{/if}

		<!-- Add Provider Form -->
		{#if !managedProvidersEnabled && showAddForm}
			<div class="flex flex-col items-center justify-center py-16">
				<div class="flex h-20 w-20 items-center justify-center rounded-2xl bg-[var(--accent)]/10 text-[var(--accent)]">
					<Globe class="h-10 w-10" />
				</div>
				<h2 class="mt-6 text-lg font-semibold text-[var(--text-bright)]">Add Custom Instance</h2>
				<p class="mt-2 text-sm text-[var(--text-secondary)]">Enter the URL of a GitLab or Gitea/Forgejo instance</p>

				<div class="mt-6 w-full max-w-md">
					<div class="flex gap-2">
						<input						bind:this={addProviderInput}							type="url"
							placeholder="https://gitlab.example.com"
							class="flex-1 rounded-xl border border-[var(--border-color)] bg-transparent px-4 py-3 text-sm text-[var(--text-secondary)] placeholder-[var(--text-muted)] transition focus:border-[var(--accent)] focus:outline-none"
							bind:value={newProviderUrl}
							onkeydown={handleAddUrlKeydown}
							disabled={detecting}
						/>
						<button
							type="button"
							class="btn btn-outline"
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
				{#if provider.type === 'github'}
					<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-3">
						<p class="text-xs text-[var(--text-muted)]">
							<span class="font-medium text-[var(--text-secondary)]">GitHub</span> org at
							<span class="font-mono text-[var(--accent)]">{provider.baseUrl}</span>
						</p>
					</div>

					<div class="flex flex-col gap-4 sm:flex-row sm:items-center">
						<div class="flex-1 rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 text-sm text-[var(--text-secondary)]">
							<span class="text-[var(--text-tertiary)]">Owner:</span>
							<span class="ml-2 font-medium text-[var(--text-bright)]">{provider.ownerPath || 'Unknown'}</span>
						</div>
						<button
							type="button"
							class="btn btn-outline"
							onclick={() => handleCustomSearch(provider)}
							disabled={ghLoading || !provider.ownerPath}
						>
							{ghLoading ? 'Loading...' : 'Refresh'}
						</button>
						<button
							type="button"
							class="btn btn-primary"
							onclick={() => openQueueDialog('github', provider.ownerPath || '', '', undefined, false, managedProvidersEnabled ? provider.id : undefined)}
						disabled={isQueueing(provider.id) || !provider.ownerPath}
							title="Queue SBOM generation for all projects from {provider.name}"
						>
						{isQueueing(provider.id) ? 'Queueing...' : 'Queue All'}
						</button>
					</div>

					{#if provider.id in queueStates}
						<QueueStatus state={queueStates[provider.id]} singular="repo" plural="repos" />
					{/if}

					{#if !provider.ownerPath}
						<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">
							GitHub providers must include an org or user path.
						</div>
					{:else if ghError}
						<div class="flex items-center justify-between rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">
							<span>{ghError}</span>
							{#if ghErrorUrl}
								<a href="{ghErrorUrl}" target="_blank" rel="noopener noreferrer" class="ml-4 shrink-0 text-[var(--accent)] hover:underline">Open provider →</a>
							{/if}
						</div>
					{:else if ghRepos.length === 0 && !ghLoading}
						<p class="text-sm text-[var(--text-secondary)]">No repositories found.</p>
					{:else if ghRepos.length > 0}
						<RepoTable columns={githubColumns} {sortColumn} {sortDirection} onSort={handleSort}>
							{#each ghRepos as repo}
								<RepoTableRow repo={repo} {formatDate} onSelect={() => goToRepoDetails('github', repo.full_path, undefined, managedProvidersEnabled ? provider.id : undefined)} />
							{/each}
						</RepoTable>

						<Pagination
							page={ghPage}
							totalCount={ghTotalCount}
							{pageSize}
							hasNextPage={ghHasNextPage}
							loading={ghLoading}
							onPrevious={() => fetchGitHubRepos(ghPage - 1)}
							onNext={() => fetchGitHubRepos(ghPage + 1)}
						/>
					{/if}
				{:else}
				<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-3">
					<p class="text-xs text-[var(--text-muted)]">
						<span class="font-medium text-[var(--text-secondary)]">{provider.type === 'gitlab' ? 'GitLab' : provider.type === 'forgejo' ? 'Forgejo' : 'Gitea'}</span> instance at
						<span class="font-mono text-[var(--accent)]">{provider.baseUrl}</span>
					</p>
				</div>

				<div class="flex flex-col gap-4 sm:flex-row sm:items-center">
					<div class="relative flex-1">
						<Search class="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-tertiary)]" />
						<input type="text" placeholder="Search groups and projects..." class="w-full rounded-2xl border border-[var(--border-color)] bg-transparent py-3 pl-11 pr-10 text-sm text-[var(--text-secondary)] placeholder-[var(--text-muted)] transition focus:border-[var(--accent)] focus:outline-none" bind:value={cpGroup} onkeydown={(e) => handleCustomKeydown(e, provider)} />
						{#if cpGroup}
							<button type="button" class="absolute right-3 top-1/2 -translate-y-1/2 text-[var(--text-muted)] transition hover:text-[var(--text-primary)]" onclick={() => { cpGroup = ''; cpSearchGroups = []; cpGroupPath = []; fetchCustomProjects(provider, 1); fetchCustomSubgroups(provider); }}>
								<X class="h-4 w-4" />
							</button>
						{/if}
					</div>
					<button type="button" class="btn btn-outline" onclick={() => handleCustomSearch(provider)} disabled={cpLoading}>
						{cpLoading ? 'Loading...' : cpGroup.trim() ? 'Search' : 'Browse All'}
					</button>
					<button
						type="button"
						class="btn btn-primary"
						onclick={() => openQueueDialog(provider.type, cpGroup, cpGroup, provider.baseUrl, cpIncludeSubgroups, managedProvidersEnabled ? provider.id : undefined)}
						disabled={isQueueing(provider.id)}
						title="Queue SBOM generation for all projects from {provider.name}"
					>
						{isQueueing(provider.id) ? 'Queueing...' : 'Queue All'}
					</button>
				</div>

				{#if provider.id in queueStates}
					<QueueStatus state={queueStates[provider.id]} singular="project" plural="projects" />
				{/if}

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
					<div class="flex items-center justify-between rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">
						<span>{cpError}</span>
						{#if cpErrorUrl}
							<a href="{cpErrorUrl}" target="_blank" rel="noopener noreferrer" class="ml-4 shrink-0 text-[var(--accent)] hover:underline">Open {provider.name} →</a>
						{/if}
					</div>
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

				{#if cpSearchGroups.length > 0}
					<div class="space-y-2">
						<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Groups</h3>
						<div class="flex flex-wrap gap-2">
							{#each cpSearchGroups as group}
								<button type="button" class="inline-flex items-center gap-2 rounded-xl border border-[var(--border-color)] bg-[var(--card-bg)]/40 px-3 py-2 text-sm text-[var(--text-secondary)] transition hover:border-[var(--accent)] hover:text-[var(--text-bright)]" onclick={() => { cpGroup = group.full_path; cpSearchGroups = []; cpGroupPath = []; fetchCustomProjects(provider, 1); fetchCustomSubgroups(provider); }}>
									<Folder class="h-4 w-4 text-[var(--accent)]" />
									{group.full_path}
									<span class="text-xs text-[var(--text-muted)]">({group.repo_count})</span>
									<ChevronRight class="h-3 w-3 text-[var(--text-muted)]" />
								</button>
							{/each}
						</div>
					</div>
				{/if}

				{#if provider.type === 'gitlab' && cpProjects.length > 0}
					<div class="flex items-center gap-3">
						<Toggle bind:checked={cpIncludeSubgroups} label="Include subgroup projects" />
						<span class="shrink-0 text-xs text-[var(--text-muted)]">{cpFilteredProjects.length} of {cpProjects.length}</span>
					</div>
				{/if}
				{#if cpFilteredProjects.length === 0 && !cpLoading && !cpError}
					<p class="text-sm text-[var(--text-secondary)]">No projects found.</p>
				{:else if cpFilteredProjects.length > 0}
					<RepoTable columns={gitlabColumns} {sortColumn} {sortDirection} onSort={handleSort}>
						{#each cpFilteredProjects as project}
							<RepoTableRow
								repo={project}
								showPath
								{formatDate}
								onSelect={() => goToRepoDetails(provider.type, project.full_path, provider.baseUrl, managedProvidersEnabled ? provider.id : undefined)}
							/>
						{/each}
					</RepoTable>

					<Pagination
						page={cpPage}
						totalCount={cpTotalCount}
						{pageSize}
						hasNextPage={cpHasNextPage}
						loading={cpLoading}
						onPrevious={() => fetchCustomProjects(provider, cpPage - 1)}
						onNext={() => fetchCustomProjects(provider, cpPage + 1)}
					/>
				{/if}
				{/if}
			</div>
		{/if}
	</section>
</div>

<!-- Queue All dialog -->
{#if queueDialogContext}
	{@const ctx = queueDialogContext}
	<ConfirmDialog
		bind:open={queueDialogOpen}
		title="Queue Scans"
		description="Choose how to queue scans for all repositories."
		iconVariant="default"
		buttons={[
			{ label: 'Cancel', variant: 'ghost', onclick: closeQueueDialog },
			{ label: 'Only New', variant: 'ghost', onclick: () => queueAllRepos(ctx.provider, ctx.owner, ctx.group, ctx.baseUrl, ctx.includeSubgroups, ctx.providerId, true) },
			{ label: 'Queue All', variant: 'primary', onclick: () => queueAllRepos(ctx.provider, ctx.owner, ctx.group, ctx.baseUrl, ctx.includeSubgroups, ctx.providerId, false) }
		]}
	>
		{#snippet icon()}<RotateCcw size={26} />{/snippet}
	</ConfirmDialog>
{/if}
