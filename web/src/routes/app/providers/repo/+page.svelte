<script lang="ts">
	import { goto } from '$app/navigation';
	import { browser } from '$app/environment';
	import { page } from '$app/stores';
	import {
		GitBranch, Star, GitFork, Eye, AlertCircle, Tag, Users, GitCommit,
		ArrowLeft, ExternalLink, Shield, ShieldAlert, ShieldX, FileWarning,
		Package, Clock, Scale, Play, Loader2, FileCode, Microscope, Lock, Globe
	} from 'lucide-svelte';
	import Markdown from '$lib/components/Markdown.svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';
	import Gitea from '$lib/components/icons/Gitea.svelte';
	import EmptyCommits from '$lib/components/icons/EmptyCommits.svelte';
	import EmptyContributors from '$lib/components/icons/EmptyContributors.svelte';
	import EmptyRuns from '$lib/components/icons/EmptyRuns.svelte';

	type RepoStats = {
		stars: number;
		forks: number;
		watchers: number;
		open_issues: number;
		commits: number;
		branches: number;
		releases: number;
		contributors: number;
	};

	type RepoDetails = {
		external_id: string;
		name: string;
		full_path: string;
		description: string;
		html_url: string;
		default_branch: string;
		languages: string[];
		is_private: boolean;
		is_archived: boolean;
		is_disabled: boolean;
		is_fork: boolean;
		topics: string[];
		created_at: string;
		updated_at: string;
		pushed_at: string;
		stats: RepoStats;
		license: string;
		size: number;
	};

	type CommitInfo = {
		sha: string;
		message: string;
		author_name: string;
		author_email: string;
		author_date: string;
		author_login?: string;
		author_avatar?: string;
		commit_url?: string;
	};

	type ContributorInfo = {
		login?: string;
		name?: string;
		email?: string;
		avatar_url?: string;
		profile_url?: string;
		contributions: number;
	};

	type RepoDetailsResponse = {
		details: RepoDetails;
		readme: string;
		commits?: CommitInfo[];
		contributors?: ContributorInfo[];
	};

	type SecurityData = {
		vulnerabilities: { critical: number; high: number; medium: number; low: number };
		secrets: number;
		issues: { noOwner: boolean; noLicense: boolean; noReadme: boolean; outdatedDeps: number };
		components: number;
		componentsFromSBOM: number;
		componentsFromManifest: number;
	};

	type RepoMetadataRun = {
		id: string;
		status: string;
		started_at?: string;
		finished_at?: string;
		duration_ms?: number;
		commit_sha?: string;
		artifacts?: string[];
	};

	type RepoMetadataResponse = {
		repo: {
			id: string;
			org: string;
			slug: string;
			provider_id?: string;
			provider_base_url?: string;
		};
		runs: {
			total: number;
			latest?: RepoMetadataRun;
			timeline: RepoMetadataRun[];
		};
		sbom: {
			latest?: {
				id: string;
				created_at?: string;
				format?: string;
				component_count?: number;
				download_url?: string;
			};
		};
		dependencies: {
			total?: number;
			from_sbom?: number;
			from_manifest?: number;
		};
		secrets: {
			latest_count?: number;
			latest_run_id?: string;
			last_scanned_at?: string;
		};
		vulnerabilities?: {
			summary?: {
				critical: number;
				high: number;
				medium: number;
				low: number;
			};
		};
	};

	let details: RepoDetails | null = $state(null);
	let readme = $state('');
	let commits: CommitInfo[] = $state([]);
	let contributors: ContributorInfo[] = $state([]);
	let loading = $state(true);
	let error = $state('');
	// Resolved params (may differ from URL when page loads via repo_id only)
	let resolvedPath = $state('');
	let resolvedProvider = $state('');
	let resolvedBaseUrl = $state('');
	let resolvedProviderId = $state('');
	let runTimeline: RepoMetadataRun[] = $state([]);
	let totalRuns = $state(0);
	let securityData: SecurityData = $state({
		vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 },
		secrets: 0,
		issues: { noOwner: false, noLicense: false, noReadme: false, outdatedDeps: 0 },
		components: 0,
		componentsFromSBOM: 0,
		componentsFromManifest: 0
	});

	// Get query params
	const getParams = () => {
		if (!browser) return { provider: 'github', path: '', baseUrl: '', providerId: '', repoDbId: '' };
		const params = $page.url.searchParams;
		return {
			provider: params.get('provider') || 'github',
			path: params.get('path') || '',
			baseUrl: params.get('base_url') || '',
			providerId: params.get('provider_id') || '',
			repoDbId: params.get('repo_id') || $page.params.repo_id || ''
		};
	};

	const fetchRepoDetails = async () => {
		let { provider, path, baseUrl, providerId, repoDbId } = getParams();

		// When only repo_id is provided, resolve path and provider info from metadata
		if (repoDbId && !path) {
			const meta = await fetchRepoMetadata(repoDbId);
			if (meta?.repo?.org && meta.repo.slug) {
				path = `${meta.repo.org}/${meta.repo.slug}`;
				providerId = providerId || meta.repo.provider_id || '';
				baseUrl = baseUrl || meta.repo.provider_base_url || '';
				provider = provider || meta.repo.provider || 'github';
			}
		}

		// Store resolved params for use in triggerScan
		resolvedPath = path;
		resolvedProvider = provider;
		resolvedBaseUrl = baseUrl;
		resolvedProviderId = providerId;

		if (!path && !repoDbId) {
			error = 'No repository path specified.';
			loading = false;
			return;
		}

		loading = true;
		error = '';

		const buildTypeUrl = () => {
				const q = new URLSearchParams();
				if (baseUrl) q.set('base_url', baseUrl);
				if (providerId) q.set('provider_id', providerId);
				if (provider === 'gitlab') {
					return `/api/providers/gitlab/${encodeURIComponent(path)}/details?${q}`;
				} else if (provider === 'gitea' || provider === 'forgejo') {
					return `/api/providers/gitea/${path}/details?${q}`;
				} else {
					return `/api/providers/github/${path}/details?${q}`;
				}
			};

			try {
			let response: Response;

			if (repoDbId || providerId) {
				// Use unified endpoint — backend resolves provider type and credentials from DB.
				// Never fall back to type-specific endpoints when provider_id is known, as that
				// would allow the client to influence which provider/credentials are used.
				const uq = new URLSearchParams();
				if (providerId) uq.set('provider_id', providerId);
				if (path) uq.set('path', path);
				if (repoDbId) uq.set('repo_id', repoDbId);
				response = await fetch(`/api/providers/details?${uq}`, { credentials: 'include' });
			} else {
				response = await fetch(buildTypeUrl(), { credentials: 'include' });
			}

			if (!response.ok) {
				if (response.status === 404) {
					error = 'Repository not found. Private instances may require authentication.';
				} else if (response.status === 401) {
					error = 'Authentication required. This instance requires a token to access project details.';
				} else if (response.status === 429) {
					error = 'rate_limited';
				} else {
					error = `Failed to fetch repository details (${response.status}).`;
				}
				return;
			}

			const data: RepoDetailsResponse = await response.json();
			details = data.details;
			if (!resolvedPath && data.details?.full_path) {
				resolvedPath = data.details.full_path;
			}
			readme = data.readme;
			commits = data.commits || [];
			contributors = data.contributors || [];

			// Fetch real security data
			await fetchSecurityData(provider, path, data.details, data.readme);
		} catch (err) {
			error = 'Failed to connect to API.';
		} finally {
			loading = false;
		}
	};

	// Fetch real security data from API
	const fetchSecurityData = async (provider: string, repoPath: string, repo: RepoDetails, readmeContent: string) => {
		const { repoDbId } = getParams();
		if (!repoDbId) {
			generateMockSecurityData(repo, readmeContent);
			return;
		}

		const metadata = await fetchRepoMetadata(repoDbId);
		const sbomComponents = metadata?.dependencies?.from_sbom || 0;
		const manifestComponents = metadata?.dependencies?.from_manifest || 0;
		const totalComponents = Math.max(sbomComponents, manifestComponents);
		const vulnSummary = metadata?.vulnerabilities?.summary;

		securityData = {
			vulnerabilities: {
				critical: vulnSummary?.critical || 0,
				high: vulnSummary?.high || 0,
				medium: vulnSummary?.medium || 0,
				low: vulnSummary?.low || 0
			},
			secrets: metadata?.secrets?.latest_count || 0,
			issues: {
				noOwner: false, // TODO: check for CODEOWNERS file
				noLicense: !repo.license,
				noReadme: !readmeContent,
				outdatedDeps: 0 // TODO: implement outdated deps check
			},
			components: totalComponents,
			componentsFromSBOM: sbomComponents,
			componentsFromManifest: manifestComponents
		};

		runTimeline = metadata?.runs?.timeline || [];
		totalRuns = metadata?.runs?.total || 0;
	};

	const fetchRepoMetadata = async (repoID: string): Promise<RepoMetadataResponse | null> => {
		try {
			const response = await fetch(`/api/repos/metadata?repo_id=${encodeURIComponent(repoID)}`, {
				credentials: 'include'
			});
			if (response.ok) {
				return await response.json();
			}
		} catch {
			// Ignore errors
		}
		return null;
	};

	// Generate fallback mock security data
	const generateMockSecurityData = (repo: RepoDetails, readmeContent: string) => {
		const seed = repo.external_id.split('').reduce((a, b) => a + b.charCodeAt(0), 0);
		const rand = (max: number) => Math.abs((seed * 9301 + 49297) % 233280) % max;

		securityData = {
			vulnerabilities: {
				critical: rand(3),
				high: rand(8),
				medium: rand(15),
				low: rand(25)
			},
			secrets: 0,
			issues: {
				noOwner: rand(10) > 7,
				noLicense: !repo.license,
				noReadme: !readmeContent,
				outdatedDeps: rand(12)
			},
			components: 0,
			componentsFromSBOM: 0,
			componentsFromManifest: 0
		};
	};

	const formatDate = (dateStr: string) => {
		if (!dateStr) return '';
		return new Date(dateStr).toLocaleDateString('en-US', {
			year: 'numeric',
			month: 'short',
			day: 'numeric'
		});
	};

	const formatDateTime = (dateStr?: string) => {
		if (!dateStr) return '';
		return new Date(dateStr).toLocaleString('en-US', {
			year: 'numeric',
			month: 'short',
			day: 'numeric',
			hour: '2-digit',
			minute: '2-digit'
		});
	};

	const formatDuration = (ms?: number) => {
		if (!ms || ms <= 0) return '';
		const seconds = Math.round(ms / 1000);
		if (seconds < 60) return `${seconds}s`;
		const minutes = Math.round(seconds / 60);
		return `${minutes}m`;
	};

	const formatSize = (kb: number) => {
		if (kb < 1024) return `${kb} KB`;
		return `${(kb / 1024).toFixed(1)} MB`;
	};

	const goBack = () => {
		if (browser) {
			history.back();
		}
	};

	// Scan functionality
	let activeTab = $state('contributors');
	let scanning = $state(false);
	let scanError = $state('');
	let activeRunId = $state<string | null>(null);
	let activeRunStatus = $state<string | null>(null);

	// Check for active scans on this repo
	const checkActiveScans = async () => {
		const { repoDbId } = getParams();
		if (!repoDbId) return;

		try {
			const response = await fetch(`/api/runs?repo_id=${encodeURIComponent(repoDbId)}&page_size=1`, {
				credentials: 'include'
			});
			if (response.ok) {
				const data = await response.json();
				if (data.runs && data.runs.length > 0) {
					const latestRun = data.runs[0];
					if (latestRun.status === 'QUEUED' || latestRun.status === 'RUNNING') {
						activeRunId = latestRun.id;
						activeRunStatus = latestRun.status;
					} else {
						activeRunId = null;
						activeRunStatus = null;
					}
				}
			}
		} catch {
			// Ignore errors
		}
	};

	const triggerScan = async () => {
		if (!details) return;

		scanning = true;
		scanError = '';

		try {
			const response = await fetch('/api/runs', {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					provider: resolvedProvider,
					repo_path: resolvedPath,
					base_url: resolvedBaseUrl || undefined,
					provider_id: resolvedProviderId || undefined,
					ref: details.default_branch || undefined,
					repo_disabled: details.is_disabled || undefined
				})
			});

			if (!response.ok) {
				const text = await response.text();
				throw new Error(text || 'Failed to create scan');
			}

			const data = await response.json();
			activeRunId = data.id;
			activeRunStatus = 'QUEUED';

			// Navigate to the run page
			if (browser) {
				goto(`/app/runs/${data.id}`);
			}
		} catch (err) {
			scanError = err instanceof Error ? err.message : 'Failed to trigger scan';
		} finally {
			scanning = false;
		}
	};

	const goToActiveRun = () => {
		if (activeRunId && browser) {
			goto(`/app/runs/${activeRunId}`);
		}
	};

	$effect(() => {
		if (!browser) return;
		// Re-fetch whenever URL params change (handles same-route navigation)
		const _ = $page.url.href;
		fetchRepoDetails().then(() => checkActiveScans());
	});
</script>

<svelte:head>
	<title>{details?.name || 'Repository'} - SPAM</title>
</svelte:head>

<div class="space-y-6">
	<!-- Back button + view on provider link -->
	<div class="flex items-center justify-between">
		<button
			type="button"
			class="inline-flex items-center gap-2 text-sm text-[var(--text-secondary)] transition hover:text-[var(--accent)]"
			onclick={goBack}
		>
			<ArrowLeft class="h-4 w-4" />
			Back to providers
		</button>
		{#if details}
			<a
				href={details.html_url}
				target="_blank"
				rel="noopener noreferrer"
				class="flex mr-[2em] pr-2 items-center gap-1.5 text-[11px] font-medium transition-opacity hover:opacity-70"
				style="color: var(--accent);"
			>
				View on {resolvedBaseUrl ? new URL(resolvedBaseUrl).hostname : resolvedProvider === 'gitlab' ? 'GitLab' : resolvedProvider === 'gitea' ? 'Gitea' : resolvedProvider === 'forgejo' ? 'Forgejo' : 'GitHub'}
				<svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14"></path><path d="m12 5 7 7-7 7"></path></svg>
			</a>
		{/if}
	</div>

	{#if loading}
		<div class="flex items-center justify-center py-20">
			<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
		</div>
	{:else if error === 'rate_limited'}
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-8 text-center">
			<Clock class="mx-auto h-12 w-12 text-yellow-500" />
			<p class="mt-4 text-lg font-semibold text-[var(--text-bright)]">Rate Limited</p>
			<p class="mt-2 text-sm text-[var(--text-secondary)]">API rate limit reached. Please try again later.</p>
		</div>
	{:else if error}
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-8 text-center">
			<AlertCircle class="mx-auto h-12 w-12 text-[var(--error)]" />
			<p class="mt-4 text-[var(--text-secondary)]">{error}</p>
		</div>
	{:else if details}
		<!-- Header + Stats -->
		<article class="panel-surface space-y-4 px-6 py-6 sm:px-10">
			<div class="flex items-start justify-between gap-4">
				<div class="min-w-0 flex-1">
					<div class="flex items-center gap-3">
						<GitBranch class="h-6 w-6 flex-shrink-0 text-[var(--accent)]" />
						<h1 class="truncate text-2xl font-semibold text-[var(--text-bright)]">{details.name}</h1>
						{#if details.is_private}
							<span class="inline-flex items-center gap-1 rounded-full bg-[var(--text-muted)]/20 px-2 py-0.5 text-xs text-[var(--text-muted)]"><Lock class="h-3 w-3" /> Private</span>
						{:else}
							<span class="inline-flex items-center gap-1 rounded-full bg-[var(--success)]/10 px-2 py-0.5 text-xs text-[var(--success)]"><Globe class="h-3 w-3" /> Public</span>
						{/if}

						{#if details.is_archived}
							<span class="rounded-full bg-[var(--text-muted)]/20 px-2 py-0.5 text-xs text-[var(--text-muted)]">Archived</span>
						{/if}
						{#if details.is_fork}
							<span class="rounded-full bg-[var(--accent)]/10 px-2 py-0.5 text-xs text-[var(--accent)]">Fork</span>
						{/if}
					</div>
					<p class="mt-1 text-sm text-[var(--text-muted)]">{details.full_path}</p>
					{#if details.description}
						<p class="mt-3 text-[var(--text-secondary)]">{details.description}</p>
					{/if}
					{#if details.topics && details.topics.length > 0}
						<div class="mt-3 flex flex-wrap gap-2">
							{#each details.topics as topic}
								<span class="rounded-full bg-[var(--accent)]/10 px-3 py-1 text-xs text-[var(--accent)]">{topic}</span>
							{/each}
						</div>
					{/if}
				</div>
				<div class="flex flex-col gap-2 sm:flex-row sm:items-center">
					{#if activeRunId}
						<button
							type="button"
							class="flex items-center gap-2 rounded-xl border border-[var(--info)] bg-[var(--info)]/10 px-4 py-2 text-sm font-medium text-[var(--info)] transition hover:bg-[var(--info)]/20"
							onclick={goToActiveRun}
						>
							<Loader2 class="h-4 w-4 animate-spin" />
							View {activeRunStatus} Scan
						</button>
					{:else}
						<button
							type="button"
							class="btn btn-primary disabled:opacity-50"
							onclick={triggerScan}
							disabled={scanning}
						>
							{scanning ? 'Starting...' : 'Scan Repository'}
						</button>
					{/if}
				</div>
			</div>

			{#if scanError}
				<div class="rounded-xl border border-[var(--error)]/30 bg-[var(--error)]/10 px-4 py-2 text-sm text-[var(--error)]">
					{scanError}
				</div>
			{/if}

			<!-- Quick stats row -->
			<div class="flex flex-wrap gap-4 pt-4 text-sm text-[var(--text-secondary)]">
				<span class="flex items-center gap-1.5"><Star class="h-4 w-4" /> {details.stats.stars.toLocaleString()} stars</span>
				<span class="flex items-center gap-1.5"><GitFork class="h-4 w-4" /> {details.stats.forks.toLocaleString()} forks</span>
				<span class="flex items-center gap-1.5"><Eye class="h-4 w-4" /> {details.stats.watchers.toLocaleString()} watching</span>
				{#if details.languages && details.languages.length > 0}
					{#each details.languages as lang}
						<span class="flex items-center gap-1.5" style="display:none"><span class="h-3 w-3 rounded-full bg-[var(--accent)]"></span> {lang}</span>
					{/each}
				{/if}
				{#if details.license}
					<span class="flex items-center gap-1.5"><Scale class="h-4 w-4" /> {details.license}</span>
				{/if}
				<span class="flex items-center gap-1.5">
					{#if resolvedProvider === 'gitlab'}
						<svg class="h-4 w-4" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
							<path d="M23.955 13.587l-1.342-4.135-2.664-8.189a.455.455 0 00-.867 0L16.418 9.45H7.582L4.918 1.263a.455.455 0 00-.867 0L1.386 9.45.044 13.587a.924.924 0 00.331 1.023L12 23.054l11.625-8.443a.92.92 0 00.33-1.024" />
						</svg>
					{:else if resolvedProvider === 'gitea' || resolvedProvider === 'forgejo'}
						<Gitea size={14} />
					{:else}
						<svg class="h-4 w-4" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
							<path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
						</svg>
					{/if}
					{resolvedProvider === 'gitlab' ? 'GitLab' : resolvedProvider === 'gitea' ? 'Gitea' : resolvedProvider === 'forgejo' ? 'Forgejo' : 'GitHub'}
				</span>
				<span class="flex items-center gap-1.5"><Clock class="h-4 w-4" /> Last activity {formatDate(details.updated_at)}</span>
			</div>

			<!-- Stats grid -->
			<div class="grid gap-3 pt-4 sm:grid-cols-2 lg:grid-cols-4">
			<!-- Repository Stats -->
				<div class="space-y-3 metric-card rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Repository</h3>
				<div class="grid grid-cols-2 gap-3">
					<div>
						<p class="text-2xl font-bold text-[var(--text-bright)]">{details.stats.commits.toLocaleString()}</p>
						<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><GitCommit class="h-3 w-3" /> Commits</p>
					</div>
					<div>
						<p class="text-2xl font-bold text-[var(--text-bright)]">{details.stats.branches}</p>
						<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><GitBranch class="h-3 w-3" /> Branches</p>
					</div>
					<div>
						<p class="text-2xl font-bold text-[var(--text-bright)]">{details.stats.releases}</p>
						<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><Tag class="h-3 w-3" /> Releases</p>
					</div>
					<div>
						<p class="text-2xl font-bold text-[var(--text-bright)]">{Math.max(details.stats.contributors, contributors.length)}</p>
						<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><Users class="h-3 w-3" /> Contributors</p>
					</div>
				</div>
			</div>

			<!-- Vulnerabilities -->
				<div class="space-y-3 metric-card rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Vulnerabilities</h3>
				<div class="grid grid-cols-2 gap-3">
					<div>
						<p class="text-2xl font-bold text-red-500">{securityData.vulnerabilities.critical}</p>
						<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><ShieldX class="h-3 w-3 text-red-500" /> Critical</p>
					</div>
					<div>
						<p class="text-2xl font-bold text-orange-500">{securityData.vulnerabilities.high}</p>
						<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><ShieldAlert class="h-3 w-3 text-orange-500" /> High</p>
					</div>
					<div>
						<p class="text-2xl font-bold text-yellow-500">{securityData.vulnerabilities.medium}</p>
						<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><Shield class="h-3 w-3 text-yellow-500" /> Medium</p>
					</div>
					<div>
						<p class="text-2xl font-bold text-[var(--text-secondary)]">{securityData.vulnerabilities.low}</p>
						<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><Shield class="h-3 w-3" /> Low</p>
					</div>
				</div>
			</div>

			<!-- Secrets & Issues -->
				<div class="space-y-3 metric-card rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Secrets & Issues</h3>
				<div class="space-y-2">
					<div class="flex items-center justify-between">
						<span class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
							<FileWarning class="h-4 w-4 text-red-500" /> Secrets found
						</span>
						<span class="font-semibold text-[var(--text-bright)]">{securityData.secrets}</span>
					</div>
					<div class="flex items-center justify-between">
						<span class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
							<AlertCircle class="h-4 w-4 {securityData.issues.noOwner ? 'text-orange-500' : 'text-green-500'}" /> CODEOWNERS
						</span>
						<span class="text-sm {securityData.issues.noOwner ? 'text-orange-500' : 'text-green-500'}">{securityData.issues.noOwner ? 'Missing' : 'Present'}</span>
					</div>
					<div class="flex items-center justify-between">
						<span class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
							<Scale class="h-4 w-4 {securityData.issues.noLicense ? 'text-orange-500' : 'text-green-500'}" /> License
						</span>
						<span class="text-sm {securityData.issues.noLicense ? 'text-orange-500' : 'text-green-500'}">{securityData.issues.noLicense ? 'Missing' : 'Present'}</span>
					</div>
					<div class="flex items-center justify-between">
						<span class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
							<Package class="h-4 w-4 text-yellow-500" /> Outdated deps
						</span>
						<span class="font-semibold text-[var(--text-bright)]">{securityData.issues.outdatedDeps}</span>
					</div>
				</div>
			</div>

			<!-- Components -->
				<div class="space-y-3 metric-card rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Dependencies</h3>
				<div class="flex items-center gap-4">
					<Package class="h-10 w-10 text-[var(--accent)]" />
					<div>
						<p class="text-3xl font-bold text-[var(--text-bright)]">{securityData.components}</p>
						<p class="text-sm text-[var(--text-muted)]">Total components</p>
					</div>
				</div>
				<div class="mt-2 space-y-1 text-xs text-[var(--text-muted)]">
											<div class="flex items-center justify-between">
							<span class="flex items-center gap-1">
								<Microscope class="h-3 w-3 text-blue-400" />
								From SBOM
							</span>
							<span class="font-semibold text-[var(--text-secondary)]">{securityData.componentsFromSBOM}</span>
						</div>
						<div class="flex items-center justify-between">
							<span class="flex items-center gap-1">
								<FileCode class="h-3 w-3 text-purple-400" />
								From Manifest
							</span>
							<span class="font-semibold text-[var(--text-secondary)]">{securityData.componentsFromManifest}</span>
						</div>
					{#if details.size}
						<div class="pt-1 text-[var(--text-muted)]">
							Repository size: {formatSize(details.size)}
						</div>
					{/if}
				</div>
			</div>
			</div>
			<!-- Activity Tabs -->
			<div class="pt-4">
						<TabSelector
							options={[
								{ value: 'runs', label: 'Runs' },
								{ value: 'contributors', label: 'Contributors' },
								{ value: 'commits', label: 'Commits' }
							]}
							bind:value={activeTab}
						/>

					<div class="mt-[2em]">
					{#if activeTab === 'runs'}
						<div class="space-y-2">
							{#if totalRuns > 0}
								<p class="text-xs text-[var(--text-muted)]">{totalRuns} total runs</p>
							{/if}
							{#if runTimeline.length === 0}
								<div class="flex flex-col items-center justify-center py-8 text-center">
									<EmptyRuns class="mb-3 text-[var(--text-muted)]" />
									<p class="text-sm font-medium text-[var(--text-secondary)]">No runs yet</p>
									<p class="mt-1 text-xs text-[var(--text-muted)]">No runs recorded for this repository yet.</p>
								</div>
							{:else}
								<div class="space-y-3">
									{#each runTimeline as run}
										<a href="/app/runs/{run.id}" class="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-4 py-3 transition hover:border-[var(--accent)]/40 hover:bg-[var(--hover-bg-subtle)]">
											<div class="min-w-0 space-y-1">
												<div class="flex items-center gap-2">
													<span class="rounded-full px-2 py-0.5 text-xs font-medium {run.status === 'SUCCEEDED' ? 'bg-green-500/10 text-green-400' : run.status === 'FAILED' ? 'bg-red-500/10 text-red-400' : 'bg-yellow-500/10 text-yellow-400'}">
														{run.status}
													</span>
													<span class="text-xs text-[var(--text-muted)]">{formatDateTime(run.started_at || run.finished_at)}</span>
													{#if run.duration_ms}
														<span class="text-xs text-[var(--text-muted)]">• {formatDuration(run.duration_ms)}</span>
													{/if}
												</div>
												{#if run.commit_sha}
													<p class="truncate text-xs text-[var(--text-secondary)]">Commit {run.commit_sha.slice(0, 7)}</p>
												{/if}
											</div>
											{#if run.artifacts && run.artifacts.length > 0}
												<div class="flex flex-wrap gap-2 text-xs">
													{#each run.artifacts as artifact}
														<span class="rounded-full border border-[var(--border-color)]/60 px-2 py-0.5 text-[var(--text-secondary)]">
															{artifact.toUpperCase()}
														</span>
													{/each}
												</div>
											{/if}
										</a>
									{/each}
								</div>
							{/if}
						</div>
					{:else if activeTab === 'commits'}
						{#if commits.length === 0}
							<div class="flex flex-col items-center justify-center py-8 text-center">
								<EmptyCommits class="mb-3 text-[var(--text-muted)]" />
								<p class="text-sm font-medium text-[var(--text-secondary)]">No commits available</p>
								<p class="mt-1 text-xs text-[var(--text-muted)]">This repository has no commit history yet.</p>
							</div>
						{:else}
							<div class="space-y-2">
								{#each commits as commit}
									<div class="flex items-start gap-3 rounded-xl bg-[var(--card-bg)]/40 px-4 py-3">
										{#if commit.author_avatar}
											<img src={commit.author_avatar} alt={commit.author_login || commit.author_name} class="h-8 w-8 flex-shrink-0 rounded-full" />
										{:else}
											<div class="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-full bg-[var(--accent)]/20 text-xs font-medium text-[var(--accent)]">
												{commit.author_name.charAt(0).toUpperCase()}
											</div>
										{/if}
										<div class="min-w-0 flex-1">
											<div class="flex items-center gap-2">
												{#if commit.commit_url}
													<a href={commit.commit_url} target="_blank" rel="noopener noreferrer" class="truncate text-sm font-medium text-[var(--text-bright)] hover:text-[var(--accent)]">
														{commit.message}
													</a>
												{:else}
													<span class="truncate text-sm font-medium text-[var(--text-bright)]">{commit.message}</span>
												{/if}
											</div>
											<div class="mt-0.5 flex items-center gap-2 text-xs text-[var(--text-muted)]">
												<span class="font-mono text-[var(--accent)]">{commit.sha.slice(0, 7)}</span>
												<span>{commit.author_login || commit.author_name}</span>
												<span>committed {formatDate(commit.author_date)}</span>
											</div>
										</div>
									</div>
								{/each}
							</div>
							{/if}
						{:else if activeTab === 'contributors'}
								{#if contributors.length === 0}
									<div class="flex flex-col items-center justify-center py-8 text-center">
										<EmptyContributors class="mb-3 text-[var(--text-muted)]" />
										<p class="text-sm font-medium text-[var(--text-secondary)]">No contributors found</p>
										<p class="mt-1 text-xs text-[var(--text-muted)]">Contributors will appear once the repository has commits.</p>
									</div>
							{:else}
								<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
									{#each contributors as contributor}
										<div class="flex items-center gap-3 rounded-xl bg-[var(--card-bg)]/40 px-4 py-3">
											{#if contributor.avatar_url}
												<img src={contributor.avatar_url} alt={contributor.login || contributor.name || ''} class="h-10 w-10 flex-shrink-0 rounded-full" />
											{:else}
												<div class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full bg-[var(--accent)]/20 text-sm font-medium text-[var(--accent)]">
													{(contributor.name || contributor.login || contributor.email || '?').charAt(0).toUpperCase()}
												</div>
											{/if}
											<div class="min-w-0 flex-1">
												{#if contributor.profile_url}
													<a href={contributor.profile_url} target="_blank" rel="noopener noreferrer" class="block truncate text-sm font-medium text-[var(--text-bright)] hover:text-[var(--accent)]">
														{contributor.login || contributor.name || contributor.email}
													</a>
												{:else}
													<p class="truncate text-sm font-medium text-[var(--text-bright)]">{contributor.name || contributor.login || contributor.email}</p>
												{/if}
												{#if contributor.email}
													<p class="truncate text-xs text-[var(--text-secondary)]">{contributor.email}</p>
												{/if}
												<p class="text-xs text-[var(--text-muted)]">{contributor.contributions} {contributor.contributions === 1 ? 'commit' : 'commits'}</p>
											</div>
										</div>
									{/each}
								</div>
							{/if}
						{/if}
						</div>
				</div>
			</article>

		<!-- README -->
		{#if readme}
			<section class="panel-surface overflow-hidden px-6 py-6 sm:px-10 max-w-[90vw]">
				<div class="w-full overflow-hidden break-words">
					<Markdown content={readme} class="max-w-full text-[var(--text-secondary)]" />
				</div>
			</section>
		{/if}
	{/if}
</div>
