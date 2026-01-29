<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { page } from '$app/stores';
	import {
		GitBranch, Star, GitFork, Eye, AlertCircle, Tag, Users, GitCommit,
		ArrowLeft, ExternalLink, Shield, ShieldAlert, ShieldX, FileWarning,
		Package, Clock, Scale, Play, Loader2
	} from 'lucide-svelte';
	import Markdown from '$lib/components/Markdown.svelte';

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
		language: string;
		is_private: boolean;
		is_archived: boolean;
		is_fork: boolean;
		topics: string[];
		created_at: string;
		updated_at: string;
		pushed_at: string;
		stats: RepoStats;
		license: string;
		size: number;
	};

	type RepoDetailsResponse = {
		details: RepoDetails;
		readme: string;
	};

	// Mock security data (for display purposes)
	type SecurityData = {
		vulnerabilities: { critical: number; high: number; medium: number; low: number };
		secrets: number;
		issues: { noOwner: boolean; noLicense: boolean; noReadme: boolean; outdatedDeps: number };
		components: number;
	};

	let details: RepoDetails | null = $state(null);
	let readme = $state('');
	let loading = $state(true);
	let error = $state('');
	let securityData: SecurityData = $state({
		vulnerabilities: { critical: 0, high: 0, medium: 0, low: 0 },
		secrets: 0,
		issues: { noOwner: false, noLicense: false, noReadme: false, outdatedDeps: 0 },
		components: 0
	});

	// Get query params
	const getParams = () => {
		if (!browser) return { provider: '', path: '', baseUrl: '' };
		const params = $page.url.searchParams;
		return {
			provider: params.get('provider') || 'github',
			path: params.get('path') || '',
			baseUrl: params.get('base_url') || ''
		};
	};

	const fetchRepoDetails = async () => {
		const { provider, path, baseUrl } = getParams();
		if (!path) {
			error = 'No repository path specified.';
			loading = false;
			return;
		}

		loading = true;
		error = '';

		try {
			let url: string;
			const params = new URLSearchParams();
			if (baseUrl) params.set('base_url', baseUrl);

			if (provider === 'github') {
				// path is owner/repo
				url = `/api/providers/github/${path}/details`;
			} else if (provider === 'gitlab') {
				// path is full project path (url encoded)
				url = `/api/providers/gitlab/${encodeURIComponent(path)}/details?${params}`;
			} else {
				// gitea/forgejo - path is owner/repo
				url = `/api/providers/gitea/${path}/details?${params}`;
			}

			const response = await fetch(url, { credentials: 'include' });

			if (!response.ok) {
				if (response.status === 404) {
					error = 'Repository not found. Private instances may require authentication.';
				} else if (response.status === 401) {
					error = 'Authentication required. This instance requires a token to access project details.';
				} else {
					error = `Failed to fetch repository details (${response.status}).`;
				}
				return;
			}

			const data: RepoDetailsResponse = await response.json();
			details = data.details;
			readme = data.readme;

			// Generate mock security data based on repo
			generateMockSecurityData(data.details, data.readme);
		} catch (err) {
			error = 'Failed to connect to API.';
		} finally {
			loading = false;
		}
	};

	// Generate realistic-looking mock security data
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
			secrets: rand(3),
			issues: {
				noOwner: rand(10) > 7,
				noLicense: !repo.license,
				noReadme: !readmeContent,
				outdatedDeps: rand(12)
			},
			components: 50 + rand(200)
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
	let scanning = $state(false);
	let scanError = $state('');
	let scanSuccess = $state('');

	const triggerScan = async () => {
		if (!details) return;

		const { provider, path, baseUrl } = getParams();
		scanning = true;
		scanError = '';
		scanSuccess = '';

		try {
			const response = await fetch('/api/runs', {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					provider,
					repo_path: path,
					base_url: baseUrl || undefined,
					ref: details.default_branch || undefined
				})
			});

			if (!response.ok) {
				const text = await response.text();
				throw new Error(text || 'Failed to create scan');
			}

			const data = await response.json();
			scanSuccess = `Scan queued! Run ID: ${data.id.substring(0, 8)}`;

			// Clear success message after 5 seconds
			setTimeout(() => {
				scanSuccess = '';
			}, 5000);
		} catch (err) {
			scanError = err instanceof Error ? err.message : 'Failed to trigger scan';
		} finally {
			scanning = false;
		}
	};

	onMount(() => {
		if (browser) {
			fetchRepoDetails();
		}
	});
</script>

<svelte:head>
	<title>{details?.name || 'Repository'} - SPAM</title>
</svelte:head>

<div class="space-y-6">
	<!-- Back button -->
	<button
		type="button"
		class="inline-flex items-center gap-2 text-sm text-[var(--text-secondary)] transition hover:text-[var(--accent)]"
		onclick={goBack}
	>
		<ArrowLeft class="h-4 w-4" />
		Back to providers
	</button>

	{#if loading}
		<div class="flex items-center justify-center py-20">
			<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
		</div>
	{:else if error}
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-8 text-center">
			<AlertCircle class="mx-auto h-12 w-12 text-[var(--error)]" />
			<p class="mt-4 text-[var(--text-secondary)]">{error}</p>
		</div>
	{:else if details}
		<!-- Header -->
		<section class="panel-surface space-y-4 px-6 py-6 sm:px-10">
			<div class="flex items-start justify-between gap-4">
				<div class="min-w-0 flex-1">
					<div class="flex items-center gap-3">
						<GitBranch class="h-6 w-6 flex-shrink-0 text-[var(--accent)]" />
						<h1 class="truncate text-2xl font-semibold text-[var(--text-bright)]">{details.name}</h1>
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
					<button
						type="button"
						class="flex items-center gap-2 rounded-xl border border-[var(--success)] bg-[var(--success)]/10 px-4 py-2 text-sm font-medium text-[var(--success)] transition hover:bg-[var(--success)]/20 disabled:opacity-50"
						onclick={triggerScan}
						disabled={scanning}
					>
						{#if scanning}
							<Loader2 class="h-4 w-4 animate-spin" />
							Scanning...
						{:else}
							<Play class="h-4 w-4" />
							Scan Repository
						{/if}
					</button>
					<a
						href={details.html_url}
						target="_blank"
						rel="noopener noreferrer"
						class="flex items-center gap-2 rounded-xl border border-[var(--accent)] bg-[var(--accent)]/10 px-4 py-2 text-sm font-medium text-[var(--accent)] transition hover:bg-[var(--accent)]/20"
					>
						View on {getParams().provider === 'github' ? 'GitHub' : getParams().provider === 'gitlab' ? 'GitLab' : 'Gitea'}
						<ExternalLink class="h-4 w-4" />
					</a>
				</div>
			</div>

			{#if scanSuccess}
				<div class="rounded-xl border border-[var(--success)]/30 bg-[var(--success)]/10 px-4 py-2 text-sm text-[var(--success)]">
					{scanSuccess}
					<a href="/app/runs" class="ml-2 underline hover:no-underline">View runs</a>
				</div>
			{/if}
			{#if scanError}
				<div class="rounded-xl border border-[var(--error)]/30 bg-[var(--error)]/10 px-4 py-2 text-sm text-[var(--error)]">
					{scanError}
				</div>
			{/if}

			<!-- Quick stats row -->
			<div class="flex flex-wrap gap-4 border-t border-[var(--border-color)]/60 pt-4 text-sm text-[var(--text-secondary)]">
				<span class="flex items-center gap-1.5"><Star class="h-4 w-4" /> {details.stats.stars.toLocaleString()} stars</span>
				<span class="flex items-center gap-1.5"><GitFork class="h-4 w-4" /> {details.stats.forks.toLocaleString()} forks</span>
				<span class="flex items-center gap-1.5"><Eye class="h-4 w-4" /> {details.stats.watchers.toLocaleString()} watching</span>
				{#if details.language}
					<span class="flex items-center gap-1.5"><span class="h-3 w-3 rounded-full bg-[var(--accent)]"></span> {details.language}</span>
				{/if}
				{#if details.license}
					<span class="flex items-center gap-1.5"><Scale class="h-4 w-4" /> {details.license}</span>
				{/if}
				<span class="flex items-center gap-1.5"><Clock class="h-4 w-4" /> Updated {formatDate(details.updated_at)}</span>
			</div>
		</section>

		<!-- Stats Cards Grid -->
		<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
			<!-- Repository Stats -->
			<div class="panel-surface space-y-3 px-5 py-4">
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
						<p class="text-2xl font-bold text-[var(--text-bright)]">{details.stats.contributors}</p>
						<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><Users class="h-3 w-3" /> Contributors</p>
					</div>
				</div>
			</div>

			<!-- Vulnerabilities -->
			<div class="panel-surface space-y-3 px-5 py-4">
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
			<div class="panel-surface space-y-3 px-5 py-4">
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
			<div class="panel-surface space-y-3 px-5 py-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Dependencies</h3>
				<div class="flex items-center gap-4">
					<Package class="h-10 w-10 text-[var(--accent)]" />
					<div>
						<p class="text-3xl font-bold text-[var(--text-bright)]">{securityData.components}</p>
						<p class="text-sm text-[var(--text-muted)]">Total components</p>
					</div>
				</div>
				<div class="mt-2 text-xs text-[var(--text-muted)]">
					{#if details.size}
						Repository size: {formatSize(details.size)}
					{/if}
				</div>
			</div>
		</div>

		<!-- README -->
		{#if readme}
			<section class="panel-surface px-6 py-6 sm:px-10">
				<Markdown content={readme} class="max-w-none text-[var(--text-secondary)]" />
			</section>
		{/if}
	{/if}
</div>

