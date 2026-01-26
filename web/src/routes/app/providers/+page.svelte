<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { Search, GitBranch, Folder, ChevronRight, ExternalLink, Archive, GitFork, Lock } from 'lucide-svelte';

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

	// Tab state
	let activeTab: 'github' | 'gitlab' = $state('github');

	// GitHub state
	let ghOwner = $state('NorskHelsenett');
	let ghRepos: RepoData[] = $state([]);
	let ghLoading = $state(false);
	let ghError = $state('');
	let ghPage = $state(1);
	let ghHasNextPage = $state(false);
	let ghNextPage = $state(0);
	let ghTotalCount = $state(0);

	// GitLab state
	let glGroup = $state('gitlab-org');
	let glProjects: RepoData[] = $state([]);
	let glSubgroups: GroupData[] = $state([]);
	let glLoading = $state(false);
	let glError = $state('');
	let glPage = $state(1);
	let glHasNextPage = $state(false);
	let glNextPage = $state(0);
	let glTotalCount = $state(0);
	let glIncludeSubgroups = $state(false);
	let glGroupPath: string[] = $state([]); // Breadcrumb navigation

	const pageSize = 30;

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
			ghPage = data.page;
			ghHasNextPage = data.has_next_page;
			ghNextPage = data.next_page;
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
			glPage = data.page;
			glHasNextPage = data.has_next_page;
			glNextPage = data.next_page;
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

	const navigateToSubgroup = (group: GroupData) => {
		glGroupPath = [...glGroupPath, glGroup];
		glGroup = group.full_path;
		glPage = 1;
		fetchGitLabProjects(1);
		fetchGitLabSubgroups();
	};

	const navigateBack = (index?: number) => {
		if (index !== undefined) {
			// Navigate to specific breadcrumb
			glGroup = glGroupPath[index];
			glGroupPath = glGroupPath.slice(0, index);
		} else if (glGroupPath.length > 0) {
			// Navigate up one level
			glGroup = glGroupPath.pop()!;
			glGroupPath = [...glGroupPath];
		}
		glPage = 1;
		fetchGitLabProjects(1);
		fetchGitLabSubgroups();
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

	const handleGitHubKeydown = (e: KeyboardEvent) => {
		if (e.key === 'Enter') {
			handleGitHubSearch();
		}
	};

	const handleGitLabKeydown = (e: KeyboardEvent) => {
		if (e.key === 'Enter') {
			handleGitLabSearch();
		}
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

	onMount(() => {
		if (browser) {
			// Auto-fetch on mount with default values
			fetchGitHubRepos(1);
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
			<p class="text-sm text-[var(--text-tertiary)]">Browse public repositories from GitHub and GitLab.</p>
		</header>

		<!-- Tabs -->
		<div class="flex gap-2 border-b border-[var(--border-color)]">
			<button
				type="button"
				class="px-4 py-2 text-sm font-medium transition {activeTab === 'github'
					? 'border-b-2 border-[var(--accent)] text-[var(--accent)]'
					: 'text-[var(--text-secondary)] hover:text-[var(--text-bright)]'}"
				onclick={() => { activeTab = 'github'; if (ghRepos.length === 0) fetchGitHubRepos(1); }}
			>
				GitHub
			</button>
			<button
				type="button"
				class="px-4 py-2 text-sm font-medium transition {activeTab === 'gitlab'
					? 'border-b-2 border-[var(--accent)] text-[var(--accent)]'
					: 'text-[var(--text-secondary)] hover:text-[var(--text-bright)]'}"
				onclick={() => { activeTab = 'gitlab'; if (glProjects.length === 0) { fetchGitLabProjects(1); fetchGitLabSubgroups(); } }}
			>
				GitLab
			</button>
		</div>

		<!-- GitHub Tab Content -->
		{#if activeTab === 'github'}
			<div class="space-y-4">
				<!-- Search -->
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
					<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">
						{ghError}
					</div>
				{/if}

				{#if ghLoading}
					<p class="text-sm text-[var(--text-secondary)]">Loading repositories...</p>
				{:else if ghRepos.length === 0 && !ghError}
					<p class="text-sm text-[var(--text-secondary)]">No repositories found. Try searching for an organization or username.</p>
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
									<tr class="transition hover:bg-[var(--hover-bg-subtle)]">
										<td class="px-5 py-3">
											<div class="flex items-center gap-2">
												<GitBranch class="h-4 w-4 text-[var(--accent)]" />
												<span class="font-semibold text-[var(--text-bright)]">{repo.name}</span>
											</div>
											{#if repo.description}
												<p class="mt-0.5 line-clamp-1 text-xs text-[var(--text-muted)]" title={repo.description}>
													{repo.description}
												</p>
											{/if}
											{#if repo.topics && repo.topics.length > 0}
												<div class="mt-1 flex flex-wrap gap-1">
													{#each repo.topics.slice(0, 3) as topic}
														<span class="rounded-full bg-[var(--accent)]/10 px-2 py-0.5 text-[10px] text-[var(--accent)]">
															{topic}
														</span>
													{/each}
													{#if repo.topics.length > 3}
														<span class="text-[10px] text-[var(--text-muted)]">+{repo.topics.length - 3} more</span>
													{/if}
												</div>
											{/if}
										</td>
										<td class="px-5 py-3">
											{#if repo.language}
												<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs">
													{repo.language}
												</span>
											{:else}
												<span class="text-[var(--text-muted)]">—</span>
											{/if}
										</td>
										<td class="px-5 py-3 text-xs">
											{formatDate(repo.pushed_at || repo.updated_at)}
										</td>
										<td class="px-5 py-3 text-center">
											<div class="flex items-center justify-center gap-1">
												{#if repo.is_archived}
													<span title="Archived" class="text-[var(--text-muted)]">
														<Archive class="h-3.5 w-3.5" />
													</span>
												{/if}
												{#if repo.is_fork}
													<span title="Fork" class="text-[var(--text-muted)]">
														<GitFork class="h-3.5 w-3.5" />
													</span>
												{/if}
												{#if repo.is_private}
													<span title="Private" class="text-[var(--text-muted)]">
														<Lock class="h-3.5 w-3.5" />
													</span>
												{/if}
												{#if !repo.is_archived && !repo.is_fork && !repo.is_private}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</div>
										</td>
										<td class="px-5 py-3 text-right">
											<a
												href={repo.html_url}
												target="_blank"
												rel="noopener noreferrer"
												class="inline-flex items-center gap-1 text-xs text-[var(--accent)] hover:underline"
											>
												View <ExternalLink class="h-3 w-3" />
											</a>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>

					<!-- Pagination -->
					<div class="flex items-center justify-between pt-2">
						<p class="text-xs text-[var(--text-muted)]">
							Page {ghPage} {ghTotalCount > 0 ? `of ${Math.ceil(ghTotalCount / pageSize)}` : ''}
						</p>
						<div class="flex gap-2">
							<button
								type="button"
								class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
								disabled={ghPage <= 1 || ghLoading}
								onclick={() => fetchGitHubRepos(ghPage - 1)}
							>
								Previous
							</button>
							<button
								type="button"
								class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
								disabled={!ghHasNextPage || ghLoading}
								onclick={() => fetchGitHubRepos(ghPage + 1)}
							>
								Next
							</button>
						</div>
					</div>
				{/if}
			</div>
		{/if}

		<!-- GitLab Tab Content -->
		{#if activeTab === 'gitlab'}
			<div class="space-y-4">
				<!-- Search -->
				<div class="flex flex-col gap-4 sm:flex-row sm:items-center">
					<div class="relative flex-1">
						<Search class="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-tertiary)]" />
						<input
							type="text"
							placeholder="Group path (e.g., gitlab-org)"
							class="w-full rounded-2xl border border-[var(--border-color)] bg-transparent py-3 pl-11 pr-4 text-sm text-[var(--text-secondary)] placeholder-[var(--text-muted)] transition focus:border-[var(--accent)] focus:outline-none"
							bind:value={glGroup}
							onkeydown={handleGitLabKeydown}
						/>
					</div>
					<label class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
						<input
							type="checkbox"
							bind:checked={glIncludeSubgroups}
							class="rounded border-[var(--border-color)]"
						/>
						Include subgroups
					</label>
					<button
						type="button"
						class="rounded-2xl border border-[var(--accent)] bg-[var(--accent)]/10 px-6 py-3 text-sm font-medium text-[var(--accent)] transition hover:bg-[var(--accent)]/20 disabled:opacity-50"
						onclick={handleGitLabSearch}
						disabled={glLoading || !glGroup.trim()}
					>
						{glLoading ? 'Loading...' : 'Fetch Projects'}
					</button>
				</div>

				<!-- Breadcrumb -->
				{#if glGroupPath.length > 0}
					<div class="flex items-center gap-1 text-sm text-[var(--text-secondary)]">
						{#each glGroupPath as pathPart, i}
							<button
								type="button"
								class="text-[var(--accent)] hover:underline"
								onclick={() => navigateBack(i)}
							>
								{pathPart.split('/').pop()}
							</button>
							<ChevronRight class="h-4 w-4 text-[var(--text-muted)]" />
						{/each}
						<span class="text-[var(--text-bright)]">{glGroup.split('/').pop()}</span>
					</div>
				{/if}

				{#if glError}
					<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">
						{glError}
					</div>
				{/if}

				<!-- Subgroups -->
				{#if glSubgroups.length > 0}
					<div class="space-y-2">
						<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Subgroups</h3>
						<div class="flex flex-wrap gap-2">
							{#each glSubgroups as group}
								<button
									type="button"
									class="inline-flex items-center gap-2 rounded-xl border border-[var(--border-color)] bg-[var(--card-bg)]/40 px-3 py-2 text-sm text-[var(--text-secondary)] transition hover:border-[var(--accent)] hover:text-[var(--text-bright)]"
									onclick={() => navigateToSubgroup(group)}
								>
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
					<p class="text-sm text-[var(--text-secondary)]">No projects found. Try searching for a group path.</p>
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
									<tr class="transition hover:bg-[var(--hover-bg-subtle)]">
										<td class="px-5 py-3">
											<div class="flex items-center gap-2">
												<GitBranch class="h-4 w-4 text-[var(--accent)]" />
												<span class="font-semibold text-[var(--text-bright)]">{project.name}</span>
											</div>
											{#if project.description}
												<p class="mt-0.5 line-clamp-1 text-xs text-[var(--text-muted)]" title={project.description}>
													{project.description}
												</p>
											{/if}
											{#if project.topics && project.topics.length > 0}
												<div class="mt-1 flex flex-wrap gap-1">
													{#each project.topics.slice(0, 3) as topic}
														<span class="rounded-full bg-[var(--accent)]/10 px-2 py-0.5 text-[10px] text-[var(--accent)]">
															{topic}
														</span>
													{/each}
													{#if project.topics.length > 3}
														<span class="text-[10px] text-[var(--text-muted)]">+{project.topics.length - 3} more</span>
													{/if}
												</div>
											{/if}
										</td>
										<td class="px-5 py-3">
											<span class="text-xs text-[var(--text-muted)]">{project.full_path}</span>
										</td>
										<td class="px-5 py-3 text-xs">
											{formatDate(project.updated_at)}
										</td>
										<td class="px-5 py-3 text-center">
											<div class="flex items-center justify-center gap-1">
												{#if project.is_archived}
													<span title="Archived" class="text-[var(--text-muted)]">
														<Archive class="h-3.5 w-3.5" />
													</span>
												{/if}
												{#if project.is_fork}
													<span title="Fork" class="text-[var(--text-muted)]">
														<GitFork class="h-3.5 w-3.5" />
													</span>
												{/if}
												{#if project.is_private}
													<span title="Private" class="text-[var(--text-muted)]">
														<Lock class="h-3.5 w-3.5" />
													</span>
												{/if}
												{#if !project.is_archived && !project.is_fork && !project.is_private}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</div>
										</td>
										<td class="px-5 py-3 text-right">
											<a
												href={project.html_url}
												target="_blank"
												rel="noopener noreferrer"
												class="inline-flex items-center gap-1 text-xs text-[var(--accent)] hover:underline"
											>
												View <ExternalLink class="h-3 w-3" />
											</a>
										</td>
									</tr>
								{/each}
							</tbody>
						</table>
					</div>

					<!-- Pagination -->
					<div class="flex items-center justify-between pt-2">
						<p class="text-xs text-[var(--text-muted)]">
							Page {glPage} {glTotalCount > 0 ? `(${glTotalCount} total)` : ''}
						</p>
						<div class="flex gap-2">
							<button
								type="button"
								class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
								disabled={glPage <= 1 || glLoading}
								onclick={() => fetchGitLabProjects(glPage - 1)}
							>
								Previous
							</button>
							<button
								type="button"
								class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
								disabled={!glHasNextPage || glLoading}
								onclick={() => fetchGitLabProjects(glPage + 1)}
							>
								Next
							</button>
						</div>
					</div>
				{/if}
			</div>
		{/if}
	</section>
</div>
