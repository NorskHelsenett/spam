<script lang="ts">
	import { X, Package, GitBranch, Container, ChevronDown, ChevronRight } from 'lucide-svelte';

	type ComponentVersion = {
		id: string;
		version: string;
		repo_count: number;
		created_at: string;
	};

	type ComponentAsset = {
		asset_type: string;
		repo_id?: string;
		provider?: string;
		org?: string;
		slug?: string;
		commit_sha?: string;
		image_registry?: string;
		image_repository?: string;
		image_digest?: string;
		version: string;
		source?: string;
		manifest_path?: string;
		manifest_type?: string;
		direct?: boolean;
		scope?: string;
	};

	type ComponentDetail = {
		id: string;
		name: string;
		ecosystem: string;
		purl?: string;
		version_count: number;
		repo_count: number;
		image_count: number;
		sources: string[];
		versions: ComponentVersion[];
	};

	type Contributor = {
		login: string;
		name?: string;
		email?: string;
		avatar_url?: string;
		profile_url?: string;
		contributions: number;
	};

	type UniqueRepo = {
		key: string;
		provider: string;
		org: string;
		slug: string;
		versions: string[];
		sources: string[];
	};

	type UniqueImage = {
		key: string;
		image_registry: string;
		image_repository: string;
		versions: string[];
	};

	let {
		name,
		ecosystem,
		onClose = () => {}
	}: {
		name: string;
		ecosystem: string;
		onClose?: () => void;
	} = $props();

	let componentDetail: ComponentDetail | null = $state(null);
	let componentAssets: ComponentAsset[] = $state([]);
	let loading = $state(false);
	let assetsLoading = $state(false);
	let selectedVersion = $state('');
	let expandedRepos = $state(new Set<string>());
	let repoContributors = $state<Record<string, Contributor[]>>({});
	let loadingContributors = $state<Record<string, boolean>>({});

	$effect(() => {
		if (name && ecosystem) {
			loadDetail(name, ecosystem);
		}
	});

	const loadDetail = async (depName: string, depEcosystem: string) => {
		loading = true;
		componentDetail = null;
		componentAssets = [];
		selectedVersion = '';
		expandedRepos = new Set();
		repoContributors = {};
		try {
			const params = new URLSearchParams({ name: depName, ecosystem: depEcosystem });
			const response = await fetch(`/api/dependencies/detail?${params}`, { credentials: 'include' });
			if (response.ok) {
				componentDetail = await response.json();
				loadAssets(depName, depEcosystem, '');
			}
		} catch {
			// ignore
		} finally {
			loading = false;
		}
	};

	const loadAssets = async (depName: string, depEcosystem: string, version: string) => {
		assetsLoading = true;
		try {
			const params = new URLSearchParams({ name: depName, ecosystem: depEcosystem });
			if (version) params.set('version', version);
			params.set('page_size', '100');
			const response = await fetch(`/api/dependencies/assets?${params}`, { credentials: 'include' });
			if (response.ok) {
				const data = await response.json();
				componentAssets = data.assets || [];
			}
		} catch {
			componentAssets = [];
		} finally {
			assetsLoading = false;
		}
	};

	const uniqueRepos = $derived.by(() => {
		const map = new Map<string, UniqueRepo>();
		for (const asset of componentAssets) {
			if (asset.asset_type !== 'REPO_COMMIT') continue;
			const key = `${asset.provider}:${asset.org}:${asset.slug}`;
			if (!map.has(key)) {
				map.set(key, {
					key,
					provider: asset.provider ?? '',
					org: asset.org ?? '',
					slug: asset.slug ?? '',
					versions: [],
					sources: []
				});
			}
			const repo = map.get(key)!;
			if (asset.version && !repo.versions.includes(asset.version)) repo.versions.push(asset.version);
			if (asset.source && !repo.sources.includes(asset.source)) repo.sources.push(asset.source);
		}
		return [...map.values()];
	});

	const uniqueImages = $derived.by(() => {
		const map = new Map<string, UniqueImage>();
		for (const asset of componentAssets) {
			if (asset.asset_type !== 'IMAGE_DIGEST') continue;
			const key = `${asset.image_registry}/${asset.image_repository}`;
			if (!map.has(key)) {
				map.set(key, {
					key,
					image_registry: asset.image_registry ?? '',
					image_repository: asset.image_repository ?? '',
					versions: []
				});
			}
			const img = map.get(key)!;
			if (asset.version && !img.versions.includes(asset.version)) img.versions.push(asset.version);
		}
		return [...map.values()];
	});

	const handleVersionClick = (version: string) => {
		selectedVersion = selectedVersion === version ? '' : version;
		loadAssets(name, ecosystem, selectedVersion);
	};

	const toggleRepo = async (repo: UniqueRepo) => {
		const next = new Set(expandedRepos);
		if (next.has(repo.key)) {
			next.delete(repo.key);
		} else {
			next.add(repo.key);
			if (repo.provider === 'github' && !repoContributors[repo.key] && !loadingContributors[repo.key]) {
				loadContributors(repo);
			}
		}
		expandedRepos = next;
	};

	const loadContributors = async (repo: UniqueRepo) => {
		loadingContributors = { ...loadingContributors, [repo.key]: true };
		try {
			const response = await fetch(`/api/providers/github/${repo.org}/${repo.slug}/details`, {
				credentials: 'include'
			});
			if (response.ok) {
				const data = await response.json();
				repoContributors = {
					...repoContributors,
					[repo.key]: (data.contributors || []).slice(0, 5)
				};
			}
		} catch {
			repoContributors = { ...repoContributors, [repo.key]: [] };
		} finally {
			loadingContributors = { ...loadingContributors, [repo.key]: false };
		}
	};
</script>

<div class="flex h-full flex-col overflow-hidden bg-[var(--bg-soft)] rounded-l-[10px]">
	<!-- Header -->
	<div class="flex shrink-0 items-center justify-between gap-2 border-b border-[var(--border-color)] px-4 py-3">
		<div class="flex min-w-0 items-center gap-2">
			<Package class="h-4 w-4 shrink-0 text-[var(--accent)]" />
			<h2 class="truncate text-sm font-semibold text-[var(--text-bright)]">{name}</h2>
			<span class="shrink-0 rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs text-[var(--text-muted)]">
				{ecosystem}
			</span>
		</div>
		<button
			type="button"
			class="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg transition hover:bg-[var(--hover-bg)]"
			onclick={onClose}
			aria-label="Close"
		>
			<X class="h-3.5 w-3.5" />
		</button>
	</div>

	{#if loading}
		<div class="flex flex-1 items-center justify-center p-6">
			<p class="text-sm text-[var(--text-secondary)]">Loading...</p>
		</div>
	{:else if componentDetail}
		<div class="flex-1 divide-y divide-[var(--border-color)]/60 overflow-y-auto">
			<!-- Versions -->
			<div class="p-4">
				<h3 class="mb-2 text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">
					Versions
				</h3>
				<div class="flex flex-wrap gap-1.5">
					{#each componentDetail.versions as v}
						<button
							type="button"
							class="rounded-full border px-2.5 py-0.5 text-xs transition {selectedVersion === v.version
								? 'border-[var(--accent)] text-[var(--accent)]'
								: 'border-[var(--border-color)] text-[var(--text-secondary)] hover:border-[var(--text-muted)]'}"
							onclick={() => handleVersionClick(v.version)}
						>
							{v.version || '(no version)'}
						</button>
					{/each}
				</div>
			</div>

			<!-- Repos / Images -->
			{#if assetsLoading}
				<div class="p-4">
					<p class="text-sm text-[var(--text-secondary)]">Loading...</p>
				</div>
			{:else}
				{#if uniqueRepos.length > 0}
					<div class="p-4">
						<h3 class="mb-2 text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">
							Repositories ({uniqueRepos.length})
						</h3>
						<div class="space-y-0.5">
							{#each uniqueRepos as repo}
								<div>
									<button
										type="button"
										class="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left transition hover:bg-[var(--hover-bg-subtle)]"
										onclick={() => toggleRepo(repo)}
									>
										<GitBranch class="h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
										<span class="flex-1 truncate text-xs text-[var(--text-bright)]">{repo.org}/{repo.slug}</span>
										<span class="shrink-0 text-[10px] text-[var(--text-muted)]">{repo.provider}</span>
										{#if expandedRepos.has(repo.key)}
											<ChevronDown class="h-3 w-3 shrink-0 text-[var(--text-muted)]" />
										{:else}
											<ChevronRight class="h-3 w-3 shrink-0 text-[var(--text-muted)]" />
										{/if}
									</button>
									{#if expandedRepos.has(repo.key)}
										<div class="ml-6 mt-1 space-y-2 pb-2">
											{#if repo.versions.length > 0}
												<p class="text-xs text-[var(--text-muted)]">
													{repo.versions.join(', ')}
												</p>
											{/if}
											{#if loadingContributors[repo.key]}
												<p class="text-xs text-[var(--text-muted)]">Loading contributors...</p>
											{:else if repoContributors[repo.key]}
												{#if repoContributors[repo.key].length > 0}
													<div>
														<p class="mb-1.5 text-xs text-[var(--text-tertiary)]">Top contributors</p>
														<div class="space-y-1.5">
															{#each repoContributors[repo.key] as c}
																<div class="flex items-center gap-2">
																	{#if c.avatar_url}
																		<img
																			src={c.avatar_url}
																			alt={c.login}
																			class="h-5 w-5 rounded-full"
																		/>
																	{:else}
																		<div
																			class="flex h-5 w-5 items-center justify-center rounded-full bg-[var(--hover-bg)]"
																		>
																			<span class="text-[9px] text-[var(--text-muted)]">
																				{(c.login || c.name || '?')[0].toUpperCase()}
																			</span>
																		</div>
																	{/if}
																	<span class="flex-1 truncate text-xs text-[var(--text-secondary)]">
																		{c.login || c.name}
																	</span>
																	<span class="text-xs text-[var(--text-muted)]">{c.contributions}</span>
																</div>
															{/each}
														</div>
													</div>
												{:else}
													<p class="text-xs text-[var(--text-muted)]">No contributor data available</p>
												{/if}
											{/if}
										</div>
									{/if}
								</div>
							{/each}
						</div>
					</div>
				{/if}

				{#if uniqueImages.length > 0}
					<div class="p-4">
						<h3 class="mb-2 text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">
							Images ({uniqueImages.length})
						</h3>
						<div class="space-y-0.5">
							{#each uniqueImages as img}
								<div class="flex items-start gap-2 rounded-lg px-2 py-1.5 hover:bg-[var(--hover-bg-subtle)]">
									<Container class="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
									<div class="min-w-0">
										<p class="truncate text-xs text-[var(--text-bright)]">{img.image_repository}</p>
										<p class="text-xs text-[var(--text-muted)]">{img.image_registry}</p>
										{#if img.versions.length > 0}
											<p class="text-xs text-[var(--text-muted)]">{img.versions.join(', ')}</p>
										{/if}
									</div>
								</div>
							{/each}
						</div>
					</div>
				{/if}

				{#if uniqueRepos.length === 0 && uniqueImages.length === 0}
					<div class="p-4">
						<p class="text-sm text-[var(--text-secondary)]">No repos or images found.</p>
					</div>
				{/if}
			{/if}
		</div>
	{/if}
</div>
