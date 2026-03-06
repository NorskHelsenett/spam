<script lang="ts">
	import { browser } from '$app/environment';
	import { X, Package, GitBranch, Container, CheckCircle, Microscope, FileCode, Scale, ExternalLink, Github, Gitlab, Download, ChevronDown } from 'lucide-svelte';
	import Gitea from '$lib/components/icons/Gitea.svelte';

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
		licenses?: string[];
	};

	type Contributor = {
		login: string;
		name?: string;
		email?: string;
		avatar_url?: string;
		profile_url?: string;
		contributions: number;
	};

	type ProviderInstance = {
		id: string;
		name: string;
		type: string;
		base_url: string;
		owner_path?: string;
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

	type RepoGroup = {
		key: string;
		type: string;
		label: string;
		repos: UniqueRepo[];
	};

	let {
		name,
		ecosystem,
		sources = [],
		onClose = () => {}
	}: {
		name: string;
		ecosystem: string;
		sources?: string[];
		onClose?: () => void;
	} = $props();

	const sourceBadge = $derived.by(() => {
		const source = sources[0];
		if (source === 'both') return { icon: CheckCircle, label: 'Both', cls: 'bg-green-500/10 text-green-400', title: 'Found in both SBOM and manifest' };
		if (source === 'sbom') return { icon: Microscope, label: 'SBOM', cls: 'bg-blue-500/10 text-blue-400', title: 'From SBOM scanner' };
		if (source === 'manifest') return { icon: FileCode, label: 'Manifest', cls: 'bg-purple-500/10 text-purple-400', title: 'From manifest file' };
		return null;
	});

	const sourceInfo = (source: string) => {
		if (source === 'both') return { icon: CheckCircle, label: 'Both', cls: 'bg-green-500/10 text-green-400' };
		if (source === 'sbom') return { icon: Microscope, label: 'SBOM', cls: 'bg-blue-500/10 text-blue-400' };
		if (source === 'manifest') return { icon: FileCode, label: 'Manifest', cls: 'bg-purple-500/10 text-purple-400' };
		return null;
	};

	const parseSemver = (v: string): number[] =>
		v.replace(/^v/, '').split(/[.\-+]/).map((p) => parseInt(p, 10) || 0);

	const compareSemver = (a: string, b: string): number => {
		const pa = parseSemver(a);
		const pb = parseSemver(b);
		for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
			const diff = (pb[i] ?? 0) - (pa[i] ?? 0);
			if (diff !== 0) return diff;
		}
		return 0;
	};

	let componentDetail: ComponentDetail | null = $state(null);
	let componentAssets: ComponentAsset[] = $state([]);
	let loading = $state(false);
	let assetsLoading = $state(false);
	let selectedVersion = $state('');
	let repoContributors = $state<Record<string, Contributor[]>>({});
	let loadingContributors = $state<Record<string, boolean>>({});
	let providerInstances: ProviderInstance[] = $state([]);
	let providerInstancesLoaded = false;
	let exportDropdownOpen = $state(false);
	let exportBtnEl: HTMLDivElement | undefined = $state();

	$effect(() => {
		if (name && ecosystem) {
			loadDetail(name, ecosystem);
			loadProviderInstances();
		}
	});

	// Auto-load contributors for visible repos
	$effect(() => {
		for (const repo of uniqueRepos.slice(0, 10)) {
			if (!repoContributors[repo.key] && !loadingContributors[repo.key]) {
				loadContributors(repo);
			}
		}
	});

	// Close export dropdown on outside click
	$effect(() => {
		if (!exportDropdownOpen || !browser) return;
		const handler = (e: MouseEvent) => {
			if (exportBtnEl && !exportBtnEl.contains(e.target as Node)) exportDropdownOpen = false;
		};
		document.addEventListener('mousedown', handler);
		return () => document.removeEventListener('mousedown', handler);
	});

	const resolveProviderType = (provider: string) => {
		const instance = providerInstances.find((p) => p.id === provider || p.type === provider);
		return instance?.type ?? provider;
	};

	const loadProviderInstances = async () => {
		if (providerInstancesLoaded) return;
		providerInstancesLoaded = true;
		try {
			const response = await fetch('/api/providers/instances', { credentials: 'include' });
			if (response.ok) providerInstances = await response.json();
		} catch { /* ignore */ }
	};

	const loadDetail = async (depName: string, depEcosystem: string) => {
		loading = true;
		componentDetail = null;
		componentAssets = [];
		selectedVersion = '';
		repoContributors = {};
		try {
			const params = new URLSearchParams({ name: depName, ecosystem: depEcosystem });
			const response = await fetch(`/api/dependencies/detail?${params}`, { credentials: 'include' });
			if (response.ok) {
				componentDetail = await response.json();
				loadAssets(depName, depEcosystem, '');
			}
		} catch { /* ignore */ } finally {
			loading = false;
		}
	};

	const loadAssets = async (depName: string, depEcosystem: string, version: string) => {
		assetsLoading = true;
		try {
			const params = new URLSearchParams({ name: depName, ecosystem: depEcosystem });
			if (version) params.set('version', version);
			const primarySource = sources[0];
			if (primarySource === 'sbom' || primarySource === 'manifest') params.set('source', primarySource);
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

	const sortedVersions = $derived.by(() =>
		[...(componentDetail?.versions ?? [])].sort((a, b) => compareSemver(a.version, b.version))
	);

	const uniqueRepos = $derived.by(() => {
		const map = new Map<string, UniqueRepo>();
		for (const asset of componentAssets) {
			if (asset.asset_type !== 'REPO_COMMIT') continue;
			const key = `${asset.provider}:${asset.org}:${asset.slug}`;
			if (!map.has(key)) {
				map.set(key, { key, provider: asset.provider ?? '', org: asset.org ?? '', slug: asset.slug ?? '', versions: [], sources: [] });
			}
			const repo = map.get(key)!;
			if (asset.version && !repo.versions.includes(asset.version)) repo.versions.push(asset.version);
			if (asset.source && !repo.sources.includes(asset.source)) repo.sources.push(asset.source);
		}
		return [...map.values()];
	});

	// Group repos by resolved provider instance
	const repoGroups = $derived.by(() => {
		const map = new Map<string, RepoGroup>();
		for (const repo of uniqueRepos) {
			const instance = providerInstances.find((p) => p.id === repo.provider || p.type === repo.provider);
			const groupKey = instance?.id ?? repo.provider;
			const providerType = instance?.type ?? repo.provider;
			const baseUrl = instance?.base_url ?? (providerType === 'github' ? 'https://github.com' : providerType === 'gitlab' ? 'https://gitlab.com' : '');
			const label = baseUrl.replace(/^https?:\/\//, '');
			if (!map.has(groupKey)) map.set(groupKey, { key: groupKey, type: providerType, label, repos: [] });
			map.get(groupKey)!.repos.push(repo);
		}
		return [...map.values()];
	});

	const uniqueImages = $derived.by(() => {
		const map = new Map<string, UniqueImage>();
		for (const asset of componentAssets) {
			if (asset.asset_type !== 'IMAGE_DIGEST') continue;
			const key = `${asset.image_registry}/${asset.image_repository}`;
			if (!map.has(key)) {
				map.set(key, { key, image_registry: asset.image_registry ?? '', image_repository: asset.image_repository ?? '', versions: [] });
			}
			const img = map.get(key)!;
			if (asset.version && !img.versions.includes(asset.version)) img.versions.push(asset.version);
		}
		return [...map.values()];
	});

	const hasContributorEmails = $derived(
		Object.values(repoContributors).some((cs: Contributor[]) => cs.some((c) => c.email))
	);

	const handleVersionClick = (version: string) => {
		selectedVersion = selectedVersion === version ? '' : version;
		loadAssets(name, ecosystem, selectedVersion);
	};

	const loadContributors = async (repo: UniqueRepo) => {
		loadingContributors = { ...loadingContributors, [repo.key]: true };
		await loadProviderInstances();
		try {
			let url: string;
			const instance = providerInstances.find((p) => p.id === repo.provider || p.type === repo.provider);
			const providerType = instance?.type ?? repo.provider;
			if (providerType === 'github') {
				url = `/api/providers/github/${repo.org}/${repo.slug}/details`;
			} else if (providerType === 'gitlab') {
				if (!instance) { repoContributors = { ...repoContributors, [repo.key]: [] }; return; }
				url = `/api/providers/gitlab/${encodeURIComponent(`${repo.org}/${repo.slug}`)}/details?base_url=${encodeURIComponent(instance.base_url)}`;
			} else if (providerType === 'gitea') {
				if (!instance) { repoContributors = { ...repoContributors, [repo.key]: [] }; return; }
				url = `/api/providers/gitea/${repo.org}/${repo.slug}/details?base_url=${encodeURIComponent(instance.base_url)}`;
			} else {
				repoContributors = { ...repoContributors, [repo.key]: [] };
				return;
			}
			const response = await fetch(url, { credentials: 'include' });
			if (response.ok) {
				const data = await response.json();
				repoContributors = { ...repoContributors, [repo.key]: (data.contributors || []).slice(0, 5) };
			} else {
				// Mark as resolved to avoid tight retry loops on persistent non-2xx responses.
				repoContributors = { ...repoContributors, [repo.key]: [] };
			}
		} catch {
			repoContributors = { ...repoContributors, [repo.key]: [] };
		} finally {
			loadingContributors = { ...loadingContributors, [repo.key]: false };
		}
	};

	const repoUrl = (repo: UniqueRepo): string | null => {
		const instance = providerInstances.find((p) => p.id === repo.provider || p.type === repo.provider);
		const providerType = instance?.type ?? repo.provider;
		if (providerType === 'github') return `https://github.com/${repo.org}/${repo.slug}`;
		if (instance?.base_url) return `${instance.base_url.replace(/\/$/, '')}/${repo.org}/${repo.slug}`;
		return null;
	};

	const packageUrl = $derived.by(() => {
		const eco = ecosystem.toLowerCase();
		if (eco === 'npm') return `https://www.npmjs.com/package/${name}`;
		if (eco === 'pypi') return `https://pypi.org/project/${name}`;
		if (eco === 'nuget') return `https://www.nuget.org/packages/${name}`;
		if (eco === 'go') return `https://pkg.go.dev/${name}`;
		if (eco === 'cargo' || eco === 'crates.io') return `https://crates.io/crates/${name}`;
		if (eco === 'rubygems' || eco === 'gem') return `https://rubygems.org/gems/${name}`;
		if (eco === 'maven' || eco === 'gradle') {
			const parts = name.split(':');
			if (parts.length === 2) return `https://mvnrepository.com/artifact/${parts[0]}/${parts[1]}`;
		}
		return null;
	});

	// ── Exports ────────────────────────────────────────────────────────────────
	const downloadFile = (content: string, filename: string) => {
		const blob = new Blob([content], { type: 'text/csv' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url; a.download = filename;
		document.body.appendChild(a); a.click();
		document.body.removeChild(a); URL.revokeObjectURL(url);
	};

	const toCsvRow = (fields: unknown[]) =>
		fields.map((f) => `"${String(f ?? '').replace(/"/g, '""')}"`).join(',');

	const exportPackageInfo = () => {
		exportDropdownOpen = false;
		const safe = name.replace(/[^a-z0-9\-_.]/gi, '_');
		const rows = [['package', 'ecosystem', 'version', 'repo', 'provider', 'source']];
		for (const repo of uniqueRepos) {
			const versions = repo.versions.length > 0 ? repo.versions : [''];
			for (const v of versions) {
				rows.push([name, ecosystem, v, `${repo.org}/${repo.slug}`, resolveProviderType(repo.provider), repo.sources.join('+')]);
			}
		}
		downloadFile(rows.map(toCsvRow).join('\n'), `${safe}-${ecosystem}-info.csv`);
	};

	const exportContributorEmails = () => {
		exportDropdownOpen = false;
		const safe = name.replace(/[^a-z0-9\-_.]/gi, '_');
		const rows = [['name', 'login', 'email', 'repository', 'contributions']];
		for (const repo of uniqueRepos) {
			for (const c of repoContributors[repo.key] ?? []) {
				rows.push([c.name ?? '', c.login ?? '', c.email ?? '', `${repo.org}/${repo.slug}`, c.contributions]);
			}
		}
		downloadFile(rows.map(toCsvRow).join('\n'), `${safe}-contributors.csv`);
	};
</script>

<div class="flex h-full flex-col overflow-hidden rounded-l-[10px] bg-[var(--bg-soft)]">
	<!-- Header -->
	<div class="shrink-0 border-b border-[var(--border-color)] p-5">
		<div class="flex items-start gap-3">
			<Package class="mt-0.5 h-5 w-5 shrink-0 text-[var(--accent)]" />
			<div class="min-w-0 flex-1">
				<div class="flex items-center gap-2">
					<h2 class="truncate text-base font-semibold text-[var(--text-bright)]">{name}</h2>
					{#if packageUrl}
						<a href={packageUrl} target="_blank" rel="noopener noreferrer"
							class="shrink-0 text-[var(--text-muted)] transition hover:text-[var(--accent)]"
							title="View on {ecosystem} registry">
							<ExternalLink class="h-3.5 w-3.5" />
						</a>
					{/if}
				</div>
				{#if componentDetail?.purl}
					<p class="mt-0.5 truncate font-mono text-[11px] text-[var(--text-muted)]">{componentDetail.purl}</p>
				{/if}
				<div class="mt-2.5 flex flex-wrap gap-1.5">
					<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-2.5 py-0.5 text-[11px] text-[var(--text-secondary)]">
						{ecosystem}
					</span>
					{#if sourceBadge}
						{@const Icon = sourceBadge.icon}
						<span class="inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[11px] {sourceBadge.cls}" title={sourceBadge.title}>
							<Icon class="h-3 w-3" />{sourceBadge.label}
						</span>
					{/if}
					{#if componentDetail?.licenses?.length}
						<span class="inline-flex items-center gap-1 rounded-full bg-amber-500/10 px-2.5 py-0.5 text-[11px] text-amber-400">
							<Scale class="h-3 w-3" />{componentDetail.licenses.join(', ')}
						</span>
					{/if}
				</div>
				{#if componentDetail}
					<div class="mt-2 flex items-center gap-4">
						<span class="text-[11px] text-[var(--text-muted)]">
							<span class="font-medium text-[var(--text-secondary)]">{componentDetail.version_count}</span> versions
						</span>
						<span class="flex items-center gap-1 text-[11px] text-[var(--text-muted)]">
							<GitBranch class="h-3 w-3" />
							<span class="font-medium text-[var(--text-secondary)]">{componentDetail.repo_count}</span> repos
						</span>
						<span class="flex items-center gap-1 text-[11px] text-[var(--text-muted)]">
							<Container class="h-3 w-3" />
							<span class="font-medium text-[var(--text-secondary)]">{componentDetail.image_count}</span> images
						</span>
					</div>
				{/if}
			</div>

			<!-- Export split button -->
			{#if componentDetail}
				<div class="relative shrink-0" bind:this={exportBtnEl}>
					<div class="flex overflow-hidden rounded-[999px] border border-[var(--border-color)] bg-[var(--hover-bg)]">
						<button type="button"
							class="flex items-center gap-1.5 px-3 py-[0.4rem] text-[0.75rem] font-semibold tracking-[0.02em] text-[var(--text-bright)] transition hover:brightness-110"
							onclick={exportPackageInfo} title="Export package info as CSV">
							<Download class="h-3 w-3" /> Export
						</button>
						<div class="w-px self-stretch bg-[var(--border-color)]"></div>
						<button type="button"
							class="flex items-center bg-black/[0.06] px-2 py-[0.4rem] text-[var(--text-bright)] transition hover:bg-black/[0.12]"
							onclick={() => (exportDropdownOpen = !exportDropdownOpen)} aria-label="More export options">
							<ChevronDown class="h-3 w-3" />
						</button>
					</div>
					{#if exportDropdownOpen}
						<div class="absolute right-0 top-full z-30 mt-1 w-52 overflow-hidden rounded-xl border border-[var(--border-color)] bg-[var(--bg-soft)] py-1 shadow-xl">
							<button type="button"
								class="flex w-full items-center gap-2 px-3.5 py-2.5 text-left text-[12px] text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)]"
								onclick={exportPackageInfo}>
								<Download class="h-3 w-3 shrink-0 text-[var(--accent)]" />
								Package info (CSV)
							</button>
							<button type="button"
								class="flex w-full items-center gap-2 px-3.5 py-2.5 text-left text-[12px] transition {hasContributorEmails ? 'text-[var(--text-secondary)] hover:bg-[var(--hover-bg)]' : 'cursor-not-allowed text-[var(--text-muted)] opacity-50'}"
								onclick={exportContributorEmails} disabled={!hasContributorEmails}
								title={hasContributorEmails ? '' : 'No contributor emails loaded yet'}>
								<Download class="h-3 w-3 shrink-0 text-[var(--accent)]" />
								Contributor emails (CSV)
							</button>
						</div>
					{/if}
				</div>
			{/if}

			<button type="button"
				class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition hover:bg-[var(--hover-bg)]"
				onclick={onClose} aria-label="Close">
				<X size={18} stroke-width={2} />
			</button>
		</div>
	</div>

	{#if loading}
		<div class="flex flex-1 items-center justify-center p-8">
			<p class="text-sm text-[var(--text-secondary)]">Loading...</p>
		</div>
	{:else if componentDetail}
		<div class="flex-1 overflow-y-auto">
			<!-- Version filter -->
			<div class="border-b border-[var(--border-color)]/60 px-4 py-3">
				<div class="flex flex-wrap gap-1.5">
					<button type="button"
						class="rounded-full border px-2.5 py-0.5 text-[11px] transition {selectedVersion === '' ? 'border-[var(--accent)] text-[var(--accent)]' : 'border-[var(--border-color)] text-[var(--text-muted)] hover:border-[var(--text-muted)]'}"
						onclick={() => handleVersionClick('')}>All</button>
					{#each sortedVersions as v}
						<button type="button"
							class="rounded-full border px-2.5 py-0.5 text-[11px] transition {selectedVersion === v.version ? 'border-[var(--accent)] text-[var(--accent)]' : 'border-[var(--border-color)] text-[var(--text-muted)] hover:border-[var(--text-muted)]'}"
							onclick={() => handleVersionClick(v.version)}>
							{v.version || '(no version)'}
						</button>
					{/each}
				</div>
			</div>

			{#if assetsLoading}
				<div class="space-y-4 p-4">
					{#each [1, 2] as _}
						<div>
							<div class="mb-2 h-3 w-24 rounded bg-[var(--hover-bg)]"></div>
							<div class="space-y-1.5">
								{#each [1, 2, 3] as __}
									<div class="flex items-center gap-3 rounded-lg px-3 py-2.5">
										<div class="h-3.5 w-3.5 rounded bg-[var(--hover-bg)]"></div>
										<div class="h-3 flex-1 rounded bg-[var(--hover-bg)]"></div>
										<div class="h-4 w-12 rounded-md bg-[var(--hover-bg)]"></div>
										<div class="flex -space-x-1">
											{#each [1, 2, 3] as ___}
												<div class="h-6 w-6 animate-pulse rounded-full bg-[var(--hover-bg)]"></div>
											{/each}
										</div>
									</div>
								{/each}
							</div>
						</div>
					{/each}
				</div>
			{:else}
				<!-- Repos grouped by provider -->
				{#if uniqueRepos.length > 0}
					<div class="divide-y divide-[var(--border-color)]/40">
						{#each repoGroups as group}
							<div class="px-4 py-3">
								<!-- Provider header -->
								<div class="mb-2 flex items-center gap-2">
									{#if group.type === 'github'}
										<Github class="h-3.5 w-3.5 shrink-0 text-[var(--text-muted)]" />
									{:else if group.type === 'gitlab'}
										<Gitlab class="h-3.5 w-3.5 shrink-0 text-[var(--text-muted)]" />
									{:else}
										<span class="text-[var(--text-muted)]"><Gitea size={14} /></span>
									{/if}
									<span class="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">
										{group.type === 'github' ? 'GitHub' : group.type === 'gitlab' ? 'GitLab' : group.type === 'gitea' ? 'Gitea' : group.type}
									</span>
									{#if group.label}
										<span class="text-[10px] text-[var(--text-muted)] opacity-70">· {group.label}</span>
									{/if}
									<span class="ml-auto text-[10px] text-[var(--text-muted)]">{group.repos.length}</span>
								</div>

								<!-- Repo rows -->
								<div class="space-y-0.5">
									{#each group.repos as repo}
										{@const url = repoUrl(repo)}
										{@const contributors = repoContributors[repo.key] ?? []}
										{@const isLoadingC = loadingContributors[repo.key]}
										<div class="rounded-lg px-2 py-2 transition hover:bg-[var(--hover-bg-subtle)]">
											<!-- Row 1: repo name + external link -->
											<div class="flex items-center gap-2">
												<span class="min-w-0 flex-1 truncate text-sm">
													<span class="text-[var(--text-muted)]">{repo.org}/</span><span class="font-medium text-[var(--text-bright)]">{repo.slug}</span>
												</span>
												{#if url}
													<a href={url} target="_blank" rel="noopener noreferrer"
														class="shrink-0 rounded p-0.5 text-[var(--text-muted)] transition hover:text-[var(--accent)]"
														title="Open repository" onclick={(e) => e.stopPropagation()}>
														<ExternalLink class="h-3 w-3" />
													</a>
												{/if}
											</div>

											<!-- Row 2: version + source badges -->
											<div class="mt-1.5 flex flex-wrap gap-1">
												{#each repo.versions as v}
													<span class="inline-flex items-center rounded-md bg-[var(--hover-bg)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--text-secondary)]">{v}</span>
												{/each}
												{#each repo.sources as s}
													{@const info = sourceInfo(s)}
													{#if info}
														{@const Icon = info.icon}
														<span class="inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[10px] {info.cls}">
															<Icon class="h-2.5 w-2.5" />{info.label}
														</span>
													{/if}
												{/each}
											</div>

											<!-- Row 3: contributor avatars with tooltips -->
											{#if isLoadingC}
												<div class="mt-2 flex -space-x-1">
													{#each [1, 2, 3] as _}
														<div class="h-5 w-5 animate-pulse rounded-full bg-[var(--hover-bg)] ring-1 ring-[var(--bg-soft)]"></div>
													{/each}
												</div>
											{:else if contributors.length > 0}
												<div class="mt-2 flex items-center gap-2">
													<div class="flex -space-x-1.5">
														{#each contributors as c}
															<div class="contributor-wrap">
																{#if c.avatar_url}
																	<img src={c.avatar_url} alt={c.login || c.name || ''} class="h-5 w-5 rounded-full ring-1 ring-[var(--bg-soft)]" />
																{:else}
																	<div class="flex h-5 w-5 items-center justify-center rounded-full bg-[var(--hover-bg)] text-[8px] font-semibold text-[var(--text-muted)] ring-1 ring-[var(--bg-soft)]">
																		{(c.login || c.name || '?')[0].toUpperCase()}
																	</div>
																{/if}
																<!-- Inclined tooltip -->
																<div class="contributor-tip">
																	<div class="tip-card">
																		{#if c.avatar_url}
																			<img src={c.avatar_url} alt={c.login || c.name || ''} class="mb-2 h-10 w-10 rounded-full" />
																		{:else}
																			<div class="mb-2 flex h-10 w-10 items-center justify-center rounded-full bg-[var(--hover-bg)] text-base font-semibold text-[var(--text-secondary)]">
																				{(c.login || c.name || '?')[0].toUpperCase()}
																			</div>
																		{/if}
																		<p class="text-[12px] font-semibold text-[var(--text-bright)]">{c.login || c.name || '—'}</p>
																		{#if c.email}
																			<p class="mt-0.5 text-[10px] text-[var(--text-muted)]">{c.email}</p>
																		{/if}
																		<p class="mt-1 text-[10px] text-[var(--text-tertiary)]">{c.contributions} commits</p>
																	</div>
																</div>
															</div>
														{/each}
													</div>
													<span class="text-[10px] text-[var(--text-muted)]">
														{contributors[0].login || contributors[0].name}{contributors.length > 1 ? ` +${contributors.length - 1}` : ''}
													</span>
												</div>
											{/if}
										</div>
									{/each}
								</div>
							</div>
						{/each}
					</div>
				{/if}

				<!-- Images -->
				{#if uniqueImages.length > 0}
					<div class="border-t border-[var(--border-color)]/40 px-4 py-3">
						<div class="mb-2 flex items-center gap-2">
							<Container class="h-3.5 w-3.5 shrink-0 text-[var(--text-muted)]" />
							<span class="text-[11px] font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Images</span>
							<span class="ml-auto text-[10px] text-[var(--text-muted)]">{uniqueImages.length}</span>
						</div>
						<div class="space-y-0.5">
							{#each uniqueImages as img}
								<div class="rounded-lg px-2 py-2 transition hover:bg-[var(--hover-bg-subtle)]">
									<div class="flex items-center gap-2">
										<span class="min-w-0 flex-1 truncate text-sm font-medium text-[var(--text-bright)]">{img.image_repository}</span>
									</div>
									<div class="mt-1 flex flex-wrap items-center gap-1.5">
										<span class="text-[10px] text-[var(--text-muted)]">{img.image_registry}</span>
										{#each img.versions as v}
											<span class="inline-flex items-center rounded-md bg-[var(--hover-bg)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--text-secondary)]">{v}</span>
										{/each}
									</div>
								</div>
							{/each}
						</div>
					</div>
				{/if}

				{#if uniqueRepos.length === 0 && uniqueImages.length === 0}
					<div class="flex flex-col items-center justify-center gap-2 p-10 text-center">
						<Package class="h-8 w-8 text-[var(--border-color)]" />
						<p class="text-sm text-[var(--text-secondary)]">No usage found</p>
						<p class="text-[11px] text-[var(--text-muted)]">
							{selectedVersion ? `No repos or images use version ${selectedVersion}.` : 'This package has no tracked repositories or images.'}
						</p>
					</div>
				{/if}
			{/if}
		</div>
	{/if}
</div>

<style>
	.contributor-wrap {
		position: relative;
		cursor: default;
	}

	.contributor-tip {
		position: absolute;
		bottom: calc(100% + 8px);
		left: 50%;
		transform: translateX(-50%);
		pointer-events: none;
		z-index: 50;
		opacity: 0;
		transition: opacity 0.15s ease, transform 0.2s cubic-bezier(0.34, 1.56, 0.64, 1);
		transform-origin: bottom center;
		transform: translateX(-50%) translateY(4px) scale(0.85) rotate(4deg);
	}

	.contributor-wrap:hover .contributor-tip {
		opacity: 1;
		transform: translateX(-50%) translateY(0) scale(1) rotate(-2deg);
	}

	.tip-card {
		width: 9rem;
		background: var(--bg-soft);
		border: 1px solid var(--border-color);
		border-radius: 0.75rem;
		padding: 0.75rem;
		box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
		text-align: center;
	}
</style>
