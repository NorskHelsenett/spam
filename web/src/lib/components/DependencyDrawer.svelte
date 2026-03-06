<script lang="ts">
	import { browser } from '$app/environment';
	import { X, Package, GitBranch, Container, CheckCircle, Microscope, FileCode, Scale, ExternalLink, Github, Gitlab, Download } from 'lucide-svelte';
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
		provider_id?: string;
		provider_base_url?: string;
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

	type CommitInfo = {
		author_login?: string;
		author_email?: string;
		author_name?: string;
		author_date?: string;
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
		repo_id?: string;
		provider: string;
		provider_id?: string;
		provider_base_url?: string;
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
	let repoContributorsAll = $state<Record<string, Contributor[]>>({});
	let loadingContributors = $state<Record<string, boolean>>({});
	let providerInstances: ProviderInstance[] = $state([]);
	let providerInstancesLoaded = false;
	let drawerShellEl: HTMLDivElement | undefined = $state();
	let hoveredContributor: Contributor | null = $state(null);
	let contributorTipPos = $state({ x: 0, y: 0 });
	let hideTipTimer: ReturnType<typeof setTimeout> | null = null;
	let copiedEmail = $state('');
	let copiedEmailTimer: ReturnType<typeof setTimeout> | null = null;

	$effect(() => {
		if (name && ecosystem) {
			loadDetail(name, ecosystem);
			loadProviderInstances();
		}
	});

	// Auto-load contributors for visible repos
	$effect(() => {
		for (const repo of uniqueRepos) {
			if (!repoContributors[repo.key] && !loadingContributors[repo.key]) {
				loadContributors(repo);
			}
		}
	});

	$effect(() => {
		return () => {
			if (hideTipTimer) clearTimeout(hideTipTimer);
			if (copiedEmailTimer) clearTimeout(copiedEmailTimer);
		};
	});

	const resolveProviderType = (provider: string) => {
		const instance = findProviderInstance(provider);
		return instance?.type ?? provider;
	};

	const findProviderInstance = (provider: string, providerBaseURL?: string) => {
		return providerInstances.find((p) =>
			p.id === provider
			|| p.type === provider
			|| (providerBaseURL ? p.base_url === providerBaseURL : false),
		);
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
		repoContributorsAll = {};
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
				map.set(key, {
					key,
					repo_id: asset.repo_id,
					provider: asset.provider ?? '',
					provider_id: asset.provider_id,
					provider_base_url: asset.provider_base_url,
					org: asset.org ?? '',
					slug: asset.slug ?? '',
					versions: [],
					sources: [],
				});
			}
			const repo = map.get(key)!;
			if (!repo.repo_id && asset.repo_id) repo.repo_id = asset.repo_id;
			if (!repo.provider_id && asset.provider_id) repo.provider_id = asset.provider_id;
			if (!repo.provider_base_url && asset.provider_base_url) repo.provider_base_url = asset.provider_base_url;
			if (asset.version && !repo.versions.includes(asset.version)) repo.versions.push(asset.version);
			if (asset.source && !repo.sources.includes(asset.source)) repo.sources.push(asset.source);
		}
		return [...map.values()];
	});

	// Group repos by resolved provider instance
	const repoGroups = $derived.by(() => {
		const map = new Map<string, RepoGroup>();
		for (const repo of uniqueRepos) {
			const instance = findProviderInstance(repo.provider_id ?? repo.provider, repo.provider_base_url);
			const groupKey = instance?.id ?? repo.provider;
			const providerType = instance?.type ?? repo.provider;
			const baseUrl = instance?.base_url ?? repo.provider_base_url ?? (providerType === 'github' ? 'https://github.com' : providerType === 'gitlab' ? 'https://gitlab.com' : '');
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

	const handleVersionClick = (version: string) => {
		selectedVersion = selectedVersion === version ? '' : version;
		loadAssets(name, ecosystem, selectedVersion);
	};

	const loadContributors = async (repo: UniqueRepo) => {
		loadingContributors = { ...loadingContributors, [repo.key]: true };
		await loadProviderInstances();
		try {
			let url: string;
			const instance = findProviderInstance(repo.provider_id ?? repo.provider, repo.provider_base_url);
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
				const contributors = Array.isArray(data.contributors) ? (data.contributors as Contributor[]) : [];
				const commits = Array.isArray(data.commits) ? (data.commits as CommitInfo[]) : [];
				const sortedContributors = sortContributorsByLatest(contributors, commits);
				repoContributorsAll = {
					...repoContributorsAll,
					[repo.key]: sortedContributors,
				};
				repoContributors = {
					...repoContributors,
					[repo.key]: sortedContributors.slice(0, 5),
				};
			} else {
				// Mark as resolved to avoid tight retry loops on persistent non-2xx responses.
				repoContributors = { ...repoContributors, [repo.key]: [] };
				repoContributorsAll = { ...repoContributorsAll, [repo.key]: [] };
			}
		} catch {
			repoContributors = { ...repoContributors, [repo.key]: [] };
			repoContributorsAll = { ...repoContributorsAll, [repo.key]: [] };
		} finally {
			loadingContributors = { ...loadingContributors, [repo.key]: false };
		}
	};

	const sortContributorsByLatest = (contributors: Contributor[], commits: CommitInfo[]): Contributor[] => {
		if (contributors.length === 0 || commits.length === 0) return contributors;

		const norm = (s?: string) => (s || '').trim().toLowerCase();
		const lastSeen = new Map<string, number>();
		for (const commit of commits) {
			const ts = Date.parse(commit.author_date || '');
			if (!Number.isFinite(ts)) continue;
			for (const key of [norm(commit.author_login), norm(commit.author_email), norm(commit.author_name)]) {
				if (!key) continue;
				const prev = lastSeen.get(key) ?? 0;
				if (ts > prev) lastSeen.set(key, ts);
			}
		}

		return contributors
			.map((contributor, idx) => {
				const score = Math.max(
					lastSeen.get(norm(contributor.login)) ?? 0,
					lastSeen.get(norm(contributor.email)) ?? 0,
					lastSeen.get(norm(contributor.name)) ?? 0,
				);
				return { contributor, score, idx };
			})
			.sort((a, b) => b.score - a.score || a.idx - b.idx)
			.map((item) => item.contributor);
	};

	const clearHideTipTimer = () => {
		if (!hideTipTimer) return;
		clearTimeout(hideTipTimer);
		hideTipTimer = null;
	};

	const showContributorTip = (e: MouseEvent, contributor: Contributor) => {
		clearHideTipTimer();
		const target = e.currentTarget as HTMLElement | null;
		if (!target || !drawerShellEl) return;
		const anchor = target.querySelector<HTMLElement>('.contributor-avatar') ?? target;
		const rect = anchor.getBoundingClientRect();
		const shellRect = drawerShellEl.getBoundingClientRect();
		contributorTipPos = {
			x: rect.left + rect.width / 2 - shellRect.left,
			y: rect.top - shellRect.top - 10,
		};
		hoveredContributor = contributor;
	};

	const scheduleHideContributorTip = () => {
		clearHideTipTimer();
		hideTipTimer = setTimeout(() => {
			hoveredContributor = null;
		}, 120);
	};

	const copyEmail = async (contributor: Contributor) => {
		if (!contributor.email || !browser) return;
		try {
			await navigator.clipboard.writeText(contributor.email);
			copiedEmail = contributor.email;
			if (copiedEmailTimer) clearTimeout(copiedEmailTimer);
			copiedEmailTimer = setTimeout(() => {
				copiedEmail = '';
			}, 1400);
		} catch {
			// Ignore clipboard errors
		}
	};

	const spamRepoUrl = (repo: UniqueRepo): string | null => {
		if (!repo.repo_id) return null;
		return `/app/providers/repo/${encodeURIComponent(repo.repo_id)}`;
	};

	const providerRepoUrl = (repo: UniqueRepo): string => {
		const instance = findProviderInstance(repo.provider_id ?? repo.provider, repo.provider_base_url);
		const providerType = instance?.type ?? String(repo.provider || '').toLowerCase();
		const baseUrl = instance?.base_url
			?? repo.provider_base_url
			?? (providerType === 'github' ? 'https://github.com'
				: providerType === 'gitlab' ? 'https://gitlab.com'
					: '');
		const path = `${repo.org}/${repo.slug}`;
		if (!baseUrl) return path;
		return `${baseUrl.replace(/\/$/, '')}/${path}`;
	};

	const spamRepoExportUrl = (repo: UniqueRepo): string => {
		const instance = findProviderInstance(repo.provider_id ?? repo.provider, repo.provider_base_url);
		const providerType = instance?.type ?? String(repo.provider || '').toLowerCase();
		const repoPath = `${repo.org}/${repo.slug}`;
		let path = '';
		if (providerType && repo.org && repo.slug) {
			path = `/app/providers/repo?provider=${providerType}&path=${repoPath}`;
			if (instance?.base_url) path += `&base_url=${instance.base_url}`;
		} else {
			path = spamRepoUrl(repo) ?? '';
		}
		if (!path) return '';
		if (browser && window.location?.origin) return `${window.location.origin}${path}`;
		return path;
	};

	const handleRepoLinkClick = (event: MouseEvent, url: string) => {
		event.stopPropagation();
		if (!browser) return;
		if (event.metaKey || event.ctrlKey) {
			event.preventDefault();
			window.open(url, '_blank', 'noopener,noreferrer');
		}
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
		const safe = name.replace(/[^a-z0-9\-_.]/gi, '_');
		const rows = [['package', 'ecosystem', 'version', 'source', 'repo_url', 'spam_url', 'contributor_emails']];
		for (const repo of uniqueRepos) {
			const contributorEmails = [...new Set((repoContributorsAll[repo.key] ?? []).map((c) => c.email).filter((e): e is string => Boolean(e && e.trim())))]
				.join(';');
			const repoUrl = providerRepoUrl(repo);
			const spamUrl = spamRepoExportUrl(repo);
			const versions = repo.versions.length > 0 ? repo.versions : [''];
			for (const v of versions) {
				rows.push([name, ecosystem, v, repo.sources.join('+'), repoUrl, spamUrl, contributorEmails]);
			}
		}
		downloadFile(rows.map(toCsvRow).join('\n'), `${safe}-${ecosystem}-info.csv`);
	};
</script>

<div class="relative h-full" bind:this={drawerShellEl}>
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

			<!-- Export button -->
			{#if componentDetail}
				<button type="button"
					class="shrink-0 inline-flex items-center gap-1.5 rounded-[999px] border border-[var(--border-color)] bg-[var(--hover-bg)] px-3 py-[0.4rem] text-[0.75rem] font-semibold tracking-[0.02em] text-[var(--text-bright)] transition hover:brightness-110"
					onclick={exportPackageInfo} title="Export package info as CSV">
					<Download class="h-3 w-3" /> Export
				</button>
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
										{@const url = spamRepoUrl(repo)}
										{@const contributors = repoContributors[repo.key] ?? []}
										{@const isLoadingC = loadingContributors[repo.key]}
										<div class="rounded-lg px-2 py-2 transition hover:bg-[var(--hover-bg-subtle)]">
											<!-- Row 1: repo name + external link -->
											<div class="flex items-center gap-2">
												<span class="min-w-0 flex-1 truncate text-sm">
													<span class="text-[var(--text-muted)]">{repo.org}/</span><span class="font-medium text-[var(--text-bright)]">{repo.slug}</span>
												</span>
												{#if url}
													<a href={url}
														class="shrink-0 rounded p-0.5 text-[var(--text-muted)] transition hover:text-[var(--accent)]"
														title="Open in SPAM" onclick={(e) => handleRepoLinkClick(e, url)}>
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
															<div
																class="contributor-wrap"
																onmouseenter={(e) => showContributorTip(e, c)}
																onmouseleave={scheduleHideContributorTip}
															>
																{#if c.avatar_url}
																	<img src={c.avatar_url} alt={c.login || c.name || ''} class="contributor-avatar h-5 w-5 rounded-full ring-1 ring-[var(--bg-soft)]" />
																{:else}
																	<div class="contributor-avatar flex h-5 w-5 items-center justify-center rounded-full bg-[var(--hover-bg)] text-[8px] font-semibold text-[var(--text-muted)] ring-1 ring-[var(--bg-soft)]">
																		{(c.login || c.name || '?')[0].toUpperCase()}
																	</div>
																{/if}
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

{#if hoveredContributor}
	{#key `${hoveredContributor.login || hoveredContributor.name || ''}:${hoveredContributor.email || ''}`}
		<div
			class="contributor-tip-layer"
			style={`left:${contributorTipPos.x}px;top:${contributorTipPos.y}px;`}
			onmouseenter={clearHideTipTimer}
			onmouseleave={scheduleHideContributorTip}
		>
			<button
				type="button"
				class="tip-card"
				onclick={() => copyEmail(hoveredContributor!)}
				disabled={!hoveredContributor.email}
				title={hoveredContributor.email ? 'Click to copy email' : 'No email available'}
			>
				{#if hoveredContributor.avatar_url}
					<img src={hoveredContributor.avatar_url} alt={hoveredContributor.login || hoveredContributor.name || ''} class="mb-2 h-12 w-12 rounded-full" />
				{:else}
					<div class="mb-2 flex h-12 w-12 items-center justify-center rounded-full bg-[var(--hover-bg)] text-base font-semibold text-[var(--text-secondary)]">
						{(hoveredContributor.login || hoveredContributor.name || '?')[0].toUpperCase()}
					</div>
				{/if}
				<p class="text-[12px] font-semibold text-[var(--text-bright)]">{hoveredContributor.login || hoveredContributor.name || '—'}</p>
				{#if hoveredContributor.email}
					<p class="mt-0.5 w-full break-all text-[11px] text-[var(--text-muted)]">{hoveredContributor.email}</p>
					<p class="mt-1 text-[10px] text-[var(--text-tertiary)]">{copiedEmail === hoveredContributor.email ? 'Copied' : 'Click to copy email'}</p>
				{:else}
					<p class="mt-1 text-[10px] text-[var(--text-tertiary)]">No email available</p>
				{/if}
			</button>
		</div>
	{/key}
{/if}
</div>

<style>
	.contributor-wrap {
		position: relative;
		cursor: default;
	}

	.contributor-tip-layer {
		position: absolute;
		z-index: 1200;
		transform: translate(-50%, calc(-100% + 6px)) scale(0.9) rotate(5deg);
		pointer-events: auto;
		opacity: 0;
		animation: contributor-tip-in 180ms cubic-bezier(0.34, 1.56, 0.64, 1) forwards;
		transform-origin: bottom center;
		will-change: transform, opacity;
	}

	.tip-card {
		width: 14rem;
		background: var(--bg-soft);
		border: 1px solid var(--border-color);
		border-radius: 0.75rem;
		padding: 0.75rem;
		box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
		text-align: center;
		display: flex;
		flex-direction: column;
		align-items: center;
		cursor: pointer;
	}

	.tip-card:disabled {
		cursor: default;
	}

	@keyframes contributor-tip-in {
		from {
			opacity: 0;
			transform: translate(-50%, calc(-100% + 6px)) scale(0.9) rotate(5deg);
		}
		to {
			opacity: 1;
			transform: translate(-50%, -100%) scale(1) rotate(-2deg);
		}
	}
</style>
