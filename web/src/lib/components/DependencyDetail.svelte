<script lang="ts">
	import { X, Package, GitBranch, Container, CheckCircle, FileCode, Microscope, AlertTriangle } from 'lucide-svelte';
	import Dialog from './Dialog.svelte';

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
		provider_base_url?: string;
		org?: string;
		slug?: string;
		commit_sha?: string;
		image_registry?: string;
		image_repository?: string;
		image_digest?: string;
		version: string;
		sbom_id?: string;
		bound_at?: string;
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

	let { 
		open = $bindable(false),
		name,
		ecosystem,
		sources
	}: {
		open: boolean;
		name: string;
		ecosystem: string;
		sources: string[];
	} = $props();

	let componentDetail: ComponentDetail | null = $state(null);
	let componentAssets: ComponentAsset[] = $state([]);
	let loading = $state(false);
	let assetsLoading = $state(false);
	let selectedVersion = $state('');

	// Load component detail when dialog opens
	$effect(() => {
		if (open && name && ecosystem) {
			loadDependencyDetail(name, ecosystem);
		}
	});

	const loadDependencyDetail = async (name: string, ecosystem: string) => {
		loading = true;
		try {
			const params = new URLSearchParams({ name, ecosystem });
			const response = await fetch(`/api/dependencies/detail?${params}`, { credentials: 'include' });
			if (response.ok) {
				componentDetail = await response.json();
				componentDetail!.sources = sources;
				selectedVersion = '';
				loadDependencyAssets(name, ecosystem, '');
			}
		} catch (e) {
			console.error('Failed to load dependency:', e);
		} finally {
			loading = false;
		}
	};

	const loadDependencyAssets = async (name: string, ecosystem: string, version: string) => {
		assetsLoading = true;
		try {
			const params = new URLSearchParams({ name, ecosystem });
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

	const handleVersionFilter = (version: string) => {
		selectedVersion = version;
		loadDependencyAssets(name, ecosystem, version);
	};

	const getSourceBadge = (sources: string[]) => {
		if (!sources || sources.length === 0) return null;
		const source = sources[0];
		
		if (source === 'both') {
			return { icon: CheckCircle, label: 'Both', class: 'bg-green-500/10 text-green-400', title: 'Found in both SBOM and manifest' };
		} else if (source === 'sbom') {
			return { icon: Microscope, label: 'SBOM', class: 'bg-blue-500/10 text-blue-400', title: 'From SBOM scanner' };
		} else {
			return { icon: FileCode, label: 'Manifest', class: 'bg-purple-500/10 text-purple-400', title: 'From manifest file' };
		}
	};

	const sourceBadge = $derived(getSourceBadge(sources));
</script>

<Dialog bind:open>
	<div class="flex min-h-0 flex-1 w-full flex-col">
		<!-- Header -->
		<div class="shrink-0 border-b border-[var(--border-color)] p-6">
			<div class="flex items-start justify-between">
				<div class="flex-1">
					<div class="flex items-center gap-3">
						<Package class="h-6 w-6 text-[var(--accent)]" />
						<div>
							<h2 class="text-xl font-semibold text-[var(--text-bright)]">{name}</h2>
							{#if componentDetail?.purl}
								<p class="mt-1 text-xs text-[var(--text-muted)]">{componentDetail.purl}</p>
							{/if}
						</div>
					</div>
					<div class="mt-3 flex flex-wrap gap-2">
						<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-2.5 py-0.5 text-xs">
							{ecosystem}
						</span>
						{#if sourceBadge}
							{@const Icon = sourceBadge.icon}
							<span class="inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs {sourceBadge.class}" title={sourceBadge.title}>
								<Icon class="h-3 w-3" />
								{sourceBadge.label}
							</span>
						{/if}
						{#if componentDetail}
							<span class="inline-flex items-center gap-1 text-xs text-[var(--text-secondary)]">
								{componentDetail.version_count} versions
							</span>
							<span class="inline-flex items-center gap-1 text-xs text-[var(--text-secondary)]">
								<GitBranch class="h-3 w-3" /> {componentDetail.repo_count} repos
							</span>
							<span class="inline-flex items-center gap-1 text-xs text-[var(--text-secondary)]">
								<Container class="h-3 w-3" /> {componentDetail.image_count} images
							</span>
						{/if}
					</div>
				</div>
			</div>
		</div>

		{#if loading}
			<div class="flex flex-1 items-center justify-center p-6">
				<p class="text-sm text-[var(--text-secondary)]">Loading details...</p>
			</div>
		{:else if componentDetail}
			<div class="flex min-h-0 flex-1 flex-col gap-4 overflow-hidden p-6 md:flex-row">
				<!-- Sidebar: Versions -->
				<div class="flex flex-col w-full shrink-0 md:w-56">
					<h3 class="mb-3 flex items-center gap-2 text-sm font-semibold text-[var(--text-bright)]">
						<Package class="h-4 w-4" />
						Versions
					</h3>
					<div class="max-h-64 space-y-1 overflow-y-auto md:max-h-none md:min-h-0 md:flex-1">
						<button
							type="button"
							class="w-full rounded-lg px-3 py-2 text-left text-sm transition {selectedVersion === '' ? 'bg-[var(--hover-bg)] font-medium text-[var(--text-bright)]' : 'text-[var(--text-secondary)] hover:bg-[var(--hover-bg-subtle)]'}"
							onclick={() => handleVersionFilter('')}
						>
							All versions
							<span class="ml-1 text-xs text-[var(--text-muted)]">({componentDetail.version_count})</span>
						</button>
						{#each componentDetail.versions as v}
							<button
								type="button"
								class="w-full rounded-lg px-3 py-2 text-left text-sm transition {selectedVersion === v.version ? 'bg-[var(--hover-bg)] font-medium text-[var(--text-bright)]' : 'text-[var(--text-secondary)] hover:bg-[var(--hover-bg-subtle)]'}"
								onclick={() => handleVersionFilter(v.version)}
							>
								<div class="flex items-center justify-between">
									<span class="truncate">{v.version || '(no version)'}</span>
									<span class="ml-2 text-xs text-[var(--text-muted)]">({v.repo_count})</span>
								</div>
							</button>
						{/each}
					</div>
				</div>

				<!-- Main content: Assets and Vulnerabilities -->
				<div class="flex-1 space-y-6 overflow-y-auto">
					<!-- Vulnerabilities placeholder -->
					<div>
						<h3 class="mb-3 flex items-center gap-2 text-sm font-semibold text-[var(--text-bright)]">
							<AlertTriangle class="h-4 w-4" />
							Vulnerabilities
							<span class="text-xs font-normal text-[var(--text-muted)]">(Coming soon)</span>
						</h3>
						<div class="rounded-lg border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
							<p class="text-sm text-[var(--text-muted)]">
								Vulnerability scanning integration coming soon. Will show CVEs, severity, and remediation guidance.
							</p>
						</div>
					</div>

					<!-- Used in repos/images -->
					<div>
						<h3 class="mb-3 flex items-center gap-2 text-sm font-semibold text-[var(--text-bright)]">
							<GitBranch class="h-4 w-4" />
							Used in
							{#if selectedVersion}
								<span class="text-xs font-normal text-[var(--text-muted)]">(version {selectedVersion})</span>
							{/if}
						</h3>
						{#if assetsLoading}
							<p class="text-sm text-[var(--text-secondary)]">Loading assets...</p>
						{:else if componentAssets.length === 0}
							<div class="rounded-lg border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
								<p class="text-sm text-[var(--text-secondary)]">No repositories or images found for this version.</p>
							</div>
						{:else}
							<div class="space-y-2">
								{#each componentAssets as asset}
									<div class="rounded-lg border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-3 transition hover:border-[var(--border-color)]">
										{#if asset.asset_type === 'REPO_COMMIT'}
											<div class="flex items-start gap-3">
												<GitBranch class="mt-0.5 h-4 w-4 shrink-0 text-[var(--accent)]" />
												<div class="min-w-0 flex-1">
													<div class="flex items-center gap-2">
														<span class="truncate font-medium text-[var(--text-bright)]">
															{asset.org}/{asset.slug}
														</span>
														<span class="shrink-0 text-xs text-[var(--text-muted)]">({asset.provider})</span>
														{#if asset.source}
															<span class="shrink-0 rounded-full px-2 py-0.5 text-xs {asset.source === 'sbom' ? 'bg-blue-500/10 text-blue-400' : 'bg-purple-500/10 text-purple-400'}">
																{asset.source}
															</span>
														{/if}
													</div>
													{#if asset.commit_sha && typeof asset.commit_sha === 'string'}
														<p class="mt-1 text-xs text-[var(--text-muted)]">
															Commit: <code class="rounded bg-[var(--hover-bg)] px-1 py-0.5">{asset.commit_sha.substring(0, 8)}</code>
														</p>
													{/if}
													{#if asset.manifest_path}
														<p class="mt-1 text-xs text-[var(--text-muted)]">
															Manifest: <code class="rounded bg-[var(--hover-bg)] px-1 py-0.5">{asset.manifest_path}</code>
															{#if asset.manifest_type}
																<span class="ml-1">({asset.manifest_type})</span>
															{/if}
														</p>
													{/if}
													{#if asset.version}
														<p class="mt-0.5 text-xs text-[var(--text-tertiary)]">
															Version: {asset.version}
															{#if asset.direct}
																<span class="ml-1 text-green-400">(direct)</span>
															{/if}
															{#if asset.scope}
																<span class="ml-1">• {asset.scope}</span>
															{/if}
														</p>
													{/if}
												</div>
											</div>
										{:else if asset.asset_type === 'IMAGE_DIGEST'}
											<div class="flex items-start gap-3">
												<Container class="mt-0.5 h-4 w-4 shrink-0 text-[var(--accent)]" />
												<div class="min-w-0 flex-1">
													<span class="truncate font-medium text-[var(--text-bright)]">
														{asset.image_repository}
													</span>
													<p class="mt-1 text-xs text-[var(--text-muted)]">
														Registry: {asset.image_registry}
													</p>
													<p class="mt-0.5 text-xs text-[var(--text-muted)]">
														Digest: <code class="rounded bg-[var(--hover-bg)] px-1 py-0.5">{asset.image_digest?.substring(0, 16)}...</code>
													</p>
													{#if asset.version}
														<p class="mt-0.5 text-xs text-[var(--text-tertiary)]">
															Version: {asset.version}
														</p>
													{/if}
												</div>
											</div>
										{/if}
									</div>
								{/each}
							</div>
						{/if}
					</div>
				</div>
			</div>
		{/if}
	</div>
</Dialog>
