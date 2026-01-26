<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { Search, Package, GitBranch, Container, ChevronRight, X } from 'lucide-svelte';
	import Dialog from '$lib/components/Dialog.svelte';

	type ComponentSummary = {
		id: string;
		name: string;
		ecosystem: string;
		purl?: string;
		version_count: number;
		repo_count: number;
		image_count: number;
		created_at: string;
	};

	type VersionSummary = {
		id: string;
		version: string;
		repo_count: number;
		created_at: string;
	};

	type ComponentDetail = ComponentSummary & {
		versions: VersionSummary[];
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
		sbom_id: string;
		bound_at: string;
	};

	let components: ComponentSummary[] = $state([]);
	let ecosystems: string[] = $state([]);
	let loading = $state(true);
	let error = $state('');
	let searchQuery = $state('');
	let selectedEcosystem = $state('');
	let page = $state(1);
	let totalCount = $state(0);
	let pageSize = $state(50);

	// Detail dialog state
	let detailOpen = $state(false);
	let selectedComponent: ComponentDetail | null = $state(null);
	let componentAssets: ComponentAsset[] = $state([]);
	let assetsLoading = $state(false);
	let selectedVersion = $state('');

	let searchTimeout: ReturnType<typeof setTimeout> | null = null;

	const loadEcosystems = async () => {
		try {
			const response = await fetch('/api/components/ecosystems', { credentials: 'include' });
			if (response.ok) {
				const data = await response.json();
				ecosystems = data.ecosystems || [];
			}
		} catch {
			// Ignore ecosystem load errors
		}
	};

	const loadComponents = async () => {
		loading = true;
		error = '';
		try {
			const params = new URLSearchParams();
			if (searchQuery) params.set('q', searchQuery);
			if (selectedEcosystem) params.set('ecosystem', selectedEcosystem);
			params.set('page', String(page));
			params.set('page_size', String(pageSize));

			const response = await fetch(`/api/components?${params}`, { credentials: 'include' });
			if (!response.ok) {
				error = response.status === 401 ? 'Please log in.' : 'Failed to load components.';
				components = [];
				return;
			}
			const data = await response.json();
			components = data.components || [];
			totalCount = data.total || 0;
		} catch {
			error = 'Failed to load components.';
		} finally {
			loading = false;
		}
	};

	const loadComponentDetail = async (componentId: string) => {
		try {
			const response = await fetch(`/api/components/${componentId}`, { credentials: 'include' });
			if (response.ok) {
				selectedComponent = await response.json();
				selectedVersion = '';
				detailOpen = true;
				loadComponentAssets(componentId, '');
			}
		} catch {
			error = 'Failed to load component details.';
		}
	};

	const loadComponentAssets = async (componentId: string, version: string) => {
		assetsLoading = true;
		try {
			const params = new URLSearchParams();
			if (version) params.set('version', version);
			params.set('page_size', '50');

			const response = await fetch(`/api/components/${componentId}/assets?${params}`, { credentials: 'include' });
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

	const handleSearch = () => {
		if (searchTimeout) clearTimeout(searchTimeout);
		searchTimeout = setTimeout(() => {
			page = 1;
			loadComponents();
		}, 300);
	};

	const handleEcosystemChange = () => {
		page = 1;
		loadComponents();
	};

	const handleVersionFilter = (version: string) => {
		selectedVersion = version;
		if (selectedComponent) {
			loadComponentAssets(selectedComponent.id, version);
		}
	};

	const totalPages = $derived(Math.ceil(totalCount / pageSize));

	onMount(() => {
		if (browser) {
			loadEcosystems();
			loadComponents();
		}
	});
</script>

<svelte:head>
	<title>Components - SPAM</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Components</h1>
				<p class="text-sm text-[var(--text-tertiary)]">Search dependencies across all your SBOMs.</p>
			</div>
		</header>

		<!-- Search and filters -->
		<div class="flex flex-col gap-4 sm:flex-row sm:items-center">
			<div class="relative flex-1">
				<Search class="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-tertiary)]" />
				<input
					type="text"
					placeholder="Search by name or PURL..."
					class="w-full rounded-2xl border border-[var(--border-color)] bg-transparent py-3 pl-11 pr-4 text-sm text-[var(--text-secondary)] placeholder-[var(--text-muted)] transition focus:border-[var(--accent)] focus:outline-none"
					bind:value={searchQuery}
					oninput={handleSearch}
				/>
			</div>
			<select
				class="rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 text-sm text-[var(--text-secondary)] transition focus:border-[var(--accent)] focus:outline-none"
				bind:value={selectedEcosystem}
				onchange={handleEcosystemChange}
			>
				<option value="">All ecosystems</option>
				{#each ecosystems as eco}
					<option value={eco}>{eco}</option>
				{/each}
			</select>
		</div>

		{#if error}
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">{error}</div>
		{/if}

		{#if loading}
			<p class="text-sm text-[var(--text-secondary)]">Loading components...</p>
		{:else if components.length === 0}
			<p class="text-sm text-[var(--text-secondary)]">No components found.</p>
		{:else}
			<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
				<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
					<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
						<tr>
							<th class="px-5 py-3 text-left">Name</th>
							<th class="px-5 py-3 text-left">Ecosystem</th>
							<th class="px-5 py-3 text-center">Versions</th>
							<th class="px-5 py-3 text-center">Repos</th>
							<th class="px-5 py-3 text-center">Images</th>
							<th class="px-5 py-3 text-right"></th>
						</tr>
					</thead>
					<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
						{#each components as component}
							<tr
								class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]"
								onclick={() => loadComponentDetail(component.id)}
							>
								<td class="px-5 py-3">
									<div class="flex items-center gap-2">
										<Package class="h-4 w-4 text-[var(--accent)]" />
										<span class="font-semibold text-[var(--text-bright)]">{component.name}</span>
									</div>
									{#if component.purl}
										<p class="mt-0.5 truncate text-xs text-[var(--text-muted)]" title={component.purl}>{component.purl}</p>
									{/if}
								</td>
								<td class="px-5 py-3">
									<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs">
										{component.ecosystem || '—'}
									</span>
								</td>
								<td class="px-5 py-3 text-center">{component.version_count}</td>
								<td class="px-5 py-3 text-center">
									{#if component.repo_count > 0}
										<span class="inline-flex items-center gap-1">
											<GitBranch class="h-3 w-3" />
											{component.repo_count}
										</span>
									{:else}
										—
									{/if}
								</td>
								<td class="px-5 py-3 text-center">
									{#if component.image_count > 0}
										<span class="inline-flex items-center gap-1">
											<Container class="h-3 w-3" />
											{component.image_count}
										</span>
									{:else}
										—
									{/if}
								</td>
								<td class="px-5 py-3 text-right">
									<ChevronRight class="inline h-4 w-4 text-[var(--text-muted)]" />
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>

			<!-- Pagination -->
			{#if totalPages > 1}
				<div class="flex items-center justify-between pt-4">
					<p class="text-xs text-[var(--text-muted)]">
						Showing {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, totalCount)} of {totalCount}
					</p>
					<div class="flex gap-2">
						<button
							type="button"
							class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
							disabled={page <= 1}
							onclick={() => { page--; loadComponents(); }}
						>
							Previous
						</button>
						<button
							type="button"
							class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
							disabled={page >= totalPages}
							onclick={() => { page++; loadComponents(); }}
						>
							Next
						</button>
					</div>
				</div>
			{/if}
		{/if}
	</section>
</div>

<!-- Component Detail Dialog -->
<Dialog bind:open={detailOpen}>
	{#if selectedComponent}
		<div class="flex h-full w-full flex-col">
			<div class="flex items-start justify-between border-b border-[var(--border-color)] p-6">
				<div class="flex-1">
					<div class="flex items-center gap-2">
						<Package class="h-5 w-5 text-[var(--accent)]" />
						<h2 class="text-xl font-semibold text-[var(--text-bright)]">{selectedComponent.name}</h2>
					</div>
					{#if selectedComponent.purl}
						<p class="mt-1 text-xs text-[var(--text-muted)]">{selectedComponent.purl}</p>
					{/if}
					<div class="mt-2 flex flex-wrap gap-2">
						<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs">
							{selectedComponent.ecosystem || 'Unknown'}
						</span>
						<span class="inline-flex items-center gap-1 text-xs text-[var(--text-secondary)]">
							{selectedComponent.version_count} versions
						</span>
						<span class="inline-flex items-center gap-1 text-xs text-[var(--text-secondary)]">
							<GitBranch class="h-3 w-3" /> {selectedComponent.repo_count} repos
						</span>
						<span class="inline-flex items-center gap-1 text-xs text-[var(--text-secondary)]">
							<Container class="h-3 w-3" /> {selectedComponent.image_count} images
						</span>
					</div>
				</div>
			</div>

			<div class="flex flex-1 flex-col gap-4 overflow-hidden p-6 md:flex-row">
				<!-- Versions list -->
				<div class="w-full shrink-0 md:w-48">
					<h3 class="mb-2 text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Versions</h3>
					<div class="max-h-64 space-y-1 overflow-y-auto md:max-h-full">
						<button
							type="button"
							class="w-full rounded-lg px-3 py-2 text-left text-sm transition {selectedVersion === '' ? 'bg-[var(--hover-bg)] text-[var(--text-bright)]' : 'text-[var(--text-secondary)] hover:bg-[var(--hover-bg-subtle)]'}"
							onclick={() => handleVersionFilter('')}
						>
							All versions
						</button>
						{#each selectedComponent.versions as v}
							<button
								type="button"
								class="w-full rounded-lg px-3 py-2 text-left text-sm transition {selectedVersion === v.version ? 'bg-[var(--hover-bg)] text-[var(--text-bright)]' : 'text-[var(--text-secondary)] hover:bg-[var(--hover-bg-subtle)]'}"
								onclick={() => handleVersionFilter(v.version)}
							>
								{v.version || '(no version)'}
								<span class="ml-1 text-xs text-[var(--text-muted)]">({v.repo_count})</span>
							</button>
						{/each}
					</div>
				</div>

				<!-- Assets list -->
				<div class="flex-1 overflow-hidden">
					<h3 class="mb-2 text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">
						Used in {selectedVersion ? `(${selectedVersion})` : ''}
					</h3>
					{#if assetsLoading}
						<p class="text-sm text-[var(--text-secondary)]">Loading...</p>
					{:else if componentAssets.length === 0}
						<p class="text-sm text-[var(--text-secondary)]">No assets found.</p>
					{:else}
						<div class="max-h-96 space-y-2 overflow-y-auto">
							{#each componentAssets as asset}
								<div class="rounded-lg border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-3">
									{#if asset.asset_type === 'REPO_COMMIT'}
										<div class="flex items-center gap-2">
											<GitBranch class="h-4 w-4 text-[var(--accent)]" />
											<span class="font-medium text-[var(--text-bright)]">
												{asset.org}/{asset.slug}
											</span>
											<span class="text-xs text-[var(--text-muted)]">({asset.provider})</span>
										</div>
										<p class="mt-1 text-xs text-[var(--text-muted)]">
											Commit: {asset.commit_sha?.substring(0, 8)}
										</p>
									{:else if asset.asset_type === 'IMAGE_DIGEST'}
										<div class="flex items-center gap-2">
											<Container class="h-4 w-4 text-[var(--accent)]" />
											<span class="font-medium text-[var(--text-bright)]">
												{asset.image_repository}
											</span>
										</div>
										<p class="mt-1 text-xs text-[var(--text-muted)]">
											{asset.image_registry} @ {asset.image_digest?.substring(0, 16)}...
										</p>
									{/if}
									<p class="mt-1 text-xs text-[var(--text-tertiary)]">
										Version: {asset.version || '—'}
									</p>
								</div>
							{/each}
						</div>
					{/if}
				</div>
			</div>
		</div>
	{/if}
</Dialog>
