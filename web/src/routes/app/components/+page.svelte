<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { fly } from 'svelte/transition';
	import { cubicOut, cubicIn } from 'svelte/easing';
	import { Search, Package, GitBranch, FileCode, Microscope, CheckCircle, Download, ChevronDown } from 'lucide-svelte';
	import DependencyDrawer from '$lib/components/DependencyDrawer.svelte';
	import Select from '$lib/components/Select.svelte';

	type UnifiedDependency = {
		name: string;
		ecosystem: string;
		purl?: string;
		sources: string[];
		version_count: number;
		sbom_count: number;
		repo_count: number;
		has_direct?: boolean;
		scopes?: string[];
	};

	let dependencies: UnifiedDependency[] = $state([]);
	let ecosystems: string[] = $state([]);
	let loading = $state(true);
	let error = $state('');
	let searchQuery = $state('');
	let selectedEcosystem = $state('');
	let selectedSource = $state(''); // 'sbom', 'manifest', or ''
	let page = $state(1);
	let totalCount = $state(0);
	let pageSize = $state(50);
	let exporting = $state(false);
	let exportDropdownOpen = $state(false);
	let exportBtnEl: HTMLDivElement | undefined = $state();

	// Sorting
	let sortColumn = $state<string>('');
	let sortDirection = $state<'asc' | 'desc'>('asc');

	// Detail dialog
	let detailOpen = $state(false);
	let selectedDependency: UnifiedDependency | null = $state(null);

	let searchTimeout: ReturnType<typeof setTimeout> | null = null;
	const sourceOptions = [
		{ value: '', label: 'All sources' },
		{ value: 'sbom', label: 'SBOM only' },
		{ value: 'manifest', label: 'Manifest only' },
		{ value: 'both', label: 'Both (verified)' }
	];
	const ecosystemOptions = $derived([
		{ value: '', label: 'All ecosystems' },
		...ecosystems.map((eco) => ({ value: eco, label: eco }))
	]);

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
			if (selectedSource) params.set('source', selectedSource);
			if (sortColumn) {
				params.set('sort', sortColumn);
				params.set('order', sortDirection);
			}
			params.set('page', String(page));
			params.set('per_page', String(pageSize));

			const response = await fetch(`/api/dependencies?${params}`, { credentials: 'include' });
			if (!response.ok) {
				error = response.status === 401 ? 'Please log in.' : 'Failed to load dependencies.';
				dependencies = [];
				return;
			}
			const data = await response.json();
			dependencies = data.dependencies || [];
			totalCount = data.total || 0;
		} catch {
			error = 'Failed to load dependencies.';
		} finally {
			loading = false;
		}
	};

	const exportCsv = async () => {
		if (exporting) return;
		exporting = true;
		try {
			const params = new URLSearchParams();
			if (searchQuery) params.set('q', searchQuery);
			if (selectedEcosystem) params.set('ecosystem', selectedEcosystem);
			if (selectedSource) params.set('source', selectedSource);

			const response = await fetch(`/api/dependencies/export.csv?${params}`, { credentials: 'include' });
			if (!response.ok) {
				throw new Error(response.status === 401 ? 'Please log in.' : 'Failed to export dependencies.');
			}

			const blob = await response.blob();
			const url = URL.createObjectURL(blob);
			const link = document.createElement('a');
			const disposition = response.headers.get('content-disposition') ?? '';
			const match = disposition.match(/filename="([^"]+)"/);
			link.href = url;
			link.download = match?.[1] || 'dependencies-forensics.csv';
			document.body.appendChild(link);
			link.click();
			document.body.removeChild(link);
			URL.revokeObjectURL(url);
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to export dependencies.';
		} finally {
			exporting = false;
		}
	};

	$effect(() => {
		if (!exportDropdownOpen || !browser) return;
		const handler = (e: MouseEvent) => {
			if (exportBtnEl && !exportBtnEl.contains(e.target as Node)) exportDropdownOpen = false;
		};
		document.addEventListener('mousedown', handler);
		return () => document.removeEventListener('mousedown', handler);
	});

	const exportSelectedPackage = async () => {
		if (!selectedDependency || exporting) return;
		exportDropdownOpen = false;
		exporting = true;
		try {
			const params = new URLSearchParams({
				name: selectedDependency.name,
				ecosystem: selectedDependency.ecosystem,
				page_size: '1000'
			});
			const res = await fetch(`/api/dependencies/assets?${params}`, { credentials: 'include' });
			if (!res.ok) return;
			const data = await res.json();
			const assets: Array<Record<string, string>> = data.assets ?? [];
			const toCsvRow = (fields: unknown[]) =>
				fields.map((f) => `"${String(f ?? '').replace(/"/g, '""')}"`).join(',');
			const rows = [['package', 'ecosystem', 'version', 'type', 'repository', 'source']];
			for (const a of assets) {
				if (a.asset_type === 'REPO_COMMIT') {
					rows.push([selectedDependency.name, selectedDependency.ecosystem, a.version || '', 'repo', `${a.org}/${a.slug}`, a.source || '']);
				} else if (a.asset_type === 'IMAGE_DIGEST') {
					rows.push([selectedDependency.name, selectedDependency.ecosystem, a.version || '', 'image', `${a.image_registry}/${a.image_repository}`, '']);
				}
			}
			const csv = rows.map(toCsvRow).join('\n');
			const blob = new Blob([csv], { type: 'text/csv' });
			const url = URL.createObjectURL(blob);
			const link = document.createElement('a');
			link.href = url;
			link.download = `${selectedDependency.name.replace(/[^a-z0-9\-_.]/gi, '_')}-details.csv`;
			document.body.appendChild(link); link.click();
			document.body.removeChild(link); URL.revokeObjectURL(url);
		} catch { /* ignore */ } finally {
			exporting = false;
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

	const handleSourceChange = () => {
		page = 1;
		loadComponents();
	};

	const handleSort = (column: string) => {
		if (sortColumn === column) {
			sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
		} else {
			sortColumn = column;
			sortDirection = 'asc';
		}
		page = 1; // Reset to first page when sorting changes
		loadComponents();
	};

	const openDetail = (dep: UnifiedDependency) => {
		if (selectedDependency?.name === dep.name && selectedDependency?.ecosystem === dep.ecosystem && detailOpen) {
			detailOpen = false;
			selectedDependency = null;
		} else {
			selectedDependency = dep;
			detailOpen = true;
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
	<title>Dependencies - SPAM</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface flex flex-col gap-6 px-6 py-8 sm:px-10 sm:py-10 h-[calc(100vh-7rem)]">
		<header class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Dependencies</h1>
				<p class="text-sm text-[var(--text-tertiary)]">Search dependencies from SBOMs and manifest files.</p>
			</div>
			<div class="relative w-full sm:w-auto" bind:this={exportBtnEl}>
				<div class="flex w-full overflow-hidden rounded-[999px] border border-[var(--border-color)] bg-[var(--hover-bg)] sm:w-auto">
					<button type="button"
						class="flex flex-1 items-center gap-2 px-[1.1rem] py-[0.55rem] text-[0.85rem] font-semibold tracking-[0.02em] text-[var(--text-bright)] transition hover:brightness-110 disabled:opacity-50 sm:flex-none"
						onclick={exportCsv} disabled={exporting || loading}>
						<Download class="h-4 w-4" />
						{exporting ? 'Exporting…' : 'Export CSV'}
					</button>
					<div class="w-px self-stretch bg-[var(--border-color)]"></div>
					<button type="button"
						class="flex items-center bg-black/[0.06] px-3 py-[0.55rem] text-[var(--text-bright)] transition hover:bg-black/[0.12] disabled:opacity-50"
						onclick={() => (exportDropdownOpen = !exportDropdownOpen)}
						disabled={exporting || loading} aria-label="More export options">
						<ChevronDown class="h-4 w-4" />
					</button>
				</div>
				{#if exportDropdownOpen}
					<div class="absolute right-0 top-full z-30 mt-1 w-60 overflow-hidden rounded-xl border border-[var(--border-color)] bg-[var(--bg-soft)] py-1 shadow-xl">
						<p class="px-3.5 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">All dependencies</p>
						<button type="button"
							class="flex w-full items-center gap-2 px-3.5 py-2 text-left text-[12px] text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)]"
							onclick={() => { exportDropdownOpen = false; exportCsv(); }}>
							<Download class="h-3 w-3 shrink-0 text-[var(--accent)]" /> Export CSV
						</button>
						<div class="mx-3 my-1 border-t border-[var(--border-color)]/60"></div>
						<p class="px-3.5 pb-1 pt-1 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Selected package</p>
						<button type="button"
							class="flex w-full items-center gap-2 px-3.5 py-2 text-left text-[12px] transition {detailOpen && selectedDependency ? 'text-[var(--text-secondary)] hover:bg-[var(--hover-bg)]' : 'cursor-not-allowed text-[var(--text-muted)] opacity-50'}"
							onclick={exportSelectedPackage} disabled={!detailOpen || !selectedDependency}
							title={detailOpen && selectedDependency ? `Export ${selectedDependency.name} details` : 'Open a package to export its details'}>
							<Download class="h-3 w-3 shrink-0 text-[var(--accent)]" />
							{selectedDependency ? `${selectedDependency.name} (CSV)` : 'Package details (CSV)'}
						</button>
					</div>
				{/if}
			</div>
		</header>

		<!-- Search and filters -->
		<div class="flex flex-col gap-4 sm:flex-row sm:items-start">
			<div class="flex-1 sm:min-w-[20rem]">
				<div class="relative">
					<Search class="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--text-tertiary)]" />
					<input
						type="text"
						placeholder="Search name/PURL or use query syntax (e.g. react@19.0.1..19.2.0 || react>=20 && react<21)"
						class="w-full rounded-2xl border border-[var(--border-color)] bg-transparent py-3 pl-11 pr-4 text-sm text-[var(--text-secondary)] placeholder-[var(--text-muted)] transition focus:border-[var(--accent)] focus:outline-none"
						bind:value={searchQuery}
						oninput={handleSearch}
					/>
				</div>
				<p class="mt-2 text-xs text-[var(--text-muted)]">Examples: <code>debug@4.4.2</code>, <code>react@19.0.1..19.2.0</code>, <code>react&gt;=19.0.1 &amp;&amp; react&lt;=19.2.0</code>, <code>debug &lt;=4.4 || lodash@4.17.21</code></p>
			</div>
			<Select
				options={ecosystemOptions}
				bind:value={selectedEcosystem}
				class="w-full sm:w-auto sm:min-w-[12rem] sm:shrink-0"
				onchange={handleEcosystemChange}
			/>
			<Select
				options={sourceOptions}
				bind:value={selectedSource}
				class="w-full sm:w-auto sm:min-w-[12rem] sm:shrink-0"
				onchange={handleSourceChange}
			/>
		</div>

		{#if error}
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">{error}</div>
		{/if}

		{#if dependencies.length === 0 && !loading}
			<p class="text-sm text-[var(--text-secondary)]">No dependencies found.</p>
		{:else if dependencies.length > 0}
			<div class="relative flex flex-1 flex-col overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
				<div class="flex-1 overflow-y-auto">
			<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
					<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
						<tr>
							<th class="px-5 py-3 text-left cursor-pointer hover:text-[var(--text-secondary)] transition" onclick={() => handleSort('name')}>
								<span class="flex items-center gap-1">
									Name
									<span class="w-3 text-center" class:text-[var(--accent)]={sortColumn === 'name'} class:text-transparent={sortColumn !== 'name'}>
										{sortColumn === 'name' ? (sortDirection === 'asc' ? '↑' : '↓') : '↑'}
									</span>
								</span>
							</th>
							<th class="px-5 py-3 text-center cursor-pointer hover:text-[var(--text-secondary)] transition" onclick={() => handleSort('version_count')}>
								<span class="inline-flex items-center gap-1">
									Versions
									<span class="w-3 text-center" class:text-[var(--accent)]={sortColumn === 'version_count'} class:text-transparent={sortColumn !== 'version_count'}>
										{sortColumn === 'version_count' ? (sortDirection === 'asc' ? '↑' : '↓') : '↑'}
									</span>
								</span>
							</th>
							<th class="px-5 py-3 text-left cursor-pointer hover:text-[var(--text-secondary)] transition" onclick={() => handleSort('ecosystem')}>
								<span class="flex items-center gap-1">
									Ecosystem
									<span class="w-3 text-center" class:text-[var(--accent)]={sortColumn === 'ecosystem'} class:text-transparent={sortColumn !== 'ecosystem'}>
										{sortColumn === 'ecosystem' ? (sortDirection === 'asc' ? '↑' : '↓') : '↑'}
									</span>
								</span>
							</th>
							<th class="px-5 py-3 text-center">Source</th>
							<th class="px-5 py-3 text-center cursor-pointer hover:text-[var(--text-secondary)] transition" onclick={() => handleSort('repo_count')}>
								<span class="inline-flex items-center gap-1">
									Repos
									<span class="w-3 text-center" class:text-[var(--accent)]={sortColumn === 'repo_count'} class:text-transparent={sortColumn !== 'repo_count'}>
										{sortColumn === 'repo_count' ? (sortDirection === 'asc' ? '↑' : '↓') : '↑'}
									</span>
								</span>
							</th>
							<th class="px-5 py-3 text-center cursor-pointer hover:text-[var(--text-secondary)] transition" onclick={() => handleSort('sbom_count')}>
								<span class="inline-flex items-center gap-1">
									SBOMs
									<span class="w-3 text-center" class:text-[var(--accent)]={sortColumn === 'sbom_count'} class:text-transparent={sortColumn !== 'sbom_count'}>
										{sortColumn === 'sbom_count' ? (sortDirection === 'asc' ? '↑' : '↓') : '↑'}
									</span>
								</span>
							</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
						{#each dependencies as dep}
							<tr
						class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)] {detailOpen && selectedDependency?.name === dep.name && selectedDependency?.ecosystem === dep.ecosystem ? 'bg-[var(--hover-bg-subtle)]' : ''}"
						onclick={() => openDetail(dep)}
					>
								<td class="px-5 py-3">
									<div class="flex items-center gap-2">
										<Package class="h-4 w-4 text-[var(--accent)]" />
										<span class="font-semibold text-[var(--text-bright)]">{dep.name}</span>
									</div>
									{#if dep.purl}
										<p class="mt-0.5 truncate text-xs text-[var(--text-muted)]" title={dep.purl}>{dep.purl}</p>
									{/if}
									{#if dep.has_direct || (dep.scopes && dep.scopes.length > 0)}
										<div class="mt-1 flex gap-2">
											{#if dep.has_direct}
												<span class="text-xs text-[var(--text-muted)]">direct</span>
											{/if}
											{#if dep.scopes && dep.scopes.length > 0}
												<span class="text-xs text-[var(--text-muted)]">{dep.scopes.join(', ')}</span>
											{/if}
										</div>
									{/if}
								</td>
								<td class="px-5 py-3 text-center">
									<span class="inline-flex items-center px-2.5 py-0.5 text-xs font-semibold">
										{dep.version_count}
									</span>
								</td>
								<td class="px-5 py-3">
									<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs">
										{dep.ecosystem || '—'}
									</span>
								</td>
								<td class="px-5 py-3 text-center">
									{#if dep.sources[0] === 'both'}
										<span class="inline-flex items-center gap-1 rounded-full bg-green-500/10 px-2 py-0.5 text-xs text-green-400" title="Found in both SBOM and manifest">
											<CheckCircle class="h-3 w-3" />
											Both
										</span>
									{:else if dep.sources[0] === 'sbom'}
										<span class="inline-flex items-center gap-1 rounded-full bg-blue-500/10 px-2 py-0.5 text-xs text-blue-400" title="From SBOM scanner">
											<Microscope class="h-3 w-3" />
											SBOM
										</span>
									{:else}
										<span class="inline-flex items-center gap-1 rounded-full bg-purple-500/10 px-2 py-0.5 text-xs text-purple-400" title="From manifest file">
											<FileCode class="h-3 w-3" />
											Manifest
										</span>
									{/if}
								</td>
								<td class="px-5 py-3 text-center">
									{#if dep.repo_count > 0}
										<span class="inline-flex items-center gap-1">
											<GitBranch class="h-3 w-3" />
											{dep.repo_count}
										</span>
									{:else}
										—
									{/if}
								</td>
								<td class="px-5 py-3 text-center">
									{#if dep.sbom_count > 0}
										{dep.sbom_count}
									{:else}
										—
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
				{#if detailOpen && selectedDependency}
					<div
						class="absolute inset-y-0 right-0 z-10 w-[900px] border-l border-[var(--border-color)] rounded-l-[10px]"
						in:fly={{ x: 900, duration: 240, easing: cubicOut, opacity: 1 }}
					out:fly={{ x: 900, duration: 200, easing: cubicIn, opacity: 1 }}
					>
						<DependencyDrawer
							name={selectedDependency.name}
							ecosystem={selectedDependency.ecosystem}
							sources={selectedDependency.sources}
							onClose={() => { detailOpen = false; selectedDependency = null; }}
						/>
					</div>
				{/if}
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
