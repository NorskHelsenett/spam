<script lang="ts">
	import { Package, X, CheckCircle, FileCode, Microscope, ChevronRight, ChevronDown } from 'lucide-svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';

	type RepoDependency = {
		group_path: string;
		name: string;
		ecosystem: string;
		version: string;
		sources: string[];
		direct: boolean;
		origin_path?: string;
	};

	let {
		open = $bindable(false),
		loading = false,
		data = [],
		sourceFilter = 'all'
	}: {
		open: boolean;
		loading: boolean;
		data: RepoDependency[];
		sourceFilter?: 'all' | 'sbom' | 'manifest';
	} = $props();

	let tab = $state('all');
	let collapsedGroups = $state<Record<string, boolean>>({});

	const sourceFiltered = $derived.by(() => {
		if (sourceFilter === 'sbom') return data.filter((d) => d.sources.includes('sbom'));
		if (sourceFilter === 'manifest') return data.filter((d) => d.sources.includes('manifest'));
		return data;
	});

	const filtered = $derived.by(() => {
		if (tab === 'direct') return sourceFiltered.filter((d) => d.direct);
		if (tab === 'transitive') return sourceFiltered.filter((d) => !d.direct);
		return sourceFiltered;
	});

	const groups = $derived.by(() => {
		const map = new Map<string, RepoDependency[]>();
		for (const dep of filtered) {
			const key = dep.group_path || 'Scanner detected';
			const existing = map.get(key);
			if (existing) existing.push(dep);
			else map.set(key, [dep]);
		}
		return Array.from(map.entries()).map(([groupPath, dependencies]) => ({
			groupPath,
			ecosystems: Array.from(new Set(dependencies.map((d) => d.ecosystem))).sort((a, b) =>
				a.localeCompare(b)
			),
			dependencies: [...dependencies].sort((a, b) => {
				if (a.direct !== b.direct) return a.direct ? -1 : 1;
				if (a.name !== b.name) return a.name.localeCompare(b.name);
				return a.version.localeCompare(b.version);
			})
		}));
	});

	const toggle = (groupPath: string) => {
		collapsedGroups = { ...collapsedGroups, [groupPath]: !collapsedGroups[groupPath] };
	};

	const sourceBadge = (source: string) => {
		if (source === 'manifest')
			return { icon: FileCode, label: 'manifest', className: 'bg-purple-500/10 text-purple-400', title: 'From manifest file' };
		if (source === 'sbom')
			return { icon: Microscope, label: 'sbom', className: 'bg-blue-500/10 text-blue-400', title: 'From SBOM scanner' };
		return null;
	};

	const depTitle = (dep: RepoDependency) =>
		dep.version ? `${dep.name}@${dep.version}` : dep.name;

	const depURL = (dep: RepoDependency) => {
		const eco = dep.ecosystem.toLowerCase();
		const n = dep.name;
		const v = dep.version;
		const en = encodeURIComponent(n).replace(/%2F/g, '/');
		const maven = n.match(/^([^:]+):([^:]+)$/);
		switch (eco) {
			case 'npm': return v ? `https://www.npmjs.com/package/${en}/v/${encodeURIComponent(v)}` : `https://www.npmjs.com/package/${en}`;
			case 'nuget': return v ? `https://www.nuget.org/packages/${encodeURIComponent(n)}/${encodeURIComponent(v)}` : `https://www.nuget.org/packages/${encodeURIComponent(n)}`;
			case 'golang': return v ? `https://pkg.go.dev/${n}@${encodeURIComponent(v)}` : `https://pkg.go.dev/${n}`;
			case 'github': case 'github-action': case 'github-actions': return `https://github.com/${n}`;
			case 'pypi': return v ? `https://pypi.org/project/${encodeURIComponent(n)}/${encodeURIComponent(v)}/` : `https://pypi.org/project/${encodeURIComponent(n)}/`;
			case 'maven': case 'gradle': if (!maven) return ''; return v ? `https://mvnrepository.com/artifact/${encodeURIComponent(maven[1])}/${encodeURIComponent(maven[2])}/${encodeURIComponent(v)}` : `https://mvnrepository.com/artifact/${encodeURIComponent(maven[1])}/${encodeURIComponent(maven[2])}`;
			case 'composer': return v ? `https://packagist.org/packages/${en}#${encodeURIComponent(v)}` : `https://packagist.org/packages/${en}`;
			case 'rubygems': case 'gem': return v ? `https://rubygems.org/gems/${encodeURIComponent(n)}/versions/${encodeURIComponent(v)}` : `https://rubygems.org/gems/${encodeURIComponent(n)}`;
			case 'cargo': case 'rust': return v ? `https://crates.io/crates/${encodeURIComponent(n)}/${encodeURIComponent(v)}` : `https://crates.io/crates/${encodeURIComponent(n)}`;
			case 'pub': case 'dart': return v ? `https://pub.dev/packages/${encodeURIComponent(n)}/versions/${encodeURIComponent(v)}` : `https://pub.dev/packages/${encodeURIComponent(n)}`;
			case 'hex': case 'elixir': return v ? `https://hex.pm/packages/${encodeURIComponent(n)}/${encodeURIComponent(v)}` : `https://hex.pm/packages/${encodeURIComponent(n)}`;
			default: return '';
		}
	};
</script>

{#if open}
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div
		class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 pt-16 backdrop-blur-sm"
		onkeydown={(e) => e.key === 'Escape' && (open = false)}
		onclick={(e) => e.target === e.currentTarget && (open = false)}
	>
		<div class="w-full max-w-5xl">
			<section class="overflow-hidden rounded-2xl border border-[var(--border-color)] bg-[var(--bg)] shadow-2xl">
				<div class="flex items-center justify-between px-6 py-4">
					<div class="flex items-center gap-3">
						<Package class="h-5 w-5 text-[var(--accent)]" />
						<h2 class="text-base font-semibold text-[var(--text-bright)]">Dependencies</h2>
						{#if !loading}
							<span class="rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs text-[var(--text-muted)]">
								{filtered.length}
							</span>
						{/if}
					</div>
					<button
						type="button"
						class="rounded-lg p-1.5 text-[var(--text-muted)] transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-secondary)]"
						onclick={() => (open = false)}
					>
						<X class="h-4 w-4" />
					</button>
				</div>

				<div class="px-6">
					<p class="pb-4 text-sm text-[var(--text-muted)]">Direct and transitive dependencies detected for this repository.</p>
					{#if !loading && data.length > 0}
						<div class="mt-2">
							<TabSelector
								options={[
									{ value: 'all', label: 'All' },
									{ value: 'direct', label: 'Direct' },
									{ value: 'transitive', label: 'Transitive' }
								]}
								bind:value={tab}
							/>
						</div>
					{/if}
				</div>

				<div class="max-h-[65vh] overflow-y-auto p-4">
					{#if loading}
						<div class="flex items-center justify-center py-20">
							<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
						</div>
					{:else if data.length === 0}
						<div class="flex flex-col items-center justify-center py-16 text-center">
							<Package class="mb-3 h-10 w-10 text-[var(--text-muted)]" />
							<p class="text-sm font-medium text-[var(--text-secondary)]">No dependencies found</p>
							<p class="mt-1 text-xs text-[var(--text-muted)]">No dependency data from manifests or SBOM scans yet.</p>
						</div>
					{:else if filtered.length === 0}
						<div class="flex flex-col items-center justify-center py-16 text-center">
							<CheckCircle class="mb-3 h-10 w-10 text-[var(--text-muted)]" />
							<p class="text-sm font-medium text-[var(--text-secondary)]">No matches in this filter</p>
						</div>
					{:else}
						<div class="space-y-4">
							{#each groups as group}
								<section style="border: none; box-shadow: none; padding: 0;">
									<div class="flex items-center justify-between gap-4 px-4 py-3">
										<div class="min-w-0 flex-1">
											<div class="flex flex-wrap items-center gap-2">
												<p class="font-mono text-sm font-semibold text-[var(--text-bright)]">{group.groupPath}</p>
												{#each group.ecosystems as ecosystem}
													<span class="rounded-full border border-[var(--border-color)] px-1.5 py-0.5 text-[8px] uppercase tracking-wide text-[var(--text-muted)]">
														{ecosystem}
													</span>
												{/each}
											</div>
											<p class="mt-1 text-xs text-[var(--text-muted)]">{group.dependencies.length} dependency entries</p>
										</div>
										<button
											type="button"
											class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-[var(--text-muted)] transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-secondary)]"
											onclick={() => toggle(group.groupPath)}
											title={collapsedGroups[group.groupPath] ? 'Expand' : 'Collapse'}
										>
											{#if collapsedGroups[group.groupPath]}
												<ChevronRight class="h-4 w-4" />
											{:else}
												<ChevronDown class="h-4 w-4" />
											{/if}
										</button>
									</div>
									{#if !collapsedGroups[group.groupPath]}
										<div class="space-y-1 border-t border-[var(--border-color)]/60 p-1">
											{#each group.dependencies as dep}
												<article class="rounded-lg px-4 py-3 transition-colors hover:bg-[var(--hover-bg-subtle)]">
													<div class="flex items-start gap-4">
														<div class="w-20 shrink-0 pt-0.5">
															{#if dep.direct}
																<span class="inline-flex items-center rounded-full border border-green-500/40 bg-green-500/10 px-2 py-0.5 text-xs font-semibold text-green-400">direct</span>
															{:else}
																<span class="inline-flex items-center rounded-full border border-[var(--border-color)] bg-[var(--hover-bg)] px-2 py-0.5 text-xs font-semibold text-[var(--text-muted)]">transitive</span>
															{/if}
														</div>
														<div class="min-w-0 flex-1 space-y-1.5">
															<div class="flex flex-wrap items-center gap-2">
																{#if depURL(dep)}
																	<a href={depURL(dep)} target="_blank" rel="noopener noreferrer" class="truncate text-sm font-semibold text-[var(--accent)] hover:underline">
																		{depTitle(dep)}
																	</a>
																{:else}
																	<p class="truncate text-sm font-semibold text-[var(--text-bright)]">{depTitle(dep)}</p>
																{/if}
																<div class="ml-auto flex flex-wrap items-center gap-2">
																	{#each dep.sources as source}
																		{@const badge = sourceBadge(source)}
																		{#if badge}
																			{@const Icon = badge.icon}
																			<span class="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-medium {badge.className}" title={badge.title}>
																				<Icon class="h-3 w-3" />
																				{badge.label}
																			</span>
																		{/if}
																	{/each}
																</div>
															</div>
															<p class="text-sm text-[var(--text-secondary)]">
																{dep.name}<span class="text-[var(--text-muted)]"> in {dep.ecosystem}</span>
															</p>
															<div class="flex flex-wrap items-center gap-3 text-xs text-[var(--text-muted)]">
																<span class="font-mono">pkg:{dep.ecosystem}/{dep.name}{dep.version ? `@${dep.version}` : ''}</span>
																{#if dep.origin_path && dep.origin_path !== group.groupPath}
																	<span class="rounded-md bg-[var(--hover-bg)] px-1.5 py-0.5 font-mono text-[8px] text-[var(--text-muted)]">{dep.origin_path}</span>
																{/if}
															</div>
														</div>
													</div>
												</article>
											{/each}
										</div>
									{/if}
								</section>
							{/each}
						</div>
					{/if}
				</div>
			</section>
		</div>
	</div>
{/if}
