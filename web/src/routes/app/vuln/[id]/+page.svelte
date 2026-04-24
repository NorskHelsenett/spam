<script lang="ts">
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { browser } from '$app/environment';
	import { ArrowLeft, ShieldX, ShieldAlert, Shield, ExternalLink, GitBranch, Container, Server, Clock, RefreshCw } from 'lucide-svelte';
	import Loading from '$lib/components/Loading.svelte';
	import Markdown from '$lib/components/Markdown.svelte';
	import ContributorAvatars from '$lib/components/ContributorAvatars.svelte';
	import type { Contributor } from '$lib/components/ContributorAvatars.svelte';

	type Reference = { url: string; type?: string; label?: string };
	type ClusterPresence = {
		cluster_id: string;
		cluster: string;
		environment: string;
		namespace: string;
		container_count: number;
	};
	type AffectedRepo = {
		repo_id: string;
		repo_slug: string;
		provider: string;
		provider_instance_id: string;
		org: string;
		slug: string;
		is_private: boolean;
		pkg_name: string;
		installed_version: string;
		fixed_version: string;
		source: string;
		scanned_at: string | null;
	};
	type AffectedImage = {
		image_id: string;
		image_slug: string;
		image_digest: string;
		source_repo_id?: string;
		verified_source: boolean;
		pkg_name: string;
		installed_version: string;
		fixed_version: string;
		source: string;
		scanned_at: string | null;
		clusters: ClusterPresence[];
	};
	type Enrichment = {
		vuln_id: string;
		title: string;
		description: string;
		severity: string;
		cvss_score: number;
		cvss_vector: string;
		cwes: string[] | null;
		references: Reference[] | null;
		aliases: string[] | null;
		sources: string[] | null;
		published_at: string | null;
		modified_at: string | null;
		fetched_at: string | null;
	};
	type DetailResponse = {
		vuln_id: string;
		title: string;
		description: string;
		severity: string;
		sources: string[];
		enrichment?: Enrichment;
		enrichment_loading: boolean;
		affected_repos: AffectedRepo[];
		affected_images: AffectedImage[];
		repo_count: number;
		image_count: number;
	};

	// Route is /app/vuln/[id] — short URL for manual typing. The
	// API endpoint stays at /api/vulnerabilities/{vuln_id} since
	// that's the public-shape resource name; only the UI route
	// was shortened.
	const vulnId = $derived($page.params.id ?? '');

	let data = $state<DetailResponse | null>(null);
	let loading = $state(true);
	let error = $state('');
	// Per-repo contributor cache; repo_id → list (null = loading, [] = empty)
	let contributors = $state<Record<string, Contributor[] | null>>({});

	const fetchDetail = async () => {
		loading = true;
		error = '';
		try {
			const res = await fetch(`/api/vulnerabilities/${encodeURIComponent(vulnId)}`, { credentials: 'include' });
			if (!res.ok) {
				error = `Failed to load (${res.status})`;
				return;
			}
			const body = (await res.json()) as DetailResponse;
			// Normalize nullable arrays so the template can trust
			// .length without optional chaining on every access —
			// Go returns nil slices as JSON null, not [].
			body.affected_repos = body.affected_repos ?? [];
			body.affected_images = body.affected_images ?? [];
			body.sources = body.sources ?? [];
			data = body;
			// Kick off contributor fetches for the visible repos so the
			// page fills in progressively. Cap at the first 20 to avoid
			// hammering provider APIs on a vuln that hit a hundred repos.
			const firstRepos = data.affected_repos.slice(0, 20);
			for (const r of firstRepos) {
				loadContributors(r.repo_id);
			}
		} catch (err) {
			error = 'Failed to load vulnerability';
		} finally {
			loading = false;
		}
	};

	const loadContributors = async (repoID: string) => {
		if (repoID in contributors) return;
		contributors = { ...contributors, [repoID]: null };
		try {
			const res = await fetch(`/api/repos/contributors?repo_id=${encodeURIComponent(repoID)}`, { credentials: 'include' });
			if (res.ok) {
				const body = await res.json();
				contributors = { ...contributors, [repoID]: body?.contributors ?? [] };
			} else {
				contributors = { ...contributors, [repoID]: [] };
			}
		} catch {
			contributors = { ...contributors, [repoID]: [] };
		}
	};

	onMount(() => {
		if (!browser) return;
		fetchDetail();
	});

	// Re-fetch on route change (same layout, different vuln_id)
	$effect(() => {
		vulnId;
		if (browser && data && data.vuln_id !== vulnId) {
			fetchDetail();
		}
	});

	const fmtDate = (iso: string | null | undefined) => {
		if (!iso) return '—';
		const d = new Date(iso);
		if (isNaN(d.getTime())) return '—';
		return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
	};

	const fmtRelative = (iso: string | null | undefined) => {
		if (!iso) return '—';
		const d = new Date(iso).getTime();
		if (isNaN(d)) return '—';
		const diff = Date.now() - d;
		const days = Math.floor(diff / 86_400_000);
		if (days === 0) return 'today';
		if (days === 1) return 'yesterday';
		if (days < 30) return `${days}d ago`;
		const months = Math.floor(days / 30);
		if (months < 12) return `${months}mo ago`;
		const years = Math.floor(days / 365);
		return `${years}y ago`;
	};

	const severityClass = (sev: string | undefined): string => {
		const s = (sev ?? '').toUpperCase();
		switch (s) {
			case 'CRITICAL': return 'border-red-500/30 bg-red-500/10 text-red-400';
			case 'HIGH':     return 'border-orange-500/30 bg-orange-500/10 text-orange-400';
			case 'MEDIUM':   return 'border-yellow-500/30 bg-yellow-500/10 text-yellow-400';
			case 'LOW':      return 'border-blue-500/30 bg-blue-500/10 text-blue-400';
			default:         return 'border-[var(--border-color)] bg-[var(--hover-bg)] text-[var(--text-tertiary)]';
		}
	};

	// Parse numeric CVSS score from a vector string when the backend
	// didn't persist one (OSV often ships a vector without a score).
	// Pattern: /CVSS:<ver>/.../score:N.N/ isn't standard, so we just
	// surface the vector — the UI shows both score + vector if both
	// exist, vector-only otherwise.
	const cvssDisplay = (e: Enrichment | undefined): { score: string; vector: string } => {
		if (!e) return { score: '', vector: '' };
		const score = e.cvss_score > 0 ? e.cvss_score.toFixed(1) : '';
		return { score, vector: e.cvss_vector || '' };
	};

	// Providers we have repo-detail routes for. Used to build a link
	// to the per-repo page (where contributors + issues live), otherwise
	// we just show the slug as text.
	const repoPageLink = (repo: AffectedRepo): string | null => {
		if (!repo.provider || !repo.org || !repo.slug) return null;
		const path = `${repo.org}/${repo.slug}`;
		return `/app/providers/repo?provider=${encodeURIComponent(repo.provider)}&path=${encodeURIComponent(path)}&provider_id=${encodeURIComponent(repo.provider_instance_id)}`;
	};

	// External link for "view on upstream advisory" — only shown
	// alongside the internal detail view, never instead of it.
	const upstreamUrl = (id: string): string => {
		if (id.startsWith('CVE-')) return `https://www.cve.org/CVERecord?id=${id}`;
		if (id.startsWith('GHSA-')) return `https://github.com/advisories/${id}`;
		return `https://osv.dev/vulnerability/${id}`;
	};

	const refTypeLabel = (t: string | undefined): string => {
		switch ((t ?? '').toUpperCase()) {
			case 'ADVISORY': return 'Advisory';
			case 'FIX':      return 'Fix';
			case 'REPORT':   return 'Report';
			case 'PACKAGE':  return 'Package';
			case 'EVIDENCE': return 'Evidence';
			case 'WEB':      return 'Web';
			case '':         return 'Link';
			default:         return t!;
		}
	};
</script>

<svelte:head>
	<title>{data?.vuln_id ?? vulnId} · Vulnerabilities · SPAM</title>
</svelte:head>

<div class="space-y-6 pb-16">
	<nav>
		<!-- Prefer history.back() so SvelteKit's scroll restoration and
		     any retained list-page state (filters, virtual-scroll
		     position) are preserved. Falls back to the bare href on a
		     fresh load (user opened the CVE page directly). -->
		<a
			href="/app/vulnerabilities"
			onclick={(e) => {
				if (typeof window !== 'undefined' && window.history.length > 1) {
					e.preventDefault();
					window.history.back();
				}
			}}
			class="inline-flex items-center gap-2 text-sm text-[var(--text-secondary)] transition hover:text-[var(--accent)]"
		>
			<ArrowLeft class="h-4 w-4" /> Back
		</a>
	</nav>

	{#if loading && !data}
		<div class="panel-surface px-6 py-16 sm:px-10">
			<Loading message="Loading vulnerability" variant="bar" size="md" />
		</div>
	{:else if error}
		<div class="panel-surface space-y-2 px-6 py-10 sm:px-10">
			<h1 class="text-lg font-semibold text-[var(--text-bright)]">Couldn't load this vulnerability</h1>
			<p class="text-sm text-[var(--text-tertiary)]">{error}</p>
			<button class="btn btn-ghost mt-4" onclick={fetchDetail}>
				<RefreshCw class="h-4 w-4" /> Retry
			</button>
		</div>
	{:else if data}
		<!-- Hero: CVE ID + severity + title + sources + dates -->
		<section class="panel-surface space-y-4 px-6 py-8 sm:px-10 sm:py-10">
			<div class="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
				<div class="space-y-2">
					<div class="flex flex-wrap items-center gap-2">
						<h1 class="font-mono text-2xl font-semibold text-[var(--accent)] sm:text-3xl">{data.vuln_id}</h1>
						<span class="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium {severityClass(data.severity)}">
							{#if (data.severity ?? '').toUpperCase() === 'CRITICAL'}
								<ShieldX class="h-3 w-3" />
							{:else if (data.severity ?? '').toUpperCase() === 'HIGH'}
								<ShieldAlert class="h-3 w-3" />
							{:else}
								<Shield class="h-3 w-3" />
							{/if}
							{data.severity || 'UNKNOWN'}
						</span>
						{#if data.enrichment_loading}
							<span class="inline-flex items-center gap-1 rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs text-[var(--text-tertiary)]">
								<RefreshCw class="h-3 w-3 animate-spin" /> enriching
							</span>
						{/if}
						{#each data.sources ?? [] as src}
							<span class="inline-flex items-center rounded-full border border-[var(--border-color)] bg-[var(--hover-bg)] px-2 py-0.5 text-xs text-[var(--text-secondary)]">{src}</span>
						{/each}
					</div>
					{#if data.title}
						<p class="text-base text-[var(--text-bright)] sm:text-lg">{data.title}</p>
					{/if}
				</div>
				<a href={upstreamUrl(data.vuln_id)} target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1.5 text-xs text-[var(--text-tertiary)] transition hover:text-[var(--accent)]">
					View upstream <ExternalLink class="h-3 w-3" />
				</a>
			</div>

			<!-- Published / Modified / CVSS metric cards -->
			<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
				<div class="metric-card rounded-2xl border border-[var(--border-color)]/60 p-4">
					<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Published</p>
					<p class="mt-2 text-sm font-semibold text-[var(--text-bright)]">{fmtDate(data.enrichment?.published_at)}</p>
					<p class="text-xs text-[var(--text-tertiary)]">{fmtRelative(data.enrichment?.published_at)}</p>
				</div>
				<div class="metric-card rounded-2xl border border-[var(--border-color)]/60 p-4">
					<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Last modified</p>
					<p class="mt-2 text-sm font-semibold text-[var(--text-bright)]">{fmtDate(data.enrichment?.modified_at)}</p>
					<p class="text-xs text-[var(--text-tertiary)]">{fmtRelative(data.enrichment?.modified_at)}</p>
				</div>
				<div class="metric-card rounded-2xl border border-[var(--border-color)]/60 p-4">
					<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">CVSS</p>
					{#if cvssDisplay(data.enrichment).score}
						<p class="mt-2 text-2xl font-semibold text-[var(--text-bright)]">{cvssDisplay(data.enrichment).score}</p>
					{:else}
						<p class="mt-2 text-sm font-semibold text-[var(--text-muted)]">—</p>
					{/if}
					{#if cvssDisplay(data.enrichment).vector}
						<p class="truncate text-[10px] font-mono text-[var(--text-tertiary)]" title={cvssDisplay(data.enrichment).vector}>{cvssDisplay(data.enrichment).vector}</p>
					{/if}
				</div>
				<div class="metric-card rounded-2xl border border-[var(--border-color)]/60 p-4">
					<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Exposure</p>
					<p class="mt-2 text-2xl font-semibold text-[var(--text-bright)]">{data.repo_count + data.image_count}</p>
					<p class="text-xs text-[var(--text-tertiary)]">{data.repo_count} repos · {data.image_count} images</p>
				</div>
			</div>
		</section>

		<!-- Description, aliases, CWEs -->
		<section class="panel-surface space-y-5 px-6 py-8 sm:px-10 sm:py-10">
			<header>
				<h2 class="text-lg font-semibold text-[var(--text-bright)]">Advisory</h2>
				<p class="text-xs text-[var(--text-tertiary)]">
					{#if data.enrichment}
						Fetched {fmtRelative(data.enrichment.fetched_at)}{#if data.enrichment.sources && data.enrichment.sources.length} from {data.enrichment.sources.join(', ')}{/if}.
					{:else if data.enrichment_loading}
						Enrichment in progress — reload in a moment to see the full description.
					{:else}
						Not yet enriched. Showing scanner-reported fields only.
					{/if}
				</p>
			</header>

			{#if data.description}
				<div class="prose prose-invert max-w-none text-sm text-[var(--text-secondary)]">
					<Markdown content={data.description} />
				</div>
			{:else}
				<p class="text-sm text-[var(--text-muted)]">No description available.</p>
			{/if}

			{#if data.enrichment}
				{@const aliases = (data.enrichment.aliases ?? []).filter((a) => a !== data!.vuln_id)}
				{@const cwes = data.enrichment.cwes ?? []}
				{#if aliases.length > 0 || cwes.length > 0}
					<div class="grid gap-4 sm:grid-cols-2">
						{#if aliases.length > 0}
							<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
								<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Also known as</p>
								<div class="mt-2 flex flex-wrap gap-2">
									{#each aliases as alias}
										<a href="/app/vuln/{alias}" class="inline-flex items-center rounded-full border border-[var(--border-color)] bg-[var(--hover-bg)] px-2 py-0.5 font-mono text-xs text-[var(--text-secondary)] transition hover:text-[var(--accent)]">{alias}</a>
									{/each}
								</div>
							</div>
						{/if}
						{#if cwes.length > 0}
							<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
								<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Weaknesses (CWE)</p>
								<div class="mt-2 flex flex-wrap gap-2">
									{#each cwes as cwe}
										<a href="https://cwe.mitre.org/data/definitions/{cwe.replace(/^CWE-/i, '')}.html" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-1 rounded-full border border-[var(--border-color)] bg-[var(--hover-bg)] px-2 py-0.5 font-mono text-xs text-[var(--text-secondary)] transition hover:text-[var(--accent)]">
											{cwe}<ExternalLink class="h-3 w-3" />
										</a>
									{/each}
								</div>
							</div>
						{/if}
					</div>
				{/if}
			{/if}
		</section>

		<!-- Affected repositories -->
		{#if data.affected_repos.length > 0}
			<section class="panel-surface space-y-4 px-6 py-8 sm:px-10 sm:py-10">
				<header class="flex items-center justify-between">
					<div>
						<h2 class="text-lg font-semibold text-[var(--text-bright)] inline-flex items-center gap-2">
							<GitBranch class="h-4 w-4 text-[var(--accent)]" /> Affected repositories ({data.repo_count})
						</h2>
						<p class="text-xs text-[var(--text-tertiary)]">Repositories containing a vulnerable component. Contributors load lazily per repo.</p>
					</div>
				</header>
				<div class="overflow-auto rounded-xl border border-[var(--border-color)]/60">
					<table class="min-w-full divide-y divide-[var(--border-color)]/40 text-sm">
						<thead class="bg-[var(--card-bg)] text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
							<tr>
								<th class="px-5 py-3 text-left">Repository</th>
								<th class="px-5 py-3 text-left">Package</th>
								<th class="px-5 py-3 text-left">Installed → Fix</th>
								<th class="px-5 py-3 text-left">Contributors</th>
								<th class="px-5 py-3 text-left">Last scan</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-[var(--border-color)]/40">
							{#each data.affected_repos as repo (repo.repo_id)}
								{@const link = repoPageLink(repo)}
								<tr class="transition hover:bg-[var(--hover-bg-subtle)]">
									<td class="px-5 py-3">
										<div class="flex flex-col">
											{#if link}
												<a href={link} class="font-semibold text-[var(--text-bright)] hover:text-[var(--accent)]">{repo.repo_slug}</a>
											{:else}
												<span class="font-semibold text-[var(--text-bright)]">{repo.repo_slug}</span>
											{/if}
											<span class="text-xs text-[var(--text-muted)]">{repo.provider}{repo.is_private ? ' · private' : ''}</span>
										</div>
									</td>
									<td class="px-5 py-3 font-mono text-xs text-[var(--text-secondary)]">{repo.pkg_name || '—'}</td>
									<td class="px-5 py-3 font-mono text-xs">
										<span class="text-[var(--text-secondary)]">{repo.installed_version || '—'}</span>
										{#if repo.fixed_version}
											<span class="text-[var(--text-muted)]"> → </span>
											<span class="text-[var(--success)]">{repo.fixed_version}</span>
										{/if}
									</td>
									<td class="px-5 py-3">
										{#if contributors[repo.repo_id] === undefined || contributors[repo.repo_id] === null}
											<span class="inline-block h-6 w-24 animate-pulse rounded bg-[var(--bg3)]/40"></span>
										{:else if contributors[repo.repo_id]!.length === 0}
											<span class="text-xs text-[var(--text-muted)]">—</span>
										{:else}
											<ContributorAvatars contributors={contributors[repo.repo_id] ?? []} max={5} />
										{/if}
									</td>
									<td class="px-5 py-3 text-xs text-[var(--text-tertiary)]">{fmtRelative(repo.scanned_at)}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</section>
		{/if}

		<!-- Affected images + cluster presence -->
		{#if data.affected_images.length > 0}
			<section class="panel-surface space-y-4 px-6 py-8 sm:px-10 sm:py-10">
				<header>
					<h2 class="text-lg font-semibold text-[var(--text-bright)] inline-flex items-center gap-2">
						<Container class="h-4 w-4 text-[var(--accent)]" /> Affected images ({data.image_count})
					</h2>
					<p class="text-xs text-[var(--text-tertiary)]">Container images carrying the vulnerable package, with the clusters and namespaces where they are currently running.</p>
				</header>
				<div class="space-y-4">
					{#each data.affected_images as img (img.image_id)}
						<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
							<div class="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
								<div class="min-w-0">
									<p class="font-mono text-sm font-semibold text-[var(--text-bright)] break-all">{img.image_slug}</p>
									<p class="mt-0.5 font-mono text-[10px] text-[var(--text-muted)] break-all">{img.image_digest}</p>
								</div>
								<div class="flex flex-wrap items-center gap-2 text-xs">
									<span class="rounded-full border border-[var(--border-color)] bg-[var(--hover-bg)] px-2 py-0.5 text-[var(--text-secondary)]">{img.source}</span>
									{#if img.verified_source}
										<span class="rounded-full border border-green-500/30 bg-green-500/10 px-2 py-0.5 text-[var(--success)]">verified source</span>
									{/if}
									<span class="text-[var(--text-tertiary)] inline-flex items-center gap-1"><Clock class="h-3 w-3" /> {fmtRelative(img.scanned_at)}</span>
								</div>
							</div>
							<div class="mt-3 flex flex-wrap items-center gap-3 text-xs">
								<span class="font-mono text-[var(--text-secondary)]">{img.pkg_name || '—'}</span>
								<span class="font-mono text-[var(--text-secondary)]">{img.installed_version || '—'}</span>
								{#if img.fixed_version}
									<span class="font-mono text-[var(--success)]">fix: {img.fixed_version}</span>
								{/if}
							</div>
							{#if img.clusters.length > 0}
								<div class="mt-4 border-t border-[var(--border-color)]/40 pt-3">
									<p class="mb-2 text-[10px] uppercase tracking-wider text-[var(--text-muted)] inline-flex items-center gap-1">
										<Server class="h-3 w-3" /> Running in {img.clusters.length} location{img.clusters.length === 1 ? '' : 's'}
									</p>
									<div class="flex flex-wrap gap-2">
										{#each img.clusters as c}
											<span class="inline-flex items-center gap-1.5 rounded-full border border-[var(--border-color)] bg-[var(--hover-bg)] px-2.5 py-1 text-xs">
												<span class="font-semibold text-[var(--text-bright)]">{c.cluster || c.cluster_id}</span>
												<span class="text-[var(--text-tertiary)]">/</span>
												<span class="font-mono text-[var(--text-secondary)]">{c.namespace}</span>
												<span class="text-[var(--text-muted)]">×{c.container_count}</span>
											</span>
										{/each}
									</div>
								</div>
							{:else}
								<p class="mt-3 text-xs text-[var(--text-muted)]">Not currently running in any accessible cluster.</p>
							{/if}
						</div>
					{/each}
				</div>
			</section>
		{/if}

		<!-- References -->
		{#if (data.enrichment?.references?.length ?? 0) > 0}
			<section class="panel-surface space-y-4 px-6 py-8 sm:px-10 sm:py-10">
				<header>
					<h2 class="text-lg font-semibold text-[var(--text-bright)]">References</h2>
					<p class="text-xs text-[var(--text-tertiary)]">External advisories, patches, and context cited by the data sources.</p>
				</header>
				<ul class="space-y-2">
					{#each data.enrichment!.references! as ref}
						<li class="flex items-start gap-3 rounded-xl border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40 p-3">
							<span class="inline-flex items-center rounded-full border border-[var(--border-color)] bg-[var(--hover-bg)] px-2 py-0.5 text-xs text-[var(--text-tertiary)]">{refTypeLabel(ref.type)}</span>
							<a href={ref.url} target="_blank" rel="noopener noreferrer" class="min-w-0 flex-1 truncate text-sm text-[var(--text-secondary)] transition hover:text-[var(--accent)]">
								{ref.url}
							</a>
							<ExternalLink class="h-3 w-3 text-[var(--text-tertiary)] shrink-0" />
						</li>
					{/each}
				</ul>
			</section>
		{/if}

		{#if data.affected_repos.length === 0 && data.affected_images.length === 0}
			<section class="panel-surface px-6 py-10 sm:px-10">
				<p class="text-sm text-[var(--text-tertiary)]">No affected repositories or images are currently visible to you. This may be because the vuln is only present on assets outside your access scope, or because scan results haven't been ingested yet.</p>
			</section>
		{/if}
	{/if}
</div>
