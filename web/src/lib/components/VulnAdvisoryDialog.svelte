<script lang="ts" module>
	// Shared across instances + page navigations within the SPA so
	// reopening the same advisory is instant.
	type VulnAffectedRepo = {
		repo_id: string;
		repo_slug: string;
		provider?: string;
		provider_instance_id?: string;
		org?: string;
		slug?: string;
	};
	type VulnAffectedImage = {
		image_id: string;
		image_slug: string;
		image_digest: string;
	};
	type VulnAuthority = {
		vuln_id: string;
		prefix: string;
		severity?: string;
		cvss_score?: number;
		cvss_vector?: string;
		is_primary: boolean;
	};
	export type VulnDetail = {
		vuln_id: string;
		title: string;
		description: string;
		severity: string;
		sources: string[];
		enrichment_loading?: boolean;
		kev_known?: boolean;
		kev_known_ransomware?: boolean;
		kev_date_added?: string;
		epss_score?: number;
		epss_percentile?: number;
		affected_repos?: VulnAffectedRepo[];
		affected_images?: VulnAffectedImage[];
		repo_count?: number;
		image_count?: number;
		authorities?: VulnAuthority[];
	};

	const detailCache = new Map<string, VulnDetail>();
</script>

<script lang="ts">
	import { AlertOctagon, AlertTriangle, ExternalLink, Info, X } from 'lucide-svelte';
	import Dialog from '$lib/components/Dialog.svelte';

	let { open = $bindable(false), vulnId = '' }: { open?: boolean; vulnId?: string } = $props();

	let detail = $state<VulnDetail | null>(null);
	let loading = $state(false);
	let loadedFor = $state('');

	const fetchDetail = async (id: string) => {
		loading = true;
		try {
			const res = await fetch(`/api/vulnerabilities/${encodeURIComponent(id)}`, {
				credentials: 'include'
			});
			if (!res.ok) throw new Error(`HTTP ${res.status}`);
			const d: VulnDetail = await res.json();
			detailCache.set(id, d);
			if (id === vulnId) detail = d;
			// Backend enqueues a VULN_META_FETCH on cache miss; re-poll
			// once so the description fills in without a manual reopen.
			if (d.enrichment_loading && !d.description) {
				setTimeout(async () => {
					try {
						const r2 = await fetch(`/api/vulnerabilities/${encodeURIComponent(id)}`, {
							credentials: 'include'
						});
						if (r2.ok) {
							const d2: VulnDetail = await r2.json();
							if (!d2.enrichment_loading || d2.description) {
								detailCache.set(id, d2);
								if (id === vulnId) detail = d2;
							}
						}
					} catch {
						/* ignore re-poll errors */
					}
				}, 3000);
			}
		} catch {
			if (id === vulnId) detail = null;
		} finally {
			if (id === vulnId) loading = false;
		}
	};

	$effect(() => {
		if (!open || !vulnId) return;
		if (loadedFor === vulnId) return;
		loadedFor = vulnId;
		const cached = detailCache.get(vulnId);
		if (cached) {
			detail = cached;
			loading = false;
			return;
		}
		detail = null;
		void fetchDetail(vulnId);
	});

	const shortDigest = (digest: string | undefined | null) => {
		if (!digest) return '';
		const i = digest.indexOf(':');
		if (i < 0) return digest.slice(0, 12);
		return digest.slice(0, i + 13);
	};

	const formatShortDate = (iso: string | undefined) => {
		if (!iso) return '—';
		return new Date(iso).toLocaleDateString();
	};

	const severityClass = (s: string) => {
		switch (s?.toUpperCase()) {
			case 'CRITICAL': return 'text-red-400 border-red-500/40 bg-red-500/10';
			case 'HIGH':     return 'text-orange-400 border-orange-500/40 bg-orange-500/10';
			case 'MEDIUM':   return 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10';
			case 'LOW':      return 'text-blue-400 border-blue-500/40 bg-blue-500/10';
			default:         return 'text-[var(--text-muted)] border-[var(--border-color)] bg-transparent';
		}
	};

	const severityTextClass = (s: string) => {
		switch (s?.toUpperCase()) {
			case 'CRITICAL': return 'text-red-400';
			case 'HIGH':     return 'text-orange-400';
			case 'MEDIUM':   return 'text-yellow-400';
			case 'LOW':      return 'text-blue-400';
			default:         return 'text-[var(--text-muted)]';
		}
	};

	// Header icon mirrors the severity pill palette (same tailwind
	// tones severityClass uses) so the dialog reads at a glance.
	const sevIcon = (s?: string) => {
		switch (s?.toUpperCase()) {
			case 'CRITICAL': return { icon: AlertOctagon, cls: 'text-red-400 bg-red-500/10' };
			case 'HIGH':     return { icon: AlertTriangle, cls: 'text-orange-400 bg-orange-500/10' };
			case 'MEDIUM':   return { icon: AlertTriangle, cls: 'text-yellow-400 bg-yellow-500/10' };
			case 'LOW':      return { icon: Info, cls: 'text-blue-400 bg-blue-500/10' };
			default:         return { icon: Info, cls: 'text-[var(--text-muted)] bg-[var(--hover-bg-subtle)]' };
		}
	};

	const vulnUrl = (id: string) => `/vuln/${encodeURIComponent(id)}`;

	// Canonical external advisory link for the given vuln id. CVE-* → NVD
	// gets users the CVSS vector + CWE; GHSA / BIT / GO / PYSEC / OSV-* go
	// to the authority that publishes them. Anything we don't recognise
	// falls back to OSV.dev which aggregates most ecosystems.
	const advisoryLink = (id: string): { href: string; label: string } => {
		const u = id.toUpperCase();
		if (u.startsWith('CVE-')) return { href: `https://nvd.nist.gov/vuln/detail/${id}`, label: 'NVD' };
		if (u.startsWith('GHSA-')) return { href: `https://github.com/advisories/${id}`, label: 'GitHub Advisory' };
		if (u.startsWith('GO-')) return { href: `https://pkg.go.dev/vuln/${id}`, label: 'Go vuln DB' };
		if (u.startsWith('PYSEC-')) return { href: `https://osv.dev/vulnerability/${id}`, label: 'OSV.dev' };
		if (u.startsWith('RUSTSEC-')) return { href: `https://rustsec.org/advisories/${id}`, label: 'RustSec' };
		if (u.startsWith('BIT-')) return { href: `https://github.com/bitnami/vulndb`, label: 'Bitnami VulnDB' };
		return { href: `https://osv.dev/vulnerability/${id}`, label: 'OSV.dev' };
	};
</script>

<Dialog bind:open maxWidth="max-w-4xl" showCloseButton={false}>
	{#snippet children()}
		{@const d = detail}
		{@const adv = vulnId ? advisoryLink(vulnId) : { href: '', label: '' }}
		{@const sev = sevIcon(d?.severity)}
		{@const SevIcon = sev.icon}
		<div class="flex h-full min-h-0 flex-col">
			<header class="flex items-start justify-between gap-4 px-6 pb-4 pt-5">
				<div class="flex min-w-0 flex-1 items-start gap-3.5">
					<div class="flex h-11 w-11 shrink-0 items-center justify-center rounded-full {sev.cls}">
						<SevIcon size={22} />
					</div>
					<div class="min-w-0 flex-1">
						<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Advisory</p>
						<div class="mt-1 flex min-w-0 flex-wrap items-center gap-2.5">
							<h2 class="truncate font-mono text-lg font-semibold leading-none text-[var(--text-bright)]">{vulnId}</h2>
							{#if d?.severity}
								<span class="inline-flex items-center rounded-full border px-2 py-1 text-xs font-semibold leading-none {severityClass(d.severity)}">
									{d.severity}
								</span>
							{/if}
							{#if d?.kev_known}
								<span class="inline-flex items-center rounded-full border border-red-500/40 bg-red-500/10 px-2 py-1 text-xs font-semibold leading-none text-red-400">
									KEV{d.kev_known_ransomware ? ' · ransomware' : ''}
								</span>
							{/if}
						</div>
						{#if d?.title}
							<p class="mt-1.5 text-sm leading-snug text-[var(--text-secondary)]">{d.title}</p>
						{/if}
					</div>
				</div>
				<div class="flex shrink-0 items-center gap-1.5">
					<a class="btn btn-primary px-3 py-1.5 text-xs !shadow-none" href={vulnUrl(vulnId)}>
						Full page
						<ExternalLink class="h-3 w-3" />
					</a>
					<a class="btn btn-primary px-3 py-1.5 text-xs !shadow-none" href={adv.href} target="_blank" rel="noopener noreferrer">
						{adv.label}
						<ExternalLink class="h-3 w-3" />
					</a>
					<button
						type="button"
						class="flex h-8 w-8 items-center justify-center rounded-lg text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)]"
						aria-label="Close"
						onclick={() => (open = false)}
					>
						<X size={16} />
					</button>
				</div>
			</header>
			<div class="flex-1 space-y-5 overflow-y-auto px-6 pb-6">
				{#if loading || !d}
					<div class="flex items-center gap-2 py-12 text-sm text-[var(--text-tertiary)]">
						<div class="h-4 w-4 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
						Loading advisory…
					</div>
				{:else}
					<!-- Exploitation signals -->
					<div class="grid gap-3 sm:grid-cols-3">
						<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
							<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">EPSS</p>
							{#if d.epss_score !== undefined && d.epss_score !== null && d.epss_score > 0}
								<p class="mt-2 text-2xl font-semibold {d.epss_score >= 0.1 ? 'text-[var(--warning)]' : 'text-[var(--text-bright)]'}">
									{(d.epss_score * 100).toFixed(1)}%
								</p>
								<p class="mt-1 text-xs leading-relaxed text-[var(--text-tertiary)]">
									chance of exploitation within 30 days{#if d.epss_percentile !== undefined && d.epss_percentile !== null}
										· above {(d.epss_percentile * 100).toFixed(0)}% of all CVEs{/if}
								</p>
							{:else}
								<p class="mt-2 text-2xl font-semibold text-[var(--text-muted)]">—</p>
								<p class="mt-1 text-xs text-[var(--text-tertiary)]">no exploit-prediction data</p>
							{/if}
						</div>
						<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
							<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">CISA KEV</p>
							{#if d.kev_known}
								<p class="mt-2 text-2xl font-semibold text-red-400">Listed</p>
								<p class="mt-1 text-xs leading-relaxed text-[var(--text-tertiary)]">
									confirmed exploited in the wild{#if d.kev_date_added}
										· added {formatShortDate(d.kev_date_added)}{/if}{#if d.kev_known_ransomware}
										· used by ransomware{/if}
								</p>
							{:else}
								<p class="mt-2 text-2xl font-semibold text-[var(--text-muted)]">No</p>
								<p class="mt-1 text-xs text-[var(--text-tertiary)]">no confirmed in-the-wild exploitation</p>
							{/if}
						</div>
						<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
							<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Severity</p>
							{#if d.severity}
								{@const primary = d.authorities?.find((a) => a.is_primary) ?? d.authorities?.[0]}
								<p class="mt-2 text-2xl font-semibold {severityTextClass(d.severity)}">
									{d.severity}
								</p>
								<p class="mt-1 text-xs leading-relaxed text-[var(--text-tertiary)]">
									{#if primary && primary.cvss_score !== undefined && primary.cvss_score !== null && primary.cvss_score > 0}
										CVSS {primary.cvss_score.toFixed(1)} · {primary.vuln_id}
									{:else}
										no CVSS score published yet
									{/if}
								</p>
							{:else}
								<p class="mt-2 text-2xl font-semibold text-[var(--text-muted)]">—</p>
								<p class="mt-1 text-xs text-[var(--text-tertiary)]">not rated by any authority</p>
							{/if}
						</div>
					</div>

					{#if d.description}
						<p class="whitespace-pre-line text-sm leading-relaxed text-[var(--text-secondary)]">{d.description}</p>
					{:else if d.enrichment_loading}
						<p class="text-xs italic text-[var(--text-muted)]">Enriching from upstream feeds — re-open in a moment.</p>
					{:else}
						<p class="text-xs italic text-[var(--text-muted)]">No description available. Use the {adv.label} link above.</p>
					{/if}

					{#if d.authorities && d.authorities.length > 1}
						<div>
							<p class="mb-2 text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Severity by authority</p>
							<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
								<table class="min-w-full border-separate border-spacing-0 text-sm">
									<thead class="text-xs uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
										<tr>
											<th class="border-b border-[var(--border-color)]/40 px-3 py-2 text-left font-medium">ID</th>
											<th class="border-b border-[var(--border-color)]/40 px-3 py-2 text-left font-medium">Severity</th>
											<th class="border-b border-[var(--border-color)]/40 px-3 py-2 text-left font-medium">Vector</th>
										</tr>
									</thead>
									<tbody class="text-[var(--text-secondary)]">
										{#each d.authorities as a, idx (a.vuln_id)}
											{@const isLast = idx === (d.authorities?.length ?? 0) - 1}
											<tr>
												<td class="{isLast ? '' : 'border-b border-[var(--border-color)]/20 '}whitespace-nowrap px-3 py-1.5 font-mono text-xs text-[var(--text-bright)]">
													{a.vuln_id}{#if a.is_primary} <span class="ml-1 rounded-full bg-[var(--accent)]/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase text-[var(--accent)]">primary</span>{/if}
												</td>
												<td class="{isLast ? '' : 'border-b border-[var(--border-color)]/20 '}px-3 py-1.5">
													{#if a.severity}
														<span class="inline-flex items-center rounded-full border px-2 py-1 text-xs font-semibold leading-none {severityClass(a.severity)}">
															{a.severity}
														</span>
													{:else}
														<span class="text-xs text-[var(--text-muted)]">—</span>
													{/if}
												</td>
												<td class="{isLast ? '' : 'border-b border-[var(--border-color)]/20 '}px-3 py-1.5 truncate font-mono text-[11px] text-[var(--text-tertiary)]" title={a.cvss_vector ?? ''}>
													{a.cvss_vector || '—'}
												</td>
											</tr>
										{/each}
									</tbody>
								</table>
							</div>
						</div>
					{/if}

					{#if (d.affected_repos && d.affected_repos.length > 0) || (d.affected_images && d.affected_images.length > 0)}
						<div class="grid gap-4 lg:grid-cols-2">
							{#if d.affected_repos && d.affected_repos.length > 0}
								<div>
									<p class="mb-2 text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">
										Affected repos
										{#if d.repo_count !== undefined && d.repo_count > d.affected_repos.length}
											<span class="ml-1 text-[10px] font-normal normal-case text-[var(--text-muted)]">first {d.affected_repos.length} of {d.repo_count}</span>
										{/if}
									</p>
									<ul class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
										{#each d.affected_repos.slice(0, 8) as r, idx (r.repo_id)}
											{@const isLast = idx === Math.min(d.affected_repos?.length ?? 0, 8) - 1}
											<li class="{isLast ? '' : 'border-b border-[var(--border-color)]/30 '}flex items-center justify-between gap-3 px-3 py-2 text-xs">
												<span class="min-w-0 truncate font-mono text-[var(--text-bright)]" title={r.repo_slug}>
													{r.repo_slug || r.repo_id}
												</span>
												<a
													class="btn btn-warning shrink-0 py-1 px-2.5 text-[11px]"
													href={`/providers/repo?repo_id=${r.repo_id}${r.provider_instance_id ? `&provider_id=${r.provider_instance_id}` : ''}`}
												>
													Open
													<ExternalLink class="h-3 w-3" />
												</a>
											</li>
										{/each}
									</ul>
								</div>
							{/if}

							{#if d.affected_images && d.affected_images.length > 0}
								<div>
									<p class="mb-2 text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">
										Affected images
										{#if d.image_count !== undefined && d.image_count > d.affected_images.length}
											<span class="ml-1 text-[10px] font-normal normal-case text-[var(--text-muted)]">first {d.affected_images.length} of {d.image_count}</span>
										{/if}
									</p>
									<ul class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
										{#each d.affected_images.slice(0, 8) as i, idx (i.image_id)}
											{@const isLast = idx === Math.min(d.affected_images?.length ?? 0, 8) - 1}
											<li class="{isLast ? '' : 'border-b border-[var(--border-color)]/30 '}flex items-center justify-between gap-3 px-3 py-2 text-xs">
												<div class="min-w-0 flex-1">
													<p class="truncate font-mono text-[var(--text-bright)]" title={i.image_slug}>{i.image_slug}</p>
													{#if i.image_digest}
														<p class="truncate font-mono text-[10px] text-[var(--text-tertiary)]">@{shortDigest(i.image_digest)}</p>
													{/if}
												</div>
												{#if i.image_digest}
													<a
														class="btn btn-warning shrink-0 py-1 px-2.5 text-[11px]"
														href={`/images/${encodeURIComponent(i.image_digest)}`}
													>
														Open
														<ExternalLink class="h-3 w-3" />
													</a>
												{/if}
											</li>
										{/each}
									</ul>
								</div>
							{/if}
						</div>
					{/if}

					{#if d.sources && d.sources.length > 0}
						<div class="flex flex-wrap items-center gap-1.5">
							<span class="text-xs uppercase leading-none tracking-[0.2em] text-[var(--text-muted)]">Sources</span>
							{#each d.sources as s}
								<span class="inline-flex items-center rounded-full bg-[var(--hover-bg-subtle)] px-2 py-1 text-[11px] leading-none text-[var(--text-tertiary)]">{s}</span>
							{/each}
						</div>
					{/if}
				{/if}
			</div>
		</div>
	{/snippet}
</Dialog>
