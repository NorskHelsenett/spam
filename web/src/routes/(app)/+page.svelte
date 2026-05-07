<script lang="ts">
	import { browser } from '$app/environment';
	import {
		Search,
		ShieldAlert,
		AlertTriangle,
		Eye,
		Container,
		GitBranch,
		ShieldCheck,
		Target,
		ChevronDown,
		ArrowUpRight
	} from 'lucide-svelte';
	import KubernetesIcon from '$lib/components/icons/KubernetesIcon.svelte';
	import EmptyVulns from '$lib/components/icons/EmptyVulns.svelte';
	import Loading from '$lib/components/Loading.svelte';
	import DonutChart from '$lib/components/DonutChart.svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';

	// DonutSegment is exported from DonutChart.svelte but svelte-check
	// fails to resolve type-only imports across the legacy export-let
	// boundary; inline the same shape here.
	type DonutSegment = { label: string; value: number; color: string };

	// --- Types mirror api/internal/assetrisk wire format ---
	type Reason = { id: string; fields?: Record<string, unknown> };
	type TriageRow = {
		asset_type: 'repo' | 'image' | 'cluster';
		asset_id: string;
		asset_slug: string;
		critical_count: number;
		high_count: number;
		kev_count: number;
		epss_max: number;
		has_fix_for_critical: boolean;
		active_secret_count: number;
		internet_exposed: boolean;
		signed_commits_pct: number;
		image_signed: boolean;
		scan_age_days: number;
		last_scan_at: string | null;
		has_sbom: boolean;
		worst_dep_health_score: number;
		archived_dep_count: number;
		deprecated_dep_count: number;
		max_major_behind: number;
		major_behind_dep_count: number;
		threat_score: number;
		trust_score: number;
		trust_grade: string;
		tier: 'fix_now' | 'this_week' | 'watch';
		reasons: Reason[];
	};
	type Scope = {
		clusters: number;
		repos: number;
		images: number;
		needs_attention: number;
		view_refreshed_at: string | null;
	};
	type WatchCounts = { total: number; repo: number; image: number; cluster: number };
	type WatchSection = { counts: WatchCounts; limit: number; offset: number; rows: TriageRow[] };
	type TriageResponse = {
		scope: Scope;
		fix_now: TriageRow[];
		this_week: TriageRow[];
		watch: WatchSection;
	};

	let triage: TriageResponse | null = $state(null);
	let loading = $state(true);
	let error = $state('');
	let watchSearch = $state('');
	let watchOffset = $state(0);
	let activeTab = $state<'all' | 'repo' | 'image' | 'cluster'>('all');
	// Per-row expansion state for the "show your work" panel. Keyed
	// by `${asset_type}:${asset_id}` so collapsing one row doesn't
	// collapse the row-with-the-same-id-in-another-tier (rare, but
	// happens when the same id is reused across asset types).
	let expanded = $state(new Set<string>());
	let searchTimer: ReturnType<typeof setTimeout> | null = null;

	const rowKey = (r: TriageRow) => `${r.asset_type}:${r.asset_id}`;
	const toggleExpanded = (key: string) => {
		const next = new Set(expanded);
		if (next.has(key)) next.delete(key);
		else next.add(key);
		expanded = next;
	};

	const fetchTriage = async (search: string, offset: number) => {
		const params = new URLSearchParams();
		if (search.trim()) params.set('watch_q', search.trim());
		if (offset > 0) params.set('watch_offset', String(offset));
		const res = await fetch(`/api/triage?${params}`, { credentials: 'include' });
		if (!res.ok) throw new Error(`Failed to load triage (HTTP ${res.status})`);
		return (await res.json()) as TriageResponse;
	};

	const reload = async () => {
		try {
			triage = await fetchTriage(watchSearch, watchOffset);
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to load triage';
		} finally {
			loading = false;
		}
	};

	if (browser) {
		void reload();
	}

	const onSearchInput = () => {
		if (searchTimer) clearTimeout(searchTimer);
		searchTimer = setTimeout(() => {
			watchOffset = 0;
			void reload();
		}, 250);
	};

	const goNextPage = () => {
		if (!triage) return;
		const next = watchOffset + triage.watch.limit;
		if (next >= triage.watch.counts.total) return;
		watchOffset = next;
		void reload();
	};
	const goPrevPage = () => {
		if (!triage || watchOffset === 0) return;
		watchOffset = Math.max(0, watchOffset - triage.watch.limit);
		void reload();
	};

	const fmt = (n: number) => new Intl.NumberFormat('en-US').format(n);

	// Reason templates — pre-rendered for now; the API returns the
	// structured {id, fields} so a future LLM step can swap renderer
	// without touching the API.
	const renderReason = (r: Reason): string => {
		const f = r.fields ?? {};
		switch (r.id) {
			case 'active_secret_leak':
				return `${f.count} active secret${(f.count as number) === 1 ? '' : 's'}`;
			case 'kev_and_exposed':
				return `${f.kev_count} KEV on exposed workload`;
			case 'kev_present':
				return `${f.kev_count} KEV CVE${(f.kev_count as number) === 1 ? '' : 's'}`;
			case 'epss_very_high':
				return `EPSS ${(((f.epss_max as number) ?? 0) * 100).toFixed(0)}%`;
			case 'epss_elevated':
				return `EPSS ${(((f.epss_max as number) ?? 0) * 100).toFixed(0)}%`;
			case 'critical_severity':
				return `${f.critical} Critical${f.has_fix ? ' (fix avail.)' : ''}`;
			case 'scan_stale':
				return `Scan ${f.days}d old`;
			case 'low_commit_signing':
				return `${Math.round((f.signed_pct as number) ?? 0)}% commits signed`;
			case 'image_unsigned':
				return `Unsigned image`;
			case 'no_sbom':
				return `No SBOM`;
			case 'archived_deps':
				return `${f.count} archived dep${(f.count as number) === 1 ? '' : 's'}`;
			case 'deprecated_deps':
				return `${f.count} deprecated dep${(f.count as number) === 1 ? '' : 's'}`;
			case 'low_dep_health':
				return `Worst dep health ${Math.round((f.worst_score as number) ?? 0)}/100`;
			case 'major_behind':
				return `${f.count} dep${(f.count as number) === 1 ? '' : 's'} ≥${f.max_major} major behind`;
			default:
				return r.id;
		}
	};

	// Plain-English explanation per reason ID. Returned as
	// { what, why, action } so the expansion panel can render a
	// "what's wrong / why it matters / fix this by …" card per
	// reason instead of just repeating the headline pill.
	const reasonExplain = (r: Reason): { what: string; why: string; action: string } => {
		const f = r.fields ?? {};
		switch (r.id) {
			case 'active_secret_leak':
				return {
					what: `${f.count} live credential${(f.count as number) === 1 ? '' : 's'} found in this repo were probed and confirmed still valid.`,
					why: 'A leaked secret that still authenticates is the highest-impact finding in the queue — anyone who has the repo (or the commit history) has the keys.',
					action: 'Rotate each leaked secret at the issuing provider, then scrub the value from git history (e.g. `git filter-repo`). The dismiss workflow only suppresses the finding — it does not invalidate the credential.'
				};
			case 'kev_and_exposed':
				return {
					what: `${f.kev_count} CVE${(f.kev_count as number) === 1 ? '' : 's'} on this asset are listed in CISA's Known Exploited Vulnerabilities catalogue, and the workload is reachable from the internet.`,
					why: 'KEV is the authoritative "we have seen this exploited in the wild" list. Combined with internet reach, this is the single highest-priority class of finding — public exploits typically exist.',
					action: 'Patch or remove the affected component immediately. If a fix release is unavailable, consider taking the workload offline behind authentication or a WAF until upstream lands a fix.'
				};
			case 'kev_present':
				return {
					what: `${f.kev_count} CVE${(f.kev_count as number) === 1 ? '' : 's'} on this asset are in CISA's Known Exploited Vulnerabilities catalogue.`,
					why: "KEV CVEs have confirmed in-the-wild exploitation. Even when the asset isn't internet-exposed today, exploit code is generally public — any future exposure path is high-risk.",
					action: 'Apply the fix-available upgrade for the affected package. If you intentionally accept the risk (mitigating control, not reachable, etc.), record a VEX `not_affected` so triage stops surfacing it.'
				};
			case 'epss_very_high':
				return {
					what: `At least one CVE on this asset has an EPSS score of ${(((f.epss_max as number) ?? 0) * 100).toFixed(0)}% — predicted probability of exploitation in the next 30 days.`,
					why: '50%+ EPSS is the operational "act this sprint" threshold. Vulns with very-high EPSS are usually weaponised before they hit KEV.',
					action: 'Patch the highest-EPSS CVE first; the affected component is named in the asset detail view.'
				};
			case 'epss_elevated':
				return {
					what: `A CVE on this asset has elevated EPSS (${(((f.epss_max as number) ?? 0) * 100).toFixed(0)}%) — 10–50% predicted exploitation in the next 30 days.`,
					why: 'Elevated EPSS means real-world signal of exploitability is rising. Most vulns never reach this threshold.',
					action: 'Schedule the upgrade in the current sprint. Keep an eye on EPSS — a jump above 50% means escalating to "act now".'
				};
			case 'critical_severity':
				return {
					what: `${f.critical} CRITICAL CVE${(f.critical as number) === 1 ? '' : 's'} on this asset${f.has_fix ? ' — at least one has a fix release available' : ' — no fix release available yet'}.`,
					why: 'CRITICAL severity per the scanner means CVSS≥9.0 (or vendor equivalent). These are the loudest items by impact alone.',
					action: f.has_fix
						? 'Upgrade the affected package to the fix version. The asset detail view lists each CVE with its fixed_version.'
						: 'Pin the vulnerable version, monitor for an upstream fix, and consider VEX `under_investigation` so triage shows the active reasoning.'
				};
			case 'scan_stale':
				return {
					what: `Last scan finished ${f.days as number === 999 ? 'never' : `${f.days} days ago`} — older than the 30-day freshness threshold.`,
					why: "Stale scans means the asset's *current* threat state is unknown. Fixing a CVE doesn't help if you can't tell whether the fix landed; nor does adding one if you can't tell when it appeared.",
					action: 'Trigger a re-scan from the asset detail page. If scans never run, check the runner config — the asset may be missing a provider binding.'
				};
			case 'low_commit_signing':
				return {
					what: `${Math.round((f.signed_pct as number) ?? 0)}% of recent commits carry verified signatures.`,
					why: 'Without signed commits, anything appearing in the repo history could have been pushed by anyone with the right SSH key — there is no cryptographic record of who actually authored the change.',
					action: 'Enforce signed commits in branch protection (GitHub/GitLab supports this), back-fill keys for active contributors, and require signatures for protected branches.'
				};
			case 'image_unsigned':
				return {
					what: 'This image was not built through a signing pipeline (cosign / sigstore).',
					why: "An unsigned image's chain of custody can't be verified — there's no way to prove the image you pulled is the one CI built. A compromised registry can swap binaries undetected.",
					action: 'Wire `cosign sign` into the build pipeline and configure a verification policy in admin → signing so unsigned images fail to deploy.'
				};
			case 'no_sbom':
				return {
					what: 'No SBOM exists for this asset, so the dependency inventory is unknown.',
					why: "Triage is only as good as the inventory. With no SBOM, vuln scans miss anything that isn't directly in the image layer index, and dep-health analysis can't run at all.",
					action: 'Trigger an SBOM scan from the asset detail page. For images, syft/trivy can generate one at scan time; for repos, ensure manifests are detected.'
				};
			case 'archived_deps':
				return {
					what: `${f.count} direct dependenc${(f.count as number) === 1 ? 'y is' : 'ies are'} marked archived by their upstream registry.`,
					why: 'Archived packages no longer receive security fixes. Any CVE found later will stay unfixed unless someone forks and maintains the code.',
					action: 'Replace each archived dep with a maintained alternative (the dep-health detail view names them). For genuinely-stable libraries, vendor the source so at least the supply chain is yours.'
				};
			case 'deprecated_deps':
				return {
					what: `${f.count} direct dependenc${(f.count as number) === 1 ? 'y is' : 'ies are'} flagged deprecated by the upstream registry.`,
					why: 'Deprecated packages typically point to a successor or a security advisory. Continuing to depend on them means missing the migration window.',
					action: 'Check each deprecated package\'s registry page for the recommended successor and migrate. The dep-health view shows the deprecation note when one is available.'
				};
			case 'low_dep_health':
				return {
					what: `Worst direct-dep health score is ${Math.round((f.worst_score as number) ?? 0)}/100 (single-maintainer / no recent activity / few downloads).`,
					why: 'Low dep-health scores mean bus-factor risk: a critical fix may take months or never land. The package itself may not be vulnerable today, but the supply-chain trust is thin.',
					action: 'Identify the lowest-scoring deps in the asset detail view and evaluate replacements. Fork-and-maintain only if the package is genuinely critical and replacement is impractical.'
				};
			case 'major_behind':
				return {
					what: `${f.count} direct dependenc${(f.count as number) === 1 ? 'y is' : 'ies are'} at least ${f.max_major} major version${(f.max_major as number) === 1 ? '' : 's'} behind their latest release.`,
					why: 'Major-version drift means the asset is outside upstream security support windows for those packages. CVE fixes typically land on the most recent two majors.',
					action: 'Plan an upgrade pass for the major-behind deps. Major-version bumps usually need code changes, so budget time accordingly.'
				};
			default:
				return {
					what: r.id,
					why: 'No description available.',
					action: ''
				};
		}
	};

	const reasonPillClass = (id: string): string => {
		switch (id) {
			case 'active_secret_leak':
			case 'kev_and_exposed':
			case 'kev_present':
				return 'pill pill-error';
			case 'epss_very_high':
			case 'epss_elevated':
			case 'critical_severity':
			case 'scan_stale':
			case 'archived_deps':
			case 'deprecated_deps':
			case 'low_dep_health':
				return 'pill pill-warning';
			default:
				return 'pill pill-neutral';
		}
	};

	const rowHref = (r: TriageRow): string => {
		if (r.asset_type === 'repo') return `/providers/repo?repo_id=${encodeURIComponent(r.asset_id)}`;
		if (r.asset_type === 'image') return `/images/${encodeURIComponent(r.asset_id)}`;
		return `/clusters?cluster_id=${encodeURIComponent(r.asset_id)}`;
	};

	const rowIcon = (assetType: string) => {
		if (assetType === 'repo') return GitBranch;
		if (assetType === 'image') return Container;
		return KubernetesIcon;
	};

	const trustColor = (grade: string): string => {
		if (grade.startsWith('A')) return 'var(--success)';
		if (grade.startsWith('B')) return 'var(--accent)';
		if (grade === 'C') return 'var(--warning)';
		return 'var(--error)';
	};

	// Threat-side raw inputs for the expansion panel. Returned as
	// {label, value, dim} so the renderer doesn't need its own
	// formatting logic and can grey out zero rows.
	const threatBreakdown = (r: TriageRow) => {
		const epssPct = r.epss_max > 0 ? `${(r.epss_max * 100).toFixed(1)}%` : '—';
		return [
			{ label: 'Critical CVEs', value: r.critical_count, dim: r.critical_count === 0 },
			{ label: 'High CVEs', value: r.high_count, dim: r.high_count === 0 },
			{ label: 'KEV CVEs', value: r.kev_count, dim: r.kev_count === 0 },
			{ label: 'EPSS max', value: epssPct, dim: r.epss_max === 0 },
			{ label: 'Active secrets', value: r.active_secret_count, dim: r.active_secret_count === 0 },
			{ label: 'Internet exposed', value: r.internet_exposed ? 'Yes' : 'No', dim: !r.internet_exposed },
			{ label: 'Critical w/ fix', value: r.has_fix_for_critical ? 'Yes' : 'No', dim: !r.has_fix_for_critical }
		];
	};

	const trustBreakdown = (r: TriageRow) => {
		const scanLabel = r.scan_age_days >= 999 ? 'Never' : `${r.scan_age_days}d ago`;
		const out: { label: string; value: string | number; dim: boolean }[] = [];
		if (r.asset_type === 'repo') {
			out.push({ label: 'Signed commits (90d)', value: `${Math.round(r.signed_commits_pct)}%`, dim: r.signed_commits_pct === 0 });
		}
		if (r.asset_type === 'image') {
			out.push({ label: 'Image signed', value: r.image_signed ? 'Yes' : 'No', dim: !r.image_signed });
		}
		out.push(
			{ label: 'Last scan', value: scanLabel, dim: r.scan_age_days >= 999 },
			{ label: 'Has SBOM', value: r.has_sbom ? 'Yes' : 'No', dim: !r.has_sbom },
			{ label: 'Worst dep health', value: Math.round(r.worst_dep_health_score), dim: r.worst_dep_health_score >= 100 },
			{ label: 'Archived deps', value: r.archived_dep_count, dim: r.archived_dep_count === 0 },
			{ label: 'Deprecated deps', value: r.deprecated_dep_count, dim: r.deprecated_dep_count === 0 },
			{ label: 'Major-behind deps', value: r.major_behind_dep_count, dim: r.major_behind_dep_count === 0 }
		);
		return out;
	};

	// Average trust score across all visible tiers — rough proxy for
	// the operator's overall posture. Excludes assets that fall below
	// the actionable threshold (the API drops those server-side).
	const avgTrust = $derived(() => {
		if (!triage) return null;
		const all = [...triage.fix_now, ...triage.this_week, ...triage.watch.rows];
		if (all.length === 0) return null;
		const sum = all.reduce((acc, r) => acc + r.trust_score, 0);
		return Math.round(sum / all.length);
	});

	// Asset-type distribution donut: how does the "needs attention"
	// population break down across repos / images / clusters? Helps
	// the operator orient on where to invest tooling.
	const distributionSegments = $derived((): DonutSegment[] => {
		if (!triage) return [];
		const counts = { repo: 0, image: 0, cluster: 0 };
		for (const r of [...triage.fix_now, ...triage.this_week]) {
			counts[r.asset_type]++;
		}
		// Watch counts already pre-bucketed in the response.
		counts.repo += triage.watch.counts.repo;
		counts.image += triage.watch.counts.image;
		counts.cluster += triage.watch.counts.cluster;
		const segs: DonutSegment[] = [];
		if (counts.repo > 0) segs.push({ label: 'Repos', value: counts.repo, color: 'var(--accent)' });
		if (counts.image > 0) segs.push({ label: 'Images', value: counts.image, color: 'var(--info)' });
		if (counts.cluster > 0) segs.push({ label: 'Clusters', value: counts.cluster, color: 'var(--warning)' });
		return segs;
	});

	const distributionTotal = $derived(() => {
		const segs = distributionSegments();
		return segs.reduce((a, b) => a + b.value, 0);
	});

	const tierSegments = $derived((): DonutSegment[] => {
		if (!triage) return [];
		const segs: DonutSegment[] = [];
		if (triage.fix_now.length > 0) segs.push({ label: 'Fix now', value: triage.fix_now.length, color: 'var(--error)' });
		if (triage.this_week.length > 0) segs.push({ label: 'This week', value: triage.this_week.length, color: 'var(--warning)' });
		if (triage.watch.counts.total > 0) segs.push({ label: 'Watch', value: triage.watch.counts.total, color: 'var(--text-muted)' });
		return segs;
	});

	const tierTotal = $derived(() => {
		if (!triage) return 0;
		return triage.fix_now.length + triage.this_week.length + triage.watch.counts.total;
	});

	// Tab filter applied client-side over already-fetched lists.
	// Watch is paginated server-side, so client-tab on watch is just
	// a visual filter on the current page; users searching for
	// "this image is in watch" should use the search field too.
	const filterByTab = (rows: TriageRow[]): TriageRow[] => {
		if (activeTab === 'all') return rows;
		return rows.filter((r) => r.asset_type === activeTab);
	};

	const fixNowFiltered = $derived(() => triage ? filterByTab(triage.fix_now) : []);
	const thisWeekFiltered = $derived(() => triage ? filterByTab(triage.this_week) : []);
	const watchFiltered = $derived(() => triage ? filterByTab(triage.watch.rows) : []);

	// Total count for the active tab — shown under the Findings header.
	// Includes server-side watch counts (which are pre-filtered by tab
	// using the .counts.{repo,image,cluster} buckets the API returns)
	// so the number is accurate even when the watch page on screen is
	// just a slice of the full set.
	const activeTabTotal = $derived(() => {
		if (!triage) return 0;
		if (activeTab === 'all') {
			return triage.fix_now.length + triage.this_week.length + triage.watch.counts.total;
		}
		const fix = triage.fix_now.filter((r) => r.asset_type === activeTab).length;
		const week = triage.this_week.filter((r) => r.asset_type === activeTab).length;
		const watch = triage.watch.counts[activeTab];
		return fix + week + watch;
	});

	const activeTabLabel = $derived(() => {
		if (activeTab === 'all') return 'asset';
		if (activeTab === 'repo') return 'repo';
		if (activeTab === 'image') return 'image';
		return 'cluster';
	});
</script>

<svelte:head>
	<title>Triage • Spam Monitor</title>
</svelte:head>

<div class="space-y-4">
	<!-- Stats + charts panel -->
	<article class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<div class="flex items-center justify-between gap-3">
				<div class="flex items-center gap-3">
					<Target class="h-10 w-10 flex-shrink-0 text-[var(--accent)]" />
					<div>
						<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Triage</h1>
						<p class="text-sm text-[var(--text-tertiary)]">Asset-centric "fix this now" view across repos, images, and clusters.</p>
					</div>
				</div>
			</div>
		</header>

		{#if loading}
			<div class="flex items-center justify-center py-20">
				<Loading message="Loading triage" size="lg" variant="spinner" />
			</div>
		{:else if error}
			<div class="rounded-2xl border border-[var(--error)]/30 bg-[var(--error)]/10 px-4 py-3 text-sm text-[var(--error)]">{error}</div>
		{:else if triage}
			<!-- Metric cards: tier counts + scope + posture -->
			<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Need attention</h3>
					<p class="text-3xl font-bold {triage.scope.needs_attention === 0 ? 'text-[var(--success)]' : 'text-[var(--text-bright)]'}">{fmt(triage.scope.needs_attention)}</p>
					<p class="text-xs text-[var(--text-muted)]">across {fmt(triage.scope.repos + triage.scope.images + triage.scope.clusters)} assets</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Fix now</h3>
					<p class="text-3xl font-bold text-[var(--error)]">{fmt(triage.fix_now.length)}</p>
					<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><ShieldAlert class="h-3 w-3 text-[var(--error)]" /> Acute, exposed, or leaking</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">This week</h3>
					<p class="text-3xl font-bold text-[var(--warning)]">{fmt(triage.this_week.length)}</p>
					<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><AlertTriangle class="h-3 w-3 text-[var(--warning)]" /> High-risk or stale</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Watch</h3>
					<p class="text-3xl font-bold text-[var(--text-secondary)]">{fmt(triage.watch.counts.total)}</p>
					<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><Eye class="h-3 w-3 text-[var(--text-muted)]" /> Warnings, not urgent</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Avg trust</h3>
					{#if avgTrust() === null}
						<p class="text-3xl font-bold text-[var(--text-secondary)]">—</p>
						<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><ShieldCheck class="h-3 w-3" /> No actionable assets</p>
					{:else}
						<p class="text-3xl font-bold" style="color: {trustColor((avgTrust() ?? 0) >= 90 ? 'A' : (avgTrust() ?? 0) >= 75 ? 'B' : (avgTrust() ?? 0) >= 60 ? 'C' : 'F')}">{avgTrust()}</p>
						<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><ShieldCheck class="h-3 w-3" /> Across actionable assets</p>
					{/if}
				</div>
			</div>

			<!-- Charts -->
			<div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
				<div class="metric-card rounded-2xl p-5">
					<DonutChart
						title="By tier"
						total={tierTotal()}
						segments={tierSegments()}
					/>
				</div>
				<div class="metric-card rounded-2xl p-5">
					<DonutChart
						title="By asset type"
						total={distributionTotal()}
						segments={distributionSegments()}
					/>
				</div>
			</div>

			<!-- Tab selector — filters the lists below by asset type. The
			     active-tab count is rendered in the Findings header
			     below rather than in the tab label so the tabs stay
			     scannable at a glance. -->
			<div class="pt-2">
				<TabSelector
					options={[
						{ value: 'all', label: 'All' },
						{ value: 'repo', label: 'Repos' },
						{ value: 'image', label: 'Images' },
						{ value: 'cluster', label: 'Clusters' }
					]}
					bind:value={activeTab}
				/>
			</div>
		{/if}
	</article>

	<!-- Tier list panel -->
	{#if !loading && !error && triage}
		<section class="panel-surface flex flex-col gap-6 px-6 py-8 sm:px-10 sm:py-10">
			<header class="flex items-start justify-between gap-4">
				<div>
					<h2 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Findings</h2>
					<p class="text-sm text-[var(--text-tertiary)]">
						{#if activeTabTotal() > 0}
							{fmt(activeTabTotal())} {activeTabLabel()}{activeTabTotal() === 1 ? '' : 's'} ranked by composite Threat × Trust
						{:else}
							No assets in this filter
						{/if}
					</p>
				</div>
			</header>

			{#if triage.fix_now.length === 0 && triage.this_week.length === 0 && triage.watch.counts.total === 0}
				<div class="flex flex-1 items-center justify-center py-16">
					<div class="flex flex-col items-center gap-3 text-center">
						<EmptyVulns size={64} class="text-[var(--success)]" />
						<div class="space-y-1">
							<h3 class="text-base font-semibold text-[var(--text-bright)]">All clear</h3>
							<p class="text-sm text-[var(--text-tertiary)]">Nothing in your scope needs attention right now.</p>
						</div>
					</div>
				</div>
			{:else if activeTabTotal() === 0}
				<div class="flex flex-1 items-center justify-center py-16">
					<div class="flex flex-col items-center gap-3 text-center">
						<EmptyVulns size={64} class="text-[var(--success)]" />
						<div class="space-y-1">
							<h3 class="text-base font-semibold text-[var(--text-bright)]">No {activeTabLabel()}s need attention</h3>
							<p class="text-sm text-[var(--text-tertiary)]">Switch tab or check back after the next scan.</p>
						</div>
					</div>
				</div>
			{:else}
				{#snippet triageRow(row: TriageRow, threatLevel: 'critical' | 'warning' | 'info', compact: boolean)}
					{@const Icon = rowIcon(row.asset_type)}
					{@const key = rowKey(row)}
					{@const isOpen = expanded.has(key)}
					<div class="row-wrapper" class:open={isOpen}>
						<button
							type="button"
							class="row"
							class:compact
							aria-expanded={isOpen}
							onclick={() => toggleExpanded(key)}
						>
							<div class="row-asset">
								<Icon size={compact ? 14 : 16} class="text-[var(--text-muted)]" />
								<span class="asset-slug">{row.asset_slug}</span>
								<span class="badge">{row.asset_type}</span>
							</div>
							<div class="row-scores">
								<span class="threat" data-level={threatLevel}>Threat {row.threat_score}</span>
								<span class="trust" style="color: {trustColor(row.trust_grade)}">Trust {row.trust_grade}</span>
							</div>
							<div class="row-reasons">
								{#each row.reasons.slice(0, compact ? 1 : 2) as reason}
									<span class={reasonPillClass(reason.id)}>{renderReason(reason)}</span>
								{/each}
							</div>
							<div class="row-actions">
								<a
									class="row-open"
									href={rowHref(row)}
									title="Open {row.asset_type} detail"
									onclick={(e) => e.stopPropagation()}
								>
									Open <ArrowUpRight size={12} />
								</a>
								<ChevronDown size={14} class="row-chevron {isOpen ? 'open' : ''}" />
							</div>
						</button>
						{#if isOpen}
							<div class="row-detail">
								<div class="detail-signals">
									<div class="detail-col">
										<div class="detail-head">Threat inputs</div>
										{#each threatBreakdown(row) as kv}
											<div class="detail-kv" class:dim={kv.dim}>
												<span class="detail-label">{kv.label}</span>
												<span class="detail-value">{kv.value}</span>
											</div>
										{/each}
									</div>
									<div class="detail-col">
										<div class="detail-head">Trust inputs</div>
										{#each trustBreakdown(row) as kv}
											<div class="detail-kv" class:dim={kv.dim}>
												<span class="detail-label">{kv.label}</span>
												<span class="detail-value">{kv.value}</span>
											</div>
										{/each}
									</div>
								</div>

								{#if row.reasons.length > 0}
									<div class="detail-recos">
										<div class="detail-head">What's wrong here · what to fix</div>
										<ul class="reco-list">
											{#each row.reasons as reason}
												{@const ex = reasonExplain(reason)}
												<li class="reco-card">
													<header class="reco-head">
														<span class={reasonPillClass(reason.id)}>{renderReason(reason)}</span>
													</header>
													<p class="reco-what">{ex.what}</p>
													<p class="reco-why"><span class="reco-key">Why it matters.</span> {ex.why}</p>
													{#if ex.action}
														<p class="reco-action"><span class="reco-key">Action.</span> {ex.action}</p>
													{/if}
												</li>
											{/each}
										</ul>
									</div>
								{/if}
							</div>
						{/if}
					</div>
				{/snippet}

				<!-- Fix now -->
				{#if fixNowFiltered().length > 0}
					<div class="tier" data-tier="fix-now">
						<div class="tier-head">
							<ShieldAlert size={18} class="text-[var(--error)]" />
							<h3 class="tier-title">Fix now</h3>
							<span class="badge">{fixNowFiltered().length}</span>
						</div>
						<div class="tier-rows">
							{#each fixNowFiltered() as row}
								{@render triageRow(row, 'critical', false)}
							{/each}
						</div>
					</div>
				{/if}

				<!-- This week -->
				{#if thisWeekFiltered().length > 0}
					<div class="tier" data-tier="this-week">
						<div class="tier-head">
							<AlertTriangle size={18} class="text-[var(--warning)]" />
							<h3 class="tier-title">This week</h3>
							<span class="badge">{thisWeekFiltered().length}</span>
						</div>
						<div class="tier-rows">
							{#each thisWeekFiltered() as row}
								{@render triageRow(row, 'warning', false)}
							{/each}
						</div>
					</div>
				{/if}

				<!-- Watch -->
				<div class="tier" data-tier="watch">
					<div class="tier-head">
						<Eye size={18} class="text-[var(--text-muted)]" />
						<h3 class="tier-title">Watch</h3>
						<span class="badge">{triage.watch.counts.total}</span>
						<div class="watch-search">
							<Search size={13} class="search-icon" />
							<input
								type="text"
								class="input"
								placeholder="Filter watch tier…"
								bind:value={watchSearch}
								oninput={onSearchInput}
							/>
						</div>
					</div>

					{#if watchFiltered().length === 0}
						<div class="watch-empty">
							{#if watchSearch.trim()}
								No watch-tier assets match "{watchSearch}".
							{:else if activeTab !== 'all'}
								No {activeTab} assets in the watch tier.
							{:else}
								No additional warnings beyond the urgent tiers.
							{/if}
						</div>
					{:else}
						<div class="tier-rows compact">
							{#each watchFiltered() as row}
								{@render triageRow(row, 'info', true)}
							{/each}
						</div>

						{#if triage.watch.counts.total > triage.watch.limit}
							<div class="pagination">
								<button type="button" class="btn btn-ghost" onclick={goPrevPage} disabled={watchOffset === 0}>← Prev</button>
								<span class="pagination-info">
									{watchOffset + 1}–{Math.min(watchOffset + triage.watch.limit, triage.watch.counts.total)} of {triage.watch.counts.total}
								</span>
								<button type="button" class="btn btn-ghost" onclick={goNextPage} disabled={watchOffset + triage.watch.limit >= triage.watch.counts.total}>Next →</button>
							</div>
						{/if}
					{/if}
				</div>
			{/if}
		</section>
	{/if}
</div>

<style>
	.tier {
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
	}
	.tier-head {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0 0.25rem;
	}
	.tier[data-tier='fix-now'] .tier-head {
		border-left: 3px solid var(--error);
		padding-left: 0.6rem;
	}
	.tier[data-tier='this-week'] .tier-head {
		border-left: 3px solid var(--warning);
		padding-left: 0.6rem;
	}
	.tier[data-tier='watch'] .tier-head {
		border-left: 3px solid var(--text-muted);
		padding-left: 0.6rem;
	}
	.tier-title {
		font-size: 0.95rem;
		font-weight: 600;
		color: var(--text-bright);
		letter-spacing: 0.02em;
	}

	.tier-rows {
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}

	/* row-wrapper owns the border + background so the expand panel
	   renders inside the same card without a seam. The row itself
	   is a single <button> that toggles expansion; nested <a> stops
	   propagation so the explicit "Open" affordance still navigates. */
	.row-wrapper {
		border: 1px solid var(--border-color);
		border-radius: 0.75rem;
		background: var(--card-bg);
		overflow: hidden;
		transition: border-color 120ms ease, background 120ms ease;
	}
	.row-wrapper:hover {
		border-color: color-mix(in srgb, var(--accent) 50%, transparent);
		background: var(--hover-bg-subtle);
	}
	.row-wrapper.open {
		border-color: color-mix(in srgb, var(--accent) 35%, var(--border-color));
	}
	.tier[data-tier='fix-now'] .row-wrapper {
		border-color: color-mix(in srgb, var(--error) 35%, var(--border-color));
	}
	.tier[data-tier='this-week'] .row-wrapper {
		border-color: color-mix(in srgb, var(--warning) 28%, var(--border-color));
	}

	.row {
		width: 100%;
		display: grid;
		grid-template-columns: minmax(220px, 1fr) auto minmax(180px, 1.5fr) auto;
		align-items: center;
		gap: 1rem;
		padding: 0.7rem 1rem;
		border: 0;
		background: transparent;
		color: inherit;
		text-align: left;
		cursor: pointer;
		font: inherit;
	}
	.row.compact {
		padding: 0.4rem 0.85rem;
		font-size: 0.85rem;
	}

	/* Right-edge actions: explicit "Open" link + expand chevron.
	   The link stops propagation so it navigates without toggling
	   the panel; the chevron is a visual indicator only — the whole
	   row is clickable. */
	.row-actions {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		color: var(--text-muted);
	}
	.row-open {
		display: inline-flex;
		align-items: center;
		gap: 0.25rem;
		padding: 0.3rem 0.6rem;
		border: 1px solid var(--border-color);
		border-radius: 0.4rem;
		font-size: 0.72rem;
		font-weight: 600;
		text-decoration: none;
		color: var(--text-secondary);
		background: var(--card-bg);
		transition: color 120ms ease, border-color 120ms ease, background 120ms ease;
	}
	.row-open:hover {
		color: var(--text-bright);
		border-color: color-mix(in srgb, var(--accent) 60%, transparent);
		background: color-mix(in srgb, var(--accent) 8%, var(--card-bg));
	}
	.row-chevron {
		transition: transform 120ms ease, color 120ms ease;
	}
	:global(.row-chevron.open) {
		transform: rotate(180deg);
		color: var(--accent);
	}

	.row-detail {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		padding: 0.85rem 1rem 1rem;
		border-top: 1px dashed color-mix(in srgb, var(--text-muted) 30%, transparent);
		background: color-mix(in srgb, var(--bg2) 50%, transparent);
	}
	.detail-signals {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
		gap: 0.5rem 1.5rem;
	}
	.detail-col {
		min-width: 0;
	}
	.detail-head {
		font-size: 0.65rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.12em;
		color: var(--text-tertiary);
		margin-bottom: 0.35rem;
	}
	.detail-kv {
		display: flex;
		justify-content: space-between;
		font-size: 0.78rem;
		padding: 0.15rem 0;
		color: var(--text-secondary);
	}
	.detail-kv.dim {
		opacity: 0.45;
	}
	.detail-label {
		color: var(--text-muted);
	}
	.detail-value {
		color: var(--text-bright);
		font-variant-numeric: tabular-nums;
	}

	/* Recommendations: one card per Reason, with a headline pill and
	   plain-English what / why / action paragraphs so the operator
	   doesn't have to translate raw counts back into actions. */
	.detail-recos {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}
	.reco-list {
		display: grid;
		gap: 0.5rem;
		margin: 0;
		padding: 0;
		list-style: none;
	}
	.reco-card {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
		padding: 0.65rem 0.85rem;
		border: 1px solid var(--border-color);
		border-radius: 0.5rem;
		background: var(--card-bg);
	}
	.reco-head {
		display: flex;
		align-items: center;
		gap: 0.5rem;
	}
	.reco-what {
		margin: 0;
		font-size: 0.85rem;
		color: var(--text-bright);
	}
	.reco-why,
	.reco-action {
		margin: 0;
		font-size: 0.78rem;
		color: var(--text-secondary);
		line-height: 1.45;
	}
	.reco-key {
		font-weight: 600;
		color: var(--text-tertiary);
	}

	.row-asset {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		min-width: 0;
	}
	.asset-slug {
		font-weight: 600;
		color: var(--text-bright);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.row-scores {
		display: inline-flex;
		gap: 0.5rem;
		font-size: 0.75rem;
		font-weight: 600;
		white-space: nowrap;
	}
	.threat[data-level='critical'] {
		color: var(--error);
	}
	.threat[data-level='warning'] {
		color: var(--warning);
	}
	.threat[data-level='info'] {
		color: var(--text-secondary);
	}

	.row-reasons {
		display: flex;
		flex-wrap: wrap;
		gap: 0.35rem;
		justify-content: flex-end;
	}

	/* Inline search input — extends the global .input class with
	   tighter dimensions so it sits next to the tier badge rather
	   than dominating the section header. */
	.watch-search {
		margin-left: auto;
		position: relative;
		display: inline-flex;
		align-items: center;
	}
	.watch-search :global(.search-icon) {
		position: absolute;
		left: 0.7rem;
		color: var(--text-muted);
		pointer-events: none;
	}
	.watch-search input.input {
		min-width: 200px;
		padding: 0.4rem 0.85rem 0.4rem 1.85rem;
		font-size: 0.8rem;
	}

	.watch-empty {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		padding: 1.2rem;
		border-radius: 0.75rem;
		background: var(--card-bg);
		border: 1px solid var(--border-color);
		color: var(--text-secondary);
		font-size: 0.85rem;
	}

	.pagination {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 1rem;
		padding: 0.6rem 0;
		font-size: 0.8rem;
	}
	.pagination-info {
		color: var(--text-muted);
	}
</style>
