<script lang="ts">
	import { browser } from '$app/environment';
	import {
		Search,
		ShieldAlert,
		AlertTriangle,
		Eye,
		EyeOff,
		Container,
		GitBranch,
		ShieldCheck,
		Target,
		ArrowUpRight,
		KeyRound
	} from 'lucide-svelte';
	import KubernetesIcon from '$lib/components/icons/KubernetesIcon.svelte';
	import EmptyVulns from '$lib/components/icons/EmptyVulns.svelte';
	import Loading from '$lib/components/Loading.svelte';
	import DonutChart from '$lib/components/DonutChart.svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';
	import BucketAckDialog from '$lib/components/BucketAckDialog.svelte';
	import TriageFinding from '$lib/components/TriageFinding.svelte';
	import { session } from '$lib/stores/session';

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
		image_digest?: string;
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
		fix_now_total: number;
		this_week_total: number;
		avg_trust: number;
		view_refreshed_at: string | null;
	};
	type WatchCounts = { total: number; repo: number; image: number; cluster: number };
	type WatchSection = { counts: WatchCounts; limit: number; offset: number; rows: TriageRow[] };
	type Ack = {
		id: string;
		asset_type: string;
		asset_id: string;
		action: string;
		reason_text: string;
		snooze_until?: string | null;
		signals_fingerprint?: string;
		created_by: string;
		created_at: string;
		revoked_at?: string | null;
		revoked_by?: string | null;
		revoked_reason?: string | null;
	};
	type AckedRow = TriageRow & { ack: Ack };
	type TriageResponse = {
		scope: Scope;
		fix_now: TriageRow[];
		this_week: TriageRow[];
		watch: WatchSection;
		suppressed: AckedRow[];
	};

	// Per-asset breakdown shape — fetched lazily on row expansion.
	// Mirrors api/internal/uiapi BreakdownResponse; field naming is
	// snake_case to match the wire.
	type BreakdownCVE = {
		vuln_id: string;
		severity: string;
		fixed_version?: string;
		purl?: string;
		is_kev: boolean;
		epss?: number;
	};
	type BreakdownSecret = { secret_hash: string; rule_id?: string; source?: string };
	type BreakdownImage = {
		image_id: string;
		digest: string;
		slug: string;
		critical_count: number;
		kev_count: number;
		namespace?: string;
	};
	type Breakdown = {
		asset_type: string;
		asset_id: string;
		asset_slug: string;
		tier: string;
		threat_score: number;
		trust_score: number;
		trust_grade: string;
		reasons: Reason[];
		cves?: BreakdownCVE[];
		secrets?: BreakdownSecret[];
		contributing_images?: BreakdownImage[];
		live_ack?: Ack | null;
		history: Ack[];
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

	// Lazy-fetched per-asset breakdown for the expanded panel. Keyed
	// by rowKey. We cache the response after first load so the user
	// can collapse/expand without re-fetching.
	let breakdownByKey = $state(new Map<string, Breakdown>());
	let breakdownLoadingByKey = $state(new Set<string>());

	// Ack dialog state. Only one bucket can be acknowledged at a time;
	// reusing the same component for every row.
	let ackDialogOpen = $state(false);
	let ackDialogRow = $state<TriageRow | null>(null);
	let ackDialogHistory = $state<Ack[]>([]);

	let isGlobalReader = $derived($session.role === 'global_reader');

	const rowKey = (r: TriageRow) => `${r.asset_type}:${r.asset_id}`;
	const toggleExpanded = (key: string, row?: TriageRow) => {
		const next = new Set(expanded);
		if (next.has(key)) {
			next.delete(key);
		} else {
			next.add(key);
			if (row && !breakdownByKey.has(key) && !breakdownLoadingByKey.has(key)) {
				void loadBreakdown(row);
			}
		}
		expanded = next;
	};

	const loadBreakdown = async (row: TriageRow) => {
		const key = rowKey(row);
		const nextLoading = new Set(breakdownLoadingByKey);
		nextLoading.add(key);
		breakdownLoadingByKey = nextLoading;
		try {
			const url = `/api/triage/${encodeURIComponent(row.asset_type)}/${encodeURIComponent(row.asset_id)}/breakdown`;
			const res = await fetch(url, { credentials: 'include' });
			if (!res.ok) throw new Error(`HTTP ${res.status}`);
			const data = (await res.json()) as Breakdown;
			const nextBreakdown = new Map(breakdownByKey);
			nextBreakdown.set(key, data);
			breakdownByKey = nextBreakdown;
		} catch {
			// Quietly fall back to the inline reason summary if the
			// breakdown 404s (cluster-only user lost grants between
			// list fetch and detail fetch, etc.).
		} finally {
			const next = new Set(breakdownLoadingByKey);
			next.delete(key);
			breakdownLoadingByKey = next;
		}
	};

	const openAckDialog = (row: TriageRow) => {
		ackDialogRow = row;
		// Seed history from cached breakdown if available; otherwise
		// fetch fresh so the modal shows audit context immediately.
		const cached = breakdownByKey.get(rowKey(row));
		ackDialogHistory = cached?.history ?? [];
		ackDialogOpen = true;
		if (!cached) {
			void loadBreakdown(row).then(() => {
				const fresh = breakdownByKey.get(rowKey(row));
				if (fresh) ackDialogHistory = fresh.history;
			});
		}
	};

	const headlineReasonsFor = (row: TriageRow): string[] => {
		return row.reasons.slice(0, 3).map((r) => renderReason(r));
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

	// Reason templates — the short label shown on a pill.
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

	// Imperative one-liner: the single thing to do about this reason.
	// Drives the at-a-glance "→ do this" headline on every row so the
	// operator never has to translate a raw count back into an action.
	const reasonAction = (r: Reason): string => {
		const f = r.fields ?? {};
		const n = (v: unknown) => (v as number) ?? 0;
		switch (r.id) {
			case 'active_secret_leak':
				return `Rotate ${n(f.count)} leaked secret${n(f.count) === 1 ? '' : 's'} now`;
			case 'kev_and_exposed':
				return `Patch ${n(f.kev_count)} actively-exploited CVE${n(f.kev_count) === 1 ? '' : 's'} on an internet-facing workload`;
			case 'kev_present':
				return `Patch ${n(f.kev_count)} actively-exploited (KEV) CVE${n(f.kev_count) === 1 ? '' : 's'}`;
			case 'epss_very_high':
				return `Patch the likely-to-be-exploited CVE (EPSS ${(n(f.epss_max) * 100).toFixed(0)}%)`;
			case 'epss_elevated':
				return `Schedule a patch for the rising-risk CVE (EPSS ${(n(f.epss_max) * 100).toFixed(0)}%)`;
			case 'critical_severity':
				return f.has_fix
					? `Upgrade to clear ${n(f.critical)} critical CVE${n(f.critical) === 1 ? '' : 's'}`
					: `Mitigate ${n(f.critical)} critical CVE${n(f.critical) === 1 ? '' : 's'} (no fix yet)`;
			case 'scan_stale':
				return `Re-scan — results are ${f.days === 999 ? 'missing' : `${f.days} days stale`}`;
			case 'low_commit_signing':
				return `Turn on commit signing for this repo`;
			case 'image_unsigned':
				return `Sign this image in the build pipeline`;
			case 'no_sbom':
				return `Generate an SBOM so it can be scanned`;
			case 'archived_deps':
				return `Replace ${n(f.count)} abandoned dependenc${n(f.count) === 1 ? 'y' : 'ies'}`;
			case 'deprecated_deps':
				return `Migrate off ${n(f.count)} deprecated dependenc${n(f.count) === 1 ? 'y' : 'ies'}`;
			case 'low_dep_health':
				return `Review the weakest dependencies for replacement`;
			case 'major_behind':
				return `Upgrade ${n(f.count)} badly-outdated dependenc${n(f.count) === 1 ? 'y' : 'ies'}`;
			default:
				return renderReason(r);
		}
	};

	// The headline action for a row = the action of its top-ranked
	// reason (reasons arrive pre-sorted by severity from the API).
	const primaryAction = (row: TriageRow): string =>
		row.reasons.length > 0 ? reasonAction(row.reasons[0]) : 'Review this asset';

	// Plain-English explanation per reason ID, used in the expansion.
	const reasonExplain = (r: Reason): { what: string; why: string; action: string } => {
		const f = r.fields ?? {};
		switch (r.id) {
			case 'active_secret_leak':
				return {
					what: `${f.count} live credential${(f.count as number) === 1 ? '' : 's'} found in this repo were probed and confirmed still valid.`,
					why: 'A leaked secret that still authenticates is the highest-impact finding in the queue — anyone who has the repo (or the commit history) has the keys.',
					action: 'Rotate each leaked secret at the issuing provider, then scrub the value from git history (e.g. `git filter-repo`). Hiding the finding does not invalidate the credential.'
				};
			case 'kev_and_exposed':
				return {
					what: `${f.kev_count} CVE${(f.kev_count as number) === 1 ? '' : 's'} on this asset are listed in CISA's Known Exploited Vulnerabilities catalogue, and the workload is reachable from the internet.`,
					why: 'KEV is the authoritative "we have seen this exploited in the wild" list. Combined with internet reach, this is the single highest-priority class of finding — public exploits typically exist.',
					action: 'Patch or remove the affected component immediately. If a fix release is unavailable, take the workload offline behind authentication or a WAF until upstream lands a fix.'
				};
			case 'kev_present':
				return {
					what: `${f.kev_count} CVE${(f.kev_count as number) === 1 ? '' : 's'} on this asset are in CISA's Known Exploited Vulnerabilities catalogue.`,
					why: "KEV CVEs have confirmed in-the-wild exploitation. Even when the asset isn't internet-exposed today, exploit code is generally public — any future exposure path is high-risk.",
					action: 'Apply the fix-available upgrade for the affected package. If you intentionally accept the risk, record a VEX `not_affected` so triage stops surfacing it.'
				};
			case 'epss_very_high':
				return {
					what: `At least one CVE on this asset has an EPSS score of ${(((f.epss_max as number) ?? 0) * 100).toFixed(0)}% — predicted probability of exploitation in the next 30 days.`,
					why: '50%+ EPSS is the operational "act this sprint" threshold. Vulns with very-high EPSS are usually weaponised before they hit KEV.',
					action: 'Patch the highest-EPSS CVE first; the affected component is named in the drivers list above.'
				};
			case 'epss_elevated':
				return {
					what: `A CVE on this asset has elevated EPSS (${(((f.epss_max as number) ?? 0) * 100).toFixed(0)}%) — 10–50% predicted exploitation in the next 30 days.`,
					why: 'Elevated EPSS means real-world signal of exploitability is rising. Most vulns never reach this threshold.',
					action: 'Schedule the upgrade in the current sprint. A jump above 50% means escalating to "act now".'
				};
			case 'critical_severity':
				return {
					what: `${f.critical} CRITICAL CVE${(f.critical as number) === 1 ? '' : 's'} on this asset${f.has_fix ? ' — at least one has a fix release available' : ' — no fix release available yet'}.`,
					why: 'CRITICAL severity per the scanner means CVSS≥9.0 (or vendor equivalent). These are the loudest items by impact alone.',
					action: f.has_fix
						? 'Upgrade the affected package to the fix version listed in the drivers above.'
						: 'Pin the vulnerable version, monitor for an upstream fix, and consider VEX `under_investigation`.'
				};
			case 'scan_stale':
				return {
					what: `Last scan finished ${(f.days as number) === 999 ? 'never' : `${f.days} days ago`} — older than the 30-day freshness threshold.`,
					why: "Stale scans mean the asset's *current* threat state is unknown. Fixing a CVE doesn't help if you can't tell whether the fix landed.",
					action: 'Trigger a re-scan from the asset detail page. If scans never run, check the runner config — the asset may be missing a provider binding.'
				};
			case 'low_commit_signing':
				return {
					what: `${Math.round((f.signed_pct as number) ?? 0)}% of recent commits carry verified signatures.`,
					why: 'Without signed commits, anything in the repo history could have been pushed by anyone with the right key — there is no cryptographic record of who authored the change.',
					action: 'Enforce signed commits in branch protection, back-fill keys for active contributors, and require signatures on protected branches.'
				};
			case 'image_unsigned':
				return {
					what: 'This image was not built through a signing pipeline (cosign / sigstore).',
					why: "An unsigned image's chain of custody can't be verified — there's no way to prove the image you pulled is the one CI built.",
					action: 'Wire `cosign sign` into the build pipeline and configure a verification policy in admin → signing so unsigned images fail to deploy.'
				};
			case 'no_sbom':
				return {
					what: 'No SBOM exists for this asset, so the dependency inventory is unknown.',
					why: "Triage is only as good as the inventory. With no SBOM, vuln scans miss anything that isn't in the image layer index, and dep-health analysis can't run at all.",
					action: 'Trigger an SBOM scan from the asset detail page.'
				};
			case 'archived_deps':
				return {
					what: `${f.count} direct dependenc${(f.count as number) === 1 ? 'y is' : 'ies are'} marked archived by their upstream registry.`,
					why: 'Archived packages no longer receive security fixes. Any CVE found later will stay unfixed unless someone forks and maintains the code.',
					action: 'Replace each archived dep with a maintained alternative. For genuinely-stable libraries, vendor the source so the supply chain is yours.'
				};
			case 'deprecated_deps':
				return {
					what: `${f.count} direct dependenc${(f.count as number) === 1 ? 'y is' : 'ies are'} flagged deprecated by the upstream registry.`,
					why: 'Deprecated packages typically point to a successor or a security advisory. Continuing to depend on them means missing the migration window.',
					action: "Check each deprecated package's registry page for the recommended successor and migrate."
				};
			case 'low_dep_health':
				return {
					what: `Worst direct-dep health score is ${Math.round((f.worst_score as number) ?? 0)}/100 (single-maintainer / no recent activity / few downloads).`,
					why: 'Low dep-health means bus-factor risk: a critical fix may take months or never land. The supply-chain trust is thin.',
					action: 'Identify the lowest-scoring deps in the asset detail view and evaluate replacements.'
				};
			case 'major_behind':
				return {
					what: `${f.count} direct dependenc${(f.count as number) === 1 ? 'y is' : 'ies are'} at least ${f.max_major} major version${(f.max_major as number) === 1 ? '' : 's'} behind their latest release.`,
					why: 'Major-version drift means the asset is outside upstream security support windows for those packages.',
					action: 'Plan an upgrade pass. Major-version bumps usually need code changes, so budget time accordingly.'
				};
			default:
				return { what: r.id, why: 'No description available.', action: '' };
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
		if (r.asset_type === 'image') return `/images/${encodeURIComponent(r.image_digest ?? '')}`;
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

	// Server-computed average trust across every actionable asset.
	const avgTrust = $derived(() => {
		if (!triage) return null;
		if (triage.scope.needs_attention === 0 && triage.watch.counts.total === 0) return null;
		return triage.scope.avg_trust;
	});

	// Asset-type distribution donut.
	const distributionSegments = $derived((): DonutSegment[] => {
		if (!triage) return [];
		const counts = { repo: 0, image: 0, cluster: 0 };
		for (const r of [...triage.fix_now, ...triage.this_week]) {
			counts[r.asset_type]++;
		}
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
		if (triage.scope.fix_now_total > 0) segs.push({ label: 'Fix now', value: triage.scope.fix_now_total, color: 'var(--error)' });
		if (triage.scope.this_week_total > 0) segs.push({ label: 'This week', value: triage.scope.this_week_total, color: 'var(--warning)' });
		if (triage.watch.counts.total > 0) segs.push({ label: 'Watch', value: triage.watch.counts.total, color: 'var(--text-muted)' });
		return segs;
	});

	const tierTotal = $derived(() => {
		if (!triage) return 0;
		return triage.scope.fix_now_total + triage.scope.this_week_total + triage.watch.counts.total;
	});

	// Tab filter applied client-side over already-fetched lists.
	const filterByTab = (rows: TriageRow[]): TriageRow[] => {
		if (activeTab === 'all') return rows;
		return rows.filter((r) => r.asset_type === activeTab);
	};

	const fixNowFiltered = $derived(() => (triage ? filterByTab(triage.fix_now) : []));
	const thisWeekFiltered = $derived(() => (triage ? filterByTab(triage.this_week) : []));
	const watchFiltered = $derived(() => (triage ? filterByTab(triage.watch.rows) : []));

	const activeTabTotal = $derived(() => {
		if (!triage) return 0;
		if (activeTab === 'all') {
			return triage.scope.fix_now_total + triage.scope.this_week_total + triage.watch.counts.total;
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

	const ackSummary = (ack: Ack): string => {
		if (ack.action === 'snooze') return `snoozed until ${(ack.snooze_until ?? '').slice(0, 10)}`;
		// Legacy permanent acks predate the snapshot model; flag them so
		// they read differently from the change-aware "accept the risk".
		if (ack.action === 'accept_risk') return 'risk accepted (permanent)';
		return 'risk accepted · back if signals change';
	};
</script>

<svelte:head>
	<title>Triage • Spam Monitor</title>
</svelte:head>

<div class="space-y-4">
	<!-- Stats + charts panel -->
	<article class="panel-surface space-y-8 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex items-center gap-3">
			<Target class="h-10 w-10 flex-shrink-0 text-[var(--accent)]" />
			<div>
				<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Triage</h1>
				<p class="text-sm text-[var(--text-tertiary)]">
					Your scope's assets, ranked by what needs fixing first.
				</p>
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
			<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
				<div class="metric-card rounded-2xl border border-[var(--border-color)]/60 p-4">
					<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Need attention</p>
					<p class="mt-3 text-2xl font-semibold {triage.scope.needs_attention === 0 ? 'text-[var(--success)]' : 'text-[var(--text-bright)]'}">{fmt(triage.scope.needs_attention)}</p>
					<p class="mt-1 text-xs text-[var(--text-tertiary)]">of {fmt(triage.scope.repos + triage.scope.images + triage.scope.clusters)} assets</p>
				</div>
				<div class="metric-card rounded-2xl border border-[var(--border-color)]/60 p-4">
					<p class="flex items-center gap-1.5 text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]"><ShieldAlert class="h-3.5 w-3.5 text-[var(--error)]" /> Fix now</p>
					<p class="mt-3 text-2xl font-semibold text-[var(--error)]">{fmt(triage.scope.fix_now_total)}</p>
					<p class="mt-1 text-xs text-[var(--text-tertiary)]">Exploited, exposed, or leaking</p>
				</div>
				<div class="metric-card rounded-2xl border border-[var(--border-color)]/60 p-4">
					<p class="flex items-center gap-1.5 text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]"><AlertTriangle class="h-3.5 w-3.5 text-[var(--warning)]" /> This week</p>
					<p class="mt-3 text-2xl font-semibold text-[var(--warning)]">{fmt(triage.scope.this_week_total)}</p>
					<p class="mt-1 text-xs text-[var(--text-tertiary)]">High-risk or stale</p>
				</div>
				<div class="metric-card rounded-2xl border border-[var(--border-color)]/60 p-4">
					<p class="flex items-center gap-1.5 text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]"><Eye class="h-3.5 w-3.5 text-[var(--text-muted)]" /> Watch</p>
					<p class="mt-3 text-2xl font-semibold text-[var(--text-secondary)]">{fmt(triage.watch.counts.total)}</p>
					<p class="mt-1 text-xs text-[var(--text-tertiary)]">Warnings, not urgent</p>
				</div>
				<div class="metric-card rounded-2xl border border-[var(--border-color)]/60 p-4">
					<p class="flex items-center gap-1.5 text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]"><ShieldCheck class="h-3.5 w-3.5" /> Avg trust</p>
					{#if avgTrust() === null}
						<p class="mt-3 text-2xl font-semibold text-[var(--text-secondary)]">—</p>
						<p class="mt-1 text-xs text-[var(--text-tertiary)]">No actionable assets</p>
					{:else}
						<p class="mt-3 text-2xl font-semibold" style="color: {trustColor((avgTrust() ?? 0) >= 90 ? 'A' : (avgTrust() ?? 0) >= 75 ? 'B' : (avgTrust() ?? 0) >= 60 ? 'C' : 'F')}">{avgTrust()}</p>
						<p class="mt-1 text-xs text-[var(--text-tertiary)]">Across actionable assets</p>
					{/if}
				</div>
			</div>

			<!-- Charts -->
			<div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
				<div class="metric-card rounded-2xl border border-[var(--border-color)]/60 p-5">
					<DonutChart title="By urgency" total={tierTotal()} segments={tierSegments()} />
				</div>
				<div class="metric-card rounded-2xl border border-[var(--border-color)]/60 p-5">
					<DonutChart title="By asset type" total={distributionTotal()} segments={distributionSegments()} />
				</div>
			</div>

			<TabSelector
				options={[
					{ value: 'all', label: 'All' },
					{ value: 'repo', label: 'Repos' },
					{ value: 'image', label: 'Images' },
					{ value: 'cluster', label: 'Clusters' }
				]}
				bind:value={activeTab}
			/>
		{/if}
	</article>

	<!-- Tier list panel -->
	{#if !loading && !error && triage}
		<section class="panel-surface flex flex-col gap-7 px-6 py-8 sm:px-10 sm:py-10">
			<header>
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">What to fix</h2>
				<p class="text-sm text-[var(--text-tertiary)]">
					{#if activeTabTotal() > 0}
						{fmt(activeTabTotal())} {activeTabLabel()}{activeTabTotal() === 1 ? '' : 's'} need attention — most urgent first.
					{:else}
						No assets in this filter.
					{/if}
				</p>
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
				{#snippet triageRow(row: TriageRow)}
					{@const key = rowKey(row)}
					{@const isOpen = expanded.has(key)}
					<TriageFinding
						assetType={row.asset_type}
						assetSlug={row.asset_slug}
						trustGrade={row.trust_grade}
						href={rowHref(row)}
						primaryAction={primaryAction(row)}
						reasons={row.reasons.map((r) => ({ label: renderReason(r), cls: reasonPillClass(r.id) }))}
						open={isOpen}
						readOnly={isGlobalReader}
						onToggle={() => toggleExpanded(key, row)}
						onAcknowledge={() => openAckDialog(row)}
					>
						{#snippet detail()}
							{@const bd = breakdownByKey.get(key)}
							{@const bdLoading = breakdownLoadingByKey.has(key)}
							{#if bdLoading && !bd}
								<div class="text-xs text-[var(--text-tertiary)]">Loading details…</div>
							{/if}

							{#if bd}
								<!-- Concrete drivers: the vulnerable components to act on. -->
								{#if row.asset_type === 'cluster' && bd.contributing_images && bd.contributing_images.length > 0}
									<div class="drivers">
										<p class="drivers-head"><Container size={13} /> Vulnerable images driving this ({bd.contributing_images.length})</p>
										<ul class="drivers-list">
											{#each bd.contributing_images as img}
												<li class="driver">
													<div class="driver-head">
														<a class="font-semibold text-[var(--text-bright)] hover:underline" href={`/images/${encodeURIComponent(img.digest)}`}>{img.slug}</a>
														{#if img.namespace}<span class="badge">{img.namespace}</span>{/if}
													</div>
													<p class="driver-fix">
														<span class="pill pill-error">{img.kev_count} KEV</span>
														<span class="pill pill-warning">{img.critical_count} Critical</span>
														— fix the image to clear it from this cluster.
													</p>
												</li>
											{/each}
										</ul>
									</div>
								{/if}

								{#if bd.secrets && bd.secrets.length > 0}
									<div class="drivers">
										<p class="drivers-head"><KeyRound size={13} /> Leaked secrets to rotate ({bd.secrets.length})</p>
										<ul class="drivers-list">
											{#each bd.secrets.slice(0, 10) as s}
												<li class="driver">
													<div class="driver-head">
														<span class="pill pill-error">{s.rule_id ?? 'secret'}</span>
														<span class="font-mono text-xs text-[var(--text-tertiary)]">…{s.secret_hash.slice(-12)}</span>
													</div>
													<p class="driver-fix">
														<span class="driver-key">Fix.</span> Rotate at the provider, then purge from git history.{#if s.source} <span class="text-[var(--text-tertiary)]">({s.source})</span>{/if}
													</p>
												</li>
											{/each}
										</ul>
									</div>
								{/if}

								{#if bd.cves && bd.cves.length > 0}
									<div class="drivers">
										<p class="drivers-head"><AlertTriangle size={13} /> Vulnerabilities to patch ({bd.cves.length})</p>
										<ul class="drivers-list">
											{#each bd.cves.slice(0, 12) as c}
												<li class="driver">
													<div class="driver-head">
														<span class={c.severity === 'CRITICAL' ? 'pill pill-error' : c.severity === 'HIGH' ? 'pill pill-warning' : 'pill pill-neutral'}>{c.severity}</span>
														<a class="font-mono text-[var(--text-bright)] hover:underline" href={`/vulnerabilities/${encodeURIComponent(c.vuln_id)}`}>{c.vuln_id}</a>
														{#if c.is_kev}<span class="pill pill-error">KEV</span>{/if}
														{#if c.epss && c.epss >= 0.1}<span class="pill pill-warning">EPSS {(c.epss * 100).toFixed(0)}%</span>{/if}
													</div>
													<p class="driver-fix">
														{#if c.fixed_version}
															<span class="driver-key">Fix.</span> Upgrade to {c.fixed_version} or later.
														{:else}
															<span class="driver-key">Fix.</span> No upstream fix yet — pin the version and monitor.
														{/if}
													</p>
												</li>
											{/each}
										</ul>
									</div>
								{/if}
							{/if}

							<!-- Why each finding matters + what to do, in plain English. -->
							{#if row.reasons.length > 0}
								<div class="drivers">
									<p class="drivers-head">Why it's here, and what to do</p>
									<ul class="drivers-list">
										{#each row.reasons as reason}
											{@const ex = reasonExplain(reason)}
											<li class="driver">
												<div class="driver-head">
													<span class={reasonPillClass(reason.id)}>{renderReason(reason)}</span>
												</div>
												<p class="driver-what">{ex.what}</p>
												<p class="driver-why"><span class="driver-key">Why it matters.</span> {ex.why}</p>
												{#if ex.action}
													<p class="driver-fix"><span class="driver-key">Action.</span> {ex.action}</p>
												{/if}
											</li>
										{/each}
									</ul>
								</div>
							{/if}
						{/snippet}
					</TriageFinding>
				{/snippet}

				<!-- Fix now -->
				{#if fixNowFiltered().length > 0}
					<div class="tier">
						<div class="tier-head">
							<ShieldAlert size={17} class="text-[var(--error)]" />
							<h3 class="tier-title">Fix now</h3>
							<span class="badge">{fixNowFiltered().length}</span>
							<span class="tier-sub">Exploited, exposed, or leaking — act today.</span>
						</div>
						<div class="tier-rows">
							{#each fixNowFiltered() as row (rowKey(row))}
								{@render triageRow(row)}
							{/each}
						</div>
					</div>
				{/if}

				<!-- This week -->
				{#if thisWeekFiltered().length > 0}
					<div class="tier">
						<div class="tier-head">
							<AlertTriangle size={17} class="text-[var(--warning)]" />
							<h3 class="tier-title">This week</h3>
							<span class="badge">{thisWeekFiltered().length}</span>
							<span class="tier-sub">High-risk or stale — plan it into the sprint.</span>
						</div>
						<div class="tier-rows">
							{#each thisWeekFiltered() as row (rowKey(row))}
								{@render triageRow(row)}
							{/each}
						</div>
					</div>
				{/if}

				<!-- Watch -->
				<div class="tier">
					<div class="tier-head">
						<Eye size={17} class="text-[var(--text-muted)]" />
						<h3 class="tier-title">Watch</h3>
						<span class="badge">{triage.watch.counts.total}</span>
						<div class="watch-search">
							<Search size={13} class="search-icon" />
							<input
								type="text"
								class="input"
								placeholder="Filter watch…"
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
						<div class="tier-rows">
							{#each watchFiltered() as row (rowKey(row))}
								{@render triageRow(row)}
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

		<!-- Suppressed: assets whose live ack hides them from the active
		     tiers. Always shown so operators can audit and revoke. -->
		{#if triage && triage.suppressed && triage.suppressed.length > 0}
			<section class="panel-surface flex flex-col gap-4 px-6 py-7 sm:px-10 sm:py-8">
				<header>
					<h2 class="flex items-center gap-2 text-lg font-semibold text-[var(--text-bright)]">
						<EyeOff size={18} class="text-[var(--text-muted)]" /> Hidden findings
						<span class="badge">{triage.suppressed.length}</span>
					</h2>
					<p class="text-sm text-[var(--text-tertiary)]">Removed from the active queue by an operator. Revoke to bring one back.</p>
				</header>
				<div class="tier-rows">
					{#each triage.suppressed as srow (rowKey(srow))}
						{@const SIcon = rowIcon(srow.asset_type)}
						<div class="hf">
							<div class="hf-body">
								<div class="hf-top">
									<SIcon size={15} class="shrink-0 text-[var(--text-muted)]" />
									<span class="hf-slug">{srow.asset_slug}</span>
									<span class="badge">{srow.asset_type}</span>
									<span class="pill pill-neutral">{ackSummary(srow.ack)}</span>
								</div>
								{#if srow.ack.reason_text}
									<p class="hf-reason">
										<span class="italic">"{srow.ack.reason_text}"</span>
										<span class="text-[var(--text-muted)]">— {srow.ack.created_by}</span>
									</p>
								{:else}
									<p class="hf-reason text-[var(--text-muted)]">Hidden by {srow.ack.created_by}</p>
								{/if}
							</div>
							<div class="hf-actions">
								<a class="hf-btn" href={rowHref(srow)} title="Open detail">Open <ArrowUpRight size={12} /></a>
								<button
									type="button"
									class="hf-btn"
									disabled={isGlobalReader}
									title={isGlobalReader ? 'Read-only role' : 'Bring this finding back'}
									onclick={async () => {
										if (isGlobalReader) return;
										const ok = window.confirm(`Bring "${srow.asset_slug}" back into the active queue?`);
										if (!ok) return;
										const res = await fetch(`/api/triage/acknowledge/${encodeURIComponent(srow.ack.id)}/revoke`, {
											method: 'POST',
											credentials: 'include'
										});
										if (res.ok) void reload();
									}}
								>
									Revoke
								</button>
							</div>
						</div>
					{/each}
				</div>
			</section>
		{/if}
	{/if}
</div>

<BucketAckDialog
	bind:open={ackDialogOpen}
	assetType={ackDialogRow?.asset_type ?? ''}
	assetSlug={ackDialogRow?.asset_slug ?? ''}
	assetId={ackDialogRow?.asset_id ?? ''}
	headlineReasons={ackDialogRow ? headlineReasonsFor(ackDialogRow) : []}
	history={ackDialogHistory}
	readOnly={isGlobalReader}
	onAcknowledged={() => {
		ackDialogOpen = false;
		ackDialogRow = null;
		void reload();
	}}
/>

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
	}
	.tier-title {
		font-size: 1rem;
		font-weight: 600;
		color: var(--text-bright);
	}
	.tier-sub {
		font-size: 0.8rem;
		color: var(--text-tertiary);
	}

	.tier-rows {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	/* Hidden-finding rows: a quieter single-line variant of the finding
	   card (the active row lives in TriageFinding.svelte). Flat border,
	   no coloured edge. */
	.hf {
		display: flex;
		align-items: flex-start;
		gap: 1rem;
		padding: 0.7rem 1rem;
		border: 1px solid color-mix(in srgb, var(--border-color) 60%, transparent);
		border-radius: 1rem;
		background: color-mix(in srgb, var(--card-bg) 40%, transparent);
		opacity: 0.85;
		transition: opacity 120ms ease, border-color 120ms ease;
	}
	.hf:hover {
		opacity: 1;
		border-color: color-mix(in srgb, var(--accent) 35%, var(--border-color));
	}
	.hf-body {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
	}
	.hf-top {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		flex-wrap: wrap;
	}
	.hf-slug {
		font-weight: 600;
		color: var(--text-bright);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 60vw;
	}
	.hf-reason {
		margin: 0;
		font-size: 0.82rem;
		color: var(--text-secondary);
	}
	.hf-actions {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		flex-shrink: 0;
	}
	.hf-btn {
		display: inline-flex;
		align-items: center;
		gap: 0.3rem;
		padding: 0.35rem 0.65rem;
		border: 1px solid var(--border-color);
		border-radius: 0.6rem;
		font-size: 0.72rem;
		font-weight: 600;
		color: var(--text-secondary);
		background: var(--card-bg);
		cursor: pointer;
		text-decoration: none;
		white-space: nowrap;
		transition: color 120ms ease, border-color 120ms ease, background 120ms ease;
	}
	.hf-btn:hover {
		color: var(--text-bright);
		border-color: color-mix(in srgb, var(--accent) 55%, transparent);
		background: color-mix(in srgb, var(--accent) 8%, var(--card-bg));
	}
	.hf-btn:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}

	/* Driver groups: the concrete things to fix (CVEs, secrets, images)
	   and the plain-English reasoning. Flat cards, no shadows. */
	.drivers {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}
	.drivers-head {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		margin: 0;
		font-size: 0.7rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.1em;
		color: var(--text-tertiary);
	}
	.drivers-list {
		display: grid;
		gap: 0.5rem;
		margin: 0;
		padding: 0;
		list-style: none;
	}
	.driver {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
		padding: 0.65rem 0.85rem;
		border: 1px solid color-mix(in srgb, var(--border-color) 60%, transparent);
		border-radius: 0.75rem;
		background: var(--card-bg);
	}
	.driver-head {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		flex-wrap: wrap;
	}
	.driver-what {
		margin: 0;
		font-size: 0.85rem;
		color: var(--text-bright);
	}
	.driver-why,
	.driver-fix {
		margin: 0;
		font-size: 0.8rem;
		color: var(--text-secondary);
		line-height: 1.45;
	}
	.driver-key {
		font-weight: 600;
		color: var(--text-tertiary);
	}

	/* Inline watch search. */
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
		border-radius: 0.75rem;
	}

	.watch-empty {
		padding: 1.1rem;
		border-radius: 0.75rem;
		background: color-mix(in srgb, var(--card-bg) 40%, transparent);
		border: 1px solid color-mix(in srgb, var(--border-color) 60%, transparent);
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
