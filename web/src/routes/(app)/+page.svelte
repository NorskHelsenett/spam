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
		Bot,
		Globe,
		Lock,
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
	import VulnAdvisoryDialog from '$lib/components/VulnAdvisoryDialog.svelte';
	import Tooltip from '$lib/components/Tooltip.svelte';
	import FindingChat from '$lib/components/FindingChat.svelte';

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
		medium_count: number;
		low_count: number;
		kev_count: number;
		epss_max: number;
		has_fix_for_critical: boolean;
		has_fix_for_high: boolean;
		kev_fixable_count: number;
		kev_ransomware_count: number;
		kev_due_passed: boolean;
		kev_epss_max: number;
		exposed_kev_count: number;
		exposed_critical_count: number;
		exposed_epss_max: number;
		cluster_count: number;
		exposed_cluster_count: number;
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
		tier: 'fix_now' | 'this_week' | 'watch' | 'deprioritized';
		reasons: Reason[];
		context: Reason[];
		advisory?: {
			summary?: string;
			summary_model?: string;
			verdict?: 'keep' | 'suppress';
			verdict_justification?: string;
			verdict_confidence?: number;
			verdict_missing_data?: string;
			generated_at: string;
			stale?: boolean;
		};
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
	type SectionCounts = { total: number; repo: number; image: number };
	type PagedSection = { counts: SectionCounts; limit: number; offset: number; rows: TriageRow[] };
	type TriageResponse = {
		scope: Scope;
		fix_now: TriageRow[];
		this_week: TriageRow[];
		watch: PagedSection;
		deprioritized: PagedSection;
		clusters: TriageRow[];
	};

	// Lazy expansion payload for image rows — top KEV/EPSS-ranked CVEs
	// + the exposed domains serving the digest.
	type ImageTriageVuln = {
		vuln_id: string;
		canonical_id: string;
		severity: string;
		pkg_name: string;
		installed_version: string;
		fixed_version: string;
		epss: number;
		epss_percentile: number;
		kev: boolean;
		kev_due_date?: string | null;
		kev_ransomware: boolean;
		on_path: boolean;
	};
	type ImageTriageHost = {
		host: string;
		cluster: string;
		cluster_id: string;
		namespace: string;
		tls: boolean;
	};
	type ImageTriageCluster = {
		cluster_id: string;
		name: string;
		namespaces: string;
		exposed: boolean;
	};
	type ImageTriageDetail = {
		vulns: ImageTriageVuln[];
		vuln_total: number;
		hosts: ImageTriageHost[];
		clusters: ImageTriageCluster[];
		cluster_total: number;
	};

	let triage: TriageResponse | null = $state(null);
	let loading = $state(true);
	let error = $state('');
	let watchSearch = $state('');
	let watchOffset = $state(0);
	let deprioSearch = $state('');
	let deprioOffset = $state(0);
	// The deprioritized section ships collapsed — it's the explicit
	// "you can ignore these" pile, shown on demand.
	let deprioOpen = $state(false);
	// Tier-based tabs: urgent = fix_now + this_week combined.
	let activeTab = $state<'all' | 'urgent' | 'watch' | 'deprioritized'>('all');
	// Per-row expansion state for the "show your work" panel. Keyed
	// by `${asset_type}:${asset_id}` so collapsing one row doesn't
	// collapse the row-with-the-same-id-in-another-tier (rare, but
	// happens when the same id is reused across asset types).
	let expanded = $state(new Set<string>());
	let searchTimer: ReturnType<typeof setTimeout> | null = null;

	// Lazy-loaded image expansion details, cached per asset_id so
	// re-expanding a row doesn't refetch. 'loading' marks an inflight
	// fetch; null marks a failed one (renders a retry-less notice).
	let imageDetails = $state(new Map<string, ImageTriageDetail | 'loading' | null>());

	const rowKey = (r: TriageRow) => `${r.asset_type}:${r.asset_id}`;
	const toggleExpanded = (key: string, row?: TriageRow) => {
		const next = new Set(expanded);
		if (next.has(key)) next.delete(key);
		else {
			next.add(key);
			if (row && row.asset_type === 'image') void loadImageDetail(row.asset_id);
		}
		expanded = next;
	};

	const loadImageDetail = async (assetId: string, force = false) => {
		// A prior fetch may have 504'd: the server keeps computing on a
		// detached context and warms its cache, so a forced retry usually
		// lands on the warm result. `force` bypasses the cached failure.
		if (!force && imageDetails.has(assetId)) return;
		const next = new Map(imageDetails);
		next.set(assetId, 'loading');
		imageDetails = next;
		try {
			const res = await fetch(`/api/triage/image/${encodeURIComponent(assetId)}`, {
				credentials: 'include'
			});
			if (!res.ok) throw new Error(`HTTP ${res.status}`);
			const detail = (await res.json()) as ImageTriageDetail;
			const done = new Map(imageDetails);
			done.set(assetId, detail);
			imageDetails = done;
		} catch {
			const failed = new Map(imageDetails);
			failed.set(assetId, null);
			imageDetails = failed;
		}
	};

	const fetchTriage = async () => {
		const params = new URLSearchParams();
		if (watchSearch.trim()) params.set('watch_q', watchSearch.trim());
		if (watchOffset > 0) params.set('watch_offset', String(watchOffset));
		if (deprioSearch.trim()) params.set('deprio_q', deprioSearch.trim());
		if (deprioOffset > 0) params.set('deprio_offset', String(deprioOffset));
		const res = await fetch(`/api/triage?${params}`, { credentials: 'include' });
		if (!res.ok) throw new Error(`Failed to load triage (HTTP ${res.status})`);
		return (await res.json()) as TriageResponse;
	};

	const reload = async () => {
		try {
			triage = await fetchTriage();
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
	const onDeprioSearchInput = () => {
		if (searchTimer) clearTimeout(searchTimer);
		searchTimer = setTimeout(() => {
			deprioOffset = 0;
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
	const goDeprioNext = () => {
		if (!triage) return;
		const next = deprioOffset + triage.deprioritized.limit;
		if (next >= triage.deprioritized.counts.total) return;
		deprioOffset = next;
		void reload();
	};
	const goDeprioPrev = () => {
		if (!triage || deprioOffset === 0) return;
		deprioOffset = Math.max(0, deprioOffset - triage.deprioritized.limit);
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
				return `${f.exposed_kev_count} KEV on exposed workload`;
			case 'kev_ransomware':
				return `${f.count} ransomware KEV${(f.count as number) === 1 ? '' : 's'}`;
			case 'kev_overdue':
				return `KEV past CISA due date`;
			case 'kev_fixable':
				return `${f.count} KEV with fix`;
			case 'kev_present':
				return `${f.kev_count} KEV CVE${(f.kev_count as number) === 1 ? '' : 's'}`;
			case 'epss_very_high':
				return `EPSS ${(((f.epss_max as number) ?? 0) * 100).toFixed(0)}%`;
			case 'epss_elevated':
				return `EPSS ${(((f.epss_max as number) ?? 0) * 100).toFixed(0)}%`;
			case 'exposed_critical':
				return `${f.critical} Critical on exposed workload`;
			case 'critical_fixable':
				return `${f.critical} Critical (fix avail.)`;
			case 'no_fix_available':
				return `No fix available`;
			case 'low_epss_not_exposed':
				return `EPSS ${(((f.epss_max as number) ?? 0) * 100).toFixed(1)}% · not exposed`;
			case 'low_severity_only':
				return `Medium/Low only`;
			case 'no_scan_data':
				return `Never scanned`;
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
					what: `${f.exposed_kev_count} CVE${(f.exposed_kev_count as number) === 1 ? '' : 's'} listed in CISA's Known Exploited Vulnerabilities catalogue sit on a workload that is reachable from the internet.`,
					why: 'KEV is the authoritative "we have seen this exploited in the wild" list. Combined with internet reach, this is the single highest-priority class of finding — public exploits typically exist.',
					action: 'Patch or remove the affected component immediately. If a fix release is unavailable, consider taking the workload offline behind authentication or a WAF until upstream lands a fix.'
				};
			case 'kev_ransomware':
				return {
					what: `${f.count} KEV CVE${(f.count as number) === 1 ? '' : 's'} on this asset ${(f.count as number) === 1 ? 'is' : 'are'} flagged by CISA as used in ransomware campaigns.`,
					why: 'Ransomware operators move laterally after the initial foothold — "not internet-facing" is not a defense once anything in the environment is compromised.',
					action: 'Apply the available fix now. Ransomware-flagged KEVs with a patch should not wait for a regular sprint window.'
				};
			case 'kev_overdue':
				return {
					what: "A KEV CVE on this asset is past the remediation due date CISA set in its catalogue (BOD 22-01).",
					why: 'The due date is the deadline US federal agencies are ordered to remediate by — a useful external bar for "this has been actionable long enough".',
					action: 'Patch if a fix exists. If none does, make an explicit risk decision this week and record it (VEX or compensating control) so the overdue state is owned, not ignored.'
				};
			case 'kev_fixable':
				return {
					what: `${f.count} KEV CVE${(f.count as number) === 1 ? '' : 's'} on this asset ${(f.count as number) === 1 ? 'has' : 'have'} a fixed version available.`,
					why: 'Confirmed in-the-wild exploitation plus an available patch is the clearest possible patch call — the only cost is the rollout.',
					action: 'Schedule the upgrade in this week\'s window. The expansion panel lists each CVE with its fixed version.'
				};
			case 'kev_present':
				return {
					what: `${f.kev_count} CVE${(f.kev_count as number) === 1 ? '' : 's'} on this asset are in CISA's Known Exploited Vulnerabilities catalogue.`,
					why: "KEV CVEs have confirmed in-the-wild exploitation. Even when the asset isn't internet-exposed today, exploit code is generally public — any future exposure path is high-risk.",
					action: 'No fix release exists yet — watch for one (the tier escalates automatically when it ships). If you accept the risk (mitigating control, not reachable, etc.), record a VEX `not_affected` so triage stops surfacing it.'
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
			case 'exposed_critical':
				return {
					what: `${f.critical} CRITICAL CVE${(f.critical as number) === 1 ? '' : 's'} sit on a workload that is reachable from the internet.`,
					why: 'Critical impact plus internet reach means a working exploit, when one appears, has a direct path in. The EPSS score on the row tells you how likely that is.',
					action: 'Patch the exposed criticals first — they outrank higher CVE counts on internal-only workloads.'
				};
			case 'critical_fixable':
				return {
					what: `${f.critical} CRITICAL CVE${(f.critical as number) === 1 ? '' : 's'} on this asset ${(f.critical as number) === 1 ? 'has' : 'have'} a fix release available.`,
					why: 'CRITICAL severity per the scanner means CVSS≥9.0 (or vendor equivalent). With a fix available, the remaining risk is purely a scheduling decision.',
					action: 'Upgrade the affected package to the fix version on the normal patch cadence. The expansion panel lists each CVE with its fixed version.'
				};
			case 'no_fix_available':
				return {
					what: `Critical or high findings exist (${f.critical} critical, ${f.high} high) but no upstream fix release is available for them.`,
					why: "There is nothing for the team to do yet — burning a sprint on an unfixable CVE is exactly the false urgency this view avoids. Nothing else on this asset predicts exploitation (low EPSS, not in KEV, not exposed).",
					action: 'No action. The tier escalates automatically when a fix ships or exploitation signals appear. Record a VEX `under_investigation` if you want the reasoning visible to auditors.'
				};
			case 'low_epss_not_exposed':
				return {
					what: `The remaining critical/high findings (${f.critical} critical, ${f.high} high) have low predicted exploitation (EPSS ${(((f.epss_max as number) ?? 0) * 100).toFixed(1)}%) and the workload is not internet-reachable.`,
					why: 'Severity alone overstates these: nothing in KEV, exploitation unlikely in the next 30 days, and no exposure path. They are queue noise compared to the tiers above.',
					action: 'Fold the upgrades into routine dependency maintenance. The tier escalates automatically if EPSS rises, the CVE enters KEV, or the workload becomes exposed.'
				};
			case 'low_severity_only':
				return {
					what: `Only medium/low findings exist on this asset (${f.medium} medium, ${f.low} low).`,
					why: 'Medium and low severities almost never carry standalone exploitation risk; they matter in chains, which the exposure and EPSS signals would surface.',
					action: 'No dedicated action — these resolve as a side effect of routine image rebuilds and dependency bumps.'
				};
			case 'no_scan_data':
				return {
					what: 'This asset has no scan data — no SBOM or no completed scan run.',
					why: 'The asset is listed so "deprioritized" stays honest: we are not saying it is safe, we are saying we cannot see it.',
					action: 'Trigger a scan from the asset detail page so the asset gets a real tier.'
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
			case 'kev_ransomware':
			case 'kev_overdue':
				return 'pill pill-error';
			case 'kev_fixable':
			case 'kev_present':
			case 'epss_very_high':
			case 'epss_elevated':
			case 'exposed_critical':
			case 'critical_fixable':
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

	// --- Attack-path rendering ------------------------------------
	// The card head renders an abstract path from signals alone (no
	// lazy fetch): entry → blast surface → weakness → fix. The
	// expansion replaces it with the concrete trace (domains, CVEs,
	// packages) once the per-image detail loads.
	type ChipTone = 'error' | 'warning' | 'ok' | 'muted';
	type PathChip = { label: string; tone: ChipTone };

	const pathChips = (r: TriageRow): PathChip[] => {
		const chips: PathChip[] = [];
		if (r.active_secret_count > 0) {
			chips.push({
				label: `${r.active_secret_count} live credential${r.active_secret_count === 1 ? '' : 's'}`,
				tone: 'error'
			});
		}
		chips.push(
			r.internet_exposed ? { label: 'internet', tone: 'warning' } : { label: 'internal only', tone: 'muted' }
		);
		if (r.asset_type === 'image' && r.cluster_count > 0) {
			chips.push(
				r.exposed_cluster_count > 0
					? {
							label: `exposed in ${r.exposed_cluster_count}/${r.cluster_count} cluster${r.cluster_count === 1 ? '' : 's'}`,
							tone: 'warning'
						}
					: { label: `${r.cluster_count} cluster${r.cluster_count === 1 ? '' : 's'}`, tone: 'muted' }
			);
		}
		// One weakness chip — the strongest signal, not an inventory.
		if (r.exposed_kev_count > 0) {
			chips.push({ label: `${r.exposed_kev_count} KEV on path`, tone: 'error' });
		} else if (r.kev_count > 0) {
			chips.push({ label: `${r.kev_count} KEV`, tone: 'error' });
		} else if (r.exposed_critical_count > 0) {
			chips.push({ label: `${r.exposed_critical_count} critical on path`, tone: 'warning' });
		} else if (r.critical_count > 0) {
			chips.push({ label: `${r.critical_count} critical`, tone: 'warning' });
		} else if (r.high_count > 0) {
			chips.push({ label: `${r.high_count} high`, tone: 'muted' });
		} else if (r.medium_count + r.low_count > 0) {
			chips.push({ label: 'medium/low only', tone: 'muted' });
		}
		if (r.epss_max >= 0.1) {
			chips.push({
				label: `EPSS ${(r.epss_max * 100).toFixed(0)}%`,
				tone: r.epss_max >= 0.5 ? 'error' : 'warning'
			});
		}
		if (r.kev_count > 0 || r.critical_count > 0 || r.high_count > 0) {
			const fixable = r.kev_fixable_count > 0 || r.has_fix_for_critical || r.has_fix_for_high;
			chips.push(fixable ? { label: 'fix available', tone: 'ok' } : { label: 'no fix yet', tone: 'muted' });
		}
		return chips;
	};

	// One concrete next step per card, derived from the same signals
	// the tier rules read.
	const actionLine = (r: TriageRow): string => {
		if (r.active_secret_count > 0) {
			return 'Rotate the leaked credentials at the issuing provider now, then scrub them from git history.';
		}
		const fixable = r.kev_fixable_count > 0 || r.has_fix_for_critical || r.has_fix_for_high;
		const redeploy =
			r.asset_type === 'image' && r.cluster_count > 0
				? ` and redeploy to ${r.cluster_count} cluster${r.cluster_count === 1 ? '' : 's'}`
				: '';
		if (fixable) {
			if (r.asset_type === 'image') return `Rebuild the image with the patched versions below${redeploy}.`;
			if (r.asset_type === 'repo') return 'Bump the affected dependencies to their fixed versions.';
			return 'Rebuild and redeploy the affected images listed in the tiers above.';
		}
		if (r.kev_count > 0 || r.critical_count > 0 || r.high_count > 0) {
			return r.internet_exposed
				? 'No fix released — reduce exposure (auth, WAF, or take it off the internet) and watch for a patch.'
				: 'No fix released — nothing actionable yet; the tier escalates automatically when a patch ships.';
		}
		if (!r.has_sbom || r.last_scan_at === null) {
			return 'Trigger a scan so this asset gets a real tier.';
		}
		return 'No action needed — resolves as a side effect of routine rebuilds.';
	};

	// Off-path CVE visibility per card. Hidden by default: if a vuln
	// is not on the attack path it is noise for threat modelling, even
	// at high CVSS.
	// Floating finding chat — one window at a time, keyed to the row
	// whose "Chat about this" button opened it.
	let chatOpen = $state(false);
	let chatAsset = $state({ type: '', id: '', slug: '' });
	const openChat = (row: TriageRow) => {
		chatAsset = { type: row.asset_type, id: row.asset_id, slug: row.asset_slug };
		chatOpen = true;
	};

	// Advisory dialog — same component the image page uses, so a CVE
	// click stays in context instead of navigating away.
	let vulnDialogOpen = $state(false);
	let vulnDialogId = $state('');
	const openVulnDialog = (id: string) => {
		vulnDialogId = id;
		vulnDialogOpen = true;
	};


	let offPathShown = $state(new Set<string>());
	const toggleOffPath = (key: string) => {
		const next = new Set(offPathShown);
		if (next.has(key)) next.delete(key);
		else next.add(key);
		offPathShown = next;
	};

	// Server-computed average trust across every actionable asset
	// (fix_now + this_week + entire watch tier, pre-cap). The previous
	// client-side average mixed capped tiers with only the current
	// watch page, so it drifted as the operator paginated.
	const avgTrust = $derived(() => {
		if (!triage) return null;
		// 0 is a valid value (everything failing). Show null only when
		// there are genuinely no actionable rows to average over.
		if (triage.scope.needs_attention === 0 && triage.watch.counts.total === 0) return null;
		return triage.scope.avg_trust;
	});

	// Asset-type distribution donut: how does the "needs attention"
	// population break down across repos / images? Clusters aren't
	// tier rows anymore — they live in the rollup lens below.
	const distributionSegments = $derived((): DonutSegment[] => {
		if (!triage) return [];
		const counts = { repo: 0, image: 0, cluster: 0 };
		for (const r of [...triage.fix_now, ...triage.this_week]) {
			counts[r.asset_type]++;
		}
		// Watch counts already pre-bucketed in the response.
		counts.repo += triage.watch.counts.repo;
		counts.image += triage.watch.counts.image;
		const segs: DonutSegment[] = [];
		if (counts.repo > 0) segs.push({ label: 'Repos', value: counts.repo, color: 'var(--accent)' });
		if (counts.image > 0) segs.push({ label: 'Images', value: counts.image, color: 'var(--info)' });
		return segs;
	});

	const distributionTotal = $derived(() => {
		const segs = distributionSegments();
		return segs.reduce((a, b) => a + b.value, 0);
	});

	const tierSegments = $derived((): DonutSegment[] => {
		if (!triage) return [];
		const segs: DonutSegment[] = [];
		// Use the un-capped totals so the donut reflects the real tier
		// population (fix_now / this_week arrays on the response are
		// trimmed to fixNowCap / thisWeekCap; using their .length here
		// would understate the picture).
		if (triage.scope.fix_now_total > 0) segs.push({ label: 'Fix now', value: triage.scope.fix_now_total, color: 'var(--error)' });
		if (triage.scope.this_week_total > 0) segs.push({ label: 'This week', value: triage.scope.this_week_total, color: 'var(--warning)' });
		if (triage.watch.counts.total > 0) segs.push({ label: 'Watch', value: triage.watch.counts.total, color: 'var(--text-muted)' });
		if (triage.deprioritized.counts.total > 0) segs.push({ label: 'Deprioritized', value: triage.deprioritized.counts.total, color: 'color-mix(in srgb, var(--text-muted) 45%, transparent)' });
		return segs;
	});

	const tierTotal = $derived(() => {
		if (!triage) return 0;
		return (
			triage.scope.fix_now_total +
			triage.scope.this_week_total +
			triage.watch.counts.total +
			triage.deprioritized.counts.total
		);
	});

	// Tier tabs decide which sections render; the lists themselves are
	// untouched. 'urgent' = fix_now + this_week together.
	const showUrgent = $derived(() => activeTab === 'all' || activeTab === 'urgent');
	const showWatch = $derived(() => activeTab === 'all' || activeTab === 'watch');
	const showDeprio = $derived(() => activeTab === 'all' || activeTab === 'deprioritized');
	// Selecting the deprioritized tab implies wanting to see it open.
	const deprioExpanded = $derived(() => deprioOpen || activeTab === 'deprioritized');

	// Total count for the active tab — shown under the Findings header.
	// Uses the un-capped totals so it reflects the real population.
	const activeTabTotal = $derived(() => {
		if (!triage) return 0;
		switch (activeTab) {
			case 'urgent':
				return triage.scope.fix_now_total + triage.scope.this_week_total;
			case 'watch':
				return triage.watch.counts.total;
			case 'deprioritized':
				return triage.deprioritized.counts.total;
			default:
				return triage.scope.fix_now_total + triage.scope.this_week_total + triage.watch.counts.total;
		}
	});

	// Severity inventory + scan freshness for the collapsed card's
	// meta line — informative without opening the card.
	const metaLine = (r: TriageRow): string => {
		const parts: string[] = [];
		if (r.critical_count > 0) parts.push(`${fmt(r.critical_count)} critical`);
		if (r.high_count > 0) parts.push(`${fmt(r.high_count)} high`);
		if (r.medium_count + r.low_count > 0) parts.push(`${fmt(r.medium_count + r.low_count)} med/low`);
		if (parts.length === 0) parts.push('no open CVEs');
		parts.push(r.scan_age_days >= 999 ? 'never scanned' : r.scan_age_days <= 0 ? 'scanned today' : `scanned ${r.scan_age_days}d ago`);
		return parts.join(' · ');
	};

	const severityClass = (sev: string): string => {
		switch (sev) {
			case 'CRITICAL':
				return 'sev sev-critical';
			case 'HIGH':
				return 'sev sev-high';
			case 'MEDIUM':
				return 'sev sev-medium';
			default:
				return 'sev sev-low';
		}
	};
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
						<p class="text-sm text-[var(--text-tertiary)]">Image-first advisory — which image to act on, ranked by KEV and EPSS, with what's safe to ignore.</p>
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
			<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-6">
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Need attention</h3>
					<p class="text-3xl font-bold {triage.scope.needs_attention === 0 ? 'text-[var(--success)]' : 'text-[var(--text-bright)]'}">{fmt(triage.scope.needs_attention)}</p>
					<p class="text-xs text-[var(--text-muted)]">across {fmt(triage.scope.repos + triage.scope.images + triage.scope.clusters)} assets</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Fix now</h3>
					<p class="text-3xl font-bold text-[var(--error)]">{fmt(triage.scope.fix_now_total)}</p>
					<p class="flex items-normal gap-1 text-xs text-[var(--text-muted)]"><ShieldAlert class="h-3 w-3 text-[var(--error)]" /> Acute, exposed, or leaking</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">This week</h3>
					<p class="text-3xl font-bold text-[var(--warning)]">{fmt(triage.scope.this_week_total)}</p>
					<p class="flex items-normal gap-1 text-xs text-[var(--text-muted)]"><AlertTriangle class="h-3 w-3 text-[var(--warning)]" /> High-risk or stale</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Watch</h3>
					<p class="text-3xl font-bold text-[var(--text-secondary)]">{fmt(triage.watch.counts.total)}</p>
					<p class="flex items-normal gap-1 text-xs text-[var(--text-muted)]"><Eye class="h-3 w-3 text-[var(--text-muted)]" /> Real but not urgent</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Deprioritized</h3>
					<p class="text-3xl font-bold text-[var(--text-muted)]">{fmt(triage.deprioritized.counts.total)}</p>
					<p class="flex items-normal gap-1 text-xs text-[var(--text-muted)]"><EyeOff class="h-3 w-3 text-[var(--text-muted)]" /> Reviewed, not actionable</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Avg trust</h3>
					{#if avgTrust() === null}
						<p class="text-3xl font-bold text-[var(--text-secondary)]">—</p>
						<p class="flex items-normal gap-1 text-xs text-[var(--text-muted)]"><ShieldCheck class="h-3 w-3" /> No actionable assets</p>
					{:else}
						<p class="text-3xl font-bold" style="color: {trustColor((avgTrust() ?? 0) >= 90 ? 'A' : (avgTrust() ?? 0) >= 75 ? 'B' : (avgTrust() ?? 0) >= 60 ? 'C' : 'F')}">{avgTrust()}</p>
						<p class="flex items-normal gap-1 text-xs text-[var(--text-muted)]"><ShieldCheck class="h-3 w-3" /> Across actionable assets</p>
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
						{ value: 'urgent', label: 'Urgent' },
						{ value: 'watch', label: 'Watch' },
						{ value: 'deprioritized', label: 'Deprioritized' }
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
							{fmt(activeTabTotal())} asset{activeTabTotal() === 1 ? '' : 's'} ranked by KEV and EPSS
						{:else}
							No assets in this filter
						{/if}
					</p>
				</div>
			</header>

			{#snippet triageRow(row: TriageRow, threatLevel: 'critical' | 'warning' | 'info', compact: boolean)}
				{@const Icon = rowIcon(row.asset_type)}
				{@const key = rowKey(row)}
				{@const isOpen = expanded.has(key)}
				<div class="card" class:open={isOpen} class:compact>
					<button
						type="button"
						class="card-head"
						aria-expanded={isOpen}
						onclick={() => toggleExpanded(key, row)}
					>
						<div class="icon-tile" data-level={threatLevel}>
							<Icon size={compact ? 16 : 20} />
						</div>
						<div class="card-main">
							<div class="card-top">
								<span class="asset-slug">{row.asset_slug}</span>
								<span class="asset-kind">{row.asset_type}</span>
							</div>
							<div class="card-meta">{metaLine(row)}</div>
							<div class="path-strip">
								{#each pathChips(row) as chip, i}
									{#if i > 0}<span class="path-sep" aria-hidden="true">▸</span>{/if}
									<span class="chip chip-{chip.tone}">{chip.label}</span>
								{/each}
							</div>
						</div>
						<div class="card-side">
							<a
								class="card-open"
								href={rowHref(row)}
								title="Open {row.asset_type} detail"
								onclick={(e) => e.stopPropagation()}
							>
								<ArrowUpRight size={13} />
							</a>
							<ChevronDown size={14} class="row-chevron {isOpen ? 'open' : ''}" />
						</div>
					</button>
					{#if isOpen}
						<div class="card-body">
							{#if row.advisory?.summary}
								<div class="stage stage-advisory">
									<span class="stage-label">Advisory</span>
									<div class="stage-body">
										<span class="stage-text advisory-text">{row.advisory.summary}</span>
										<span class="stage-hint">AI-generated · {row.advisory.summary_model}{row.advisory.stale ? ' · signals changed since generation' : ''}</span>
									</div>
								</div>
							{/if}
							{#if row.asset_type === 'image'}
								{@const detail = imageDetails.get(row.asset_id)}
								{#if detail === 'loading' || detail === undefined}
									<div class="detail-loading">Tracing attack path…</div>
								{:else if detail === null}
									<div class="detail-loading">
										Could not load attack-path details.
										<button
											type="button"
											class="detail-retry"
											onclick={() => void loadImageDetail(row.asset_id, true)}
										>
											Retry
										</button>
									</div>
								{:else}
									{@const onPath = detail.vulns.filter((v) => v.on_path)}
									{@const offPath = detail.vulns.filter((v) => !v.on_path)}
									{@const offTotal = detail.vuln_total - onPath.length}
									<div class="stage">
										<span class="stage-label">Entry</span>
										<div class="stage-body">
											{#if detail.hosts.length > 0}
												<div class="host-chips">
													{#each detail.hosts as h}
														<span class="host-chip" title="{h.cluster || h.cluster_id} / {h.namespace}">
															{#if h.tls}<Lock size={11} />{:else}<Globe size={11} />{/if}
															{h.host}
														</span>
													{/each}
												</div>
											{:else}
												<span class="stage-muted">No internet path — reachable only from inside the cluster.</span>
											{/if}
										</div>
									</div>
									<div class="stage">
										<span class="stage-label">Runs in</span>
										<div class="stage-body">
											{#if detail.clusters.length > 0}
												<div class="host-chips">
													{#each detail.clusters as cl}
														<Tooltip width={17}>
															<span class="chip chip-{cl.exposed ? 'warning' : 'muted'} cursor-pointer">
																{cl.name}{cl.exposed ? ' · exposed' : ''}
															</span>
															{#snippet content()}
																<p class="text-xs font-semibold text-[var(--text-bright)]">{cl.name}</p>
																{#if cl.cluster_id !== cl.name}
																	<p class="mt-0.5 text-[11px] text-[var(--text-muted)]">{cl.cluster_id}</p>
																{/if}
																{#if cl.namespaces}
																	<p class="mt-1.5 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">Namespace{cl.namespaces.includes(',') ? 's' : ''}</p>
																	<p class="mt-0.5 text-xs leading-relaxed text-[var(--text-secondary)]">{cl.namespaces}</p>
																{/if}
															{/snippet}
														</Tooltip>
													{/each}
												</div>
												{#if detail.cluster_total > detail.clusters.length}
													<span class="stage-hint">+{detail.cluster_total - detail.clusters.length} cluster{detail.cluster_total - detail.clusters.length === 1 ? '' : 's'} outside your access</span>
												{/if}
											{:else if detail.cluster_total > 0}
												<span class="stage-muted">{detail.cluster_total} cluster{detail.cluster_total === 1 ? '' : 's'} — all outside your access.</span>
											{:else}
												<span class="stage-muted">Not currently running in any cluster.</span>
											{/if}
										</div>
									</div>
									<div class="stage">
										<span class="stage-label">Weakness</span>
										<div class="stage-body">
											{#if onPath.length > 0}
												<div class="vuln-lines">
													{#each onPath as v}
														<div class="vuln-line">
															<button
																type="button"
																class="vuln-id"
																onclick={(e) => {
																	e.stopPropagation();
																	openVulnDialog(v.canonical_id);
																}}
															>{v.canonical_id}</button>
															<span class="vuln-pkg" title="{v.pkg_name}@{v.installed_version}">{v.pkg_name}@{v.installed_version}</span>
															<span class="vuln-badges">
																{#if v.kev}
																	<span class="chip chip-error">KEV{v.kev_ransomware ? ' · ransomware' : ''}</span>
																{/if}
																{#if v.epss > 0}
																	<Tooltip width={17}>
																		<span class="chip chip-{v.epss >= 0.5 ? 'error' : v.epss >= 0.1 ? 'warning' : 'muted'}">EPSS {(v.epss * 100).toFixed(v.epss < 0.1 ? 1 : 0)}%</span>
																		{#snippet content()}
																			<p class="text-xs font-semibold text-[var(--text-bright)]">EPSS {(v.epss * 100).toFixed(1)}%</p>
																			<p class="mt-1 text-xs leading-relaxed text-[var(--text-secondary)]">
																				Probability that this CVE is exploited in the wild within the next 30 days.
																			</p>
																			{#if v.epss_percentile > 0}
																				<p class="mt-1 text-[11px] text-[var(--text-muted)]">
																					Higher than {(v.epss_percentile * 100).toFixed(0)}% of all scored CVEs.
																				</p>
																			{/if}
																			<p class="mt-1.5 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">FIRST.org · updated daily</p>
																		{/snippet}
																	</Tooltip>
																{/if}
															</span>
															<span class={severityClass(v.severity)}>{v.severity}</span>
															<span class="vuln-fix" class:none={!v.fixed_version}>{v.fixed_version ? `→ ${v.fixed_version}` : 'no fix'}</span>
														</div>
													{/each}
												</div>
											{:else if row.reasons.length > 0}
												<span class="stage-muted">{reasonExplain(row.reasons[0]).what}</span>
											{:else}
												<span class="stage-muted">No vulnerability on the attack path.</span>
											{/if}
											{#if offTotal > 0}
												<button
													type="button"
													class="offpath-toggle"
													onclick={(e) => {
														e.stopPropagation();
														toggleOffPath(key);
													}}
												>
													{offPathShown.has(key) ? 'Hide' : 'Show'} {offTotal} CVE{offTotal === 1 ? '' : 's'} not on this attack path
												</button>
												{#if offPathShown.has(key)}
													<div class="vuln-lines">
														{#each offPath as v}
															<div class="vuln-line dim">
																<button
																	type="button"
																	class="vuln-id"
																	onclick={(e) => {
																		e.stopPropagation();
																		openVulnDialog(v.canonical_id);
																	}}
																>{v.canonical_id}</button>
																<span class="vuln-pkg" title="{v.pkg_name}@{v.installed_version}">{v.pkg_name}@{v.installed_version}</span>
																<span class="vuln-badges"></span>
																<span class={severityClass(v.severity)}>{v.severity}</span>
																<span class="vuln-fix" class:none={!v.fixed_version}>{v.fixed_version ? `→ ${v.fixed_version}` : 'no fix'}</span>
															</div>
														{/each}
													</div>
													{#if detail.vuln_total > detail.vulns.length}
														<span class="detail-empty">
															<a href={rowHref(row)} onclick={(e) => e.stopPropagation()}>Open image</a> for all {detail.vuln_total} CVEs.
														</span>
													{/if}
												{/if}
											{/if}
										</div>
									</div>
									<div class="stage">
										<span class="stage-label">Action</span>
										<div class="stage-body"><span class="stage-text">{actionLine(row)}</span></div>
									</div>
								{/if}
							{:else}
								<div class="stage">
									<span class="stage-label">Entry</span>
									<div class="stage-body">
										<span class="stage-text">
											{row.asset_type === 'repo'
												? 'Supply chain — source repository, not directly reachable.'
												: row.internet_exposed
													? 'Internet-facing workloads run in this cluster.'
													: 'Internal only — no internet-facing workloads.'}
										</span>
									</div>
								</div>
								{#if row.reasons.length > 0}
									<div class="stage">
										<span class="stage-label">Weakness</span>
										<div class="stage-body">
											<span class="stage-text">{reasonExplain(row.reasons[0]).what}</span>
										</div>
									</div>
								{/if}
								<div class="stage">
									<span class="stage-label">Action</span>
									<div class="stage-body"><span class="stage-text">{actionLine(row)}</span></div>
								</div>
							{/if}

							{#if row.context.length > 0}
								<div class="stage">
									<span class="stage-label">Posture</span>
									<div class="stage-body">
										<div class="context-pills">
											{#each row.context as reason}
												<span class="chip chip-muted">{renderReason(reason)}</span>
											{/each}
										</div>
										<span class="stage-hint">Context only — does not affect the tier.</span>
									</div>
								</div>
							{/if}

							{#if row.advisory?.verdict}
								<div class="stage">
									<span class="stage-label">Agent</span>
									<div class="stage-body">
										<div class="context-pills">
											<span class="chip chip-{row.advisory.verdict === 'suppress' ? 'muted' : 'warning'}">{row.advisory.verdict === 'suppress' ? 'would suppress' : 'would keep'}</span>
											{#if row.advisory.verdict_confidence}
												<span class="chip chip-muted">{Math.round(row.advisory.verdict_confidence * 100)}% confident</span>
											{/if}
										</div>
										{#if row.advisory.verdict_justification}
											<span class="stage-text">{row.advisory.verdict_justification}</span>
										{/if}
										{#if row.advisory.verdict_missing_data}
											<span class="stage-hint">Would verify: {row.advisory.verdict_missing_data}</span>
										{/if}
										<span class="stage-hint">Shadow mode — recorded to evaluate the agent, takes no action.</span>
									</div>
								</div>
							{/if}

							{#if row.asset_type !== 'cluster'}
								<div class="card-actions">
									<button
										type="button"
										class="chat-open-btn"
										onclick={(e) => {
											e.stopPropagation();
											openChat(row);
										}}
									>
										<Bot size={13} />
										Chat about this
									</button>
								</div>
							{/if}
						</div>
					{/if}
				</div>
			{/snippet}

			{#if triage.fix_now.length === 0 && triage.this_week.length === 0 && triage.watch.counts.total === 0 && triage.deprioritized.counts.total === 0}
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
							<h3 class="text-base font-semibold text-[var(--text-bright)]">Nothing in this tier</h3>
							<p class="text-sm text-[var(--text-tertiary)]">Switch tab or check back after the next scan.</p>
						</div>
					</div>
				</div>
			{:else}

				<!-- Fix now -->
				{#if showUrgent() && triage.fix_now.length > 0}
					<div class="tier" data-tier="fix-now">
						<div class="tier-head">
							<ShieldAlert size={18} class="text-[var(--error)]" />
							<h3 class="tier-title">Fix now</h3>
							<span class="badge">{triage.scope.fix_now_total}</span>
							<span class="tier-sub">Exploited in the wild and reachable, or leaking credentials</span>
						</div>
						<div class="tier-rows">
							{#each triage.fix_now as row}
								{@render triageRow(row, 'critical', false)}
							{/each}
						</div>
					</div>
				{/if}

				<!-- This week -->
				{#if showUrgent() && triage.this_week.length > 0}
					<div class="tier" data-tier="this-week">
						<div class="tier-head">
							<AlertTriangle size={18} class="text-[var(--warning)]" />
							<h3 class="tier-title">This week</h3>
							<span class="badge">{triage.scope.this_week_total}</span>
							<span class="tier-sub">Confirmed or likely exploitation, not internet-reachable</span>
						</div>
						<div class="tier-rows">
							{#each triage.this_week as row}
								{@render triageRow(row, 'warning', false)}
							{/each}
						</div>
					</div>
				{/if}

				<!-- Watch -->
				{#if showWatch()}
				<div class="tier" data-tier="watch">
					<div class="tier-head">
						<Eye size={18} class="text-[var(--text-muted)]" />
						<h3 class="tier-title">Watch</h3>
						<span class="badge">{triage.watch.counts.total}</span>
						<span class="tier-sub">Real but not urgent — normal patch cadence</span>
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

					{#if triage.watch.rows.length === 0}
						<div class="watch-empty">
							{#if watchSearch.trim()}
								No watch-tier assets match "{watchSearch}".
							{:else}
								No additional warnings beyond the urgent tiers.
							{/if}
						</div>
					{:else}
						<div class="tier-rows compact">
							{#each triage.watch.rows as row}
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

				<!-- Deprioritized — collapsed by default; the explicit
				     "safe to ignore, and here's why" pile. -->
				{#if showDeprio()}
				<div class="tier" data-tier="deprioritized">
					<button type="button" class="tier-head tier-head-toggle" onclick={() => (deprioOpen = !deprioExpanded())} aria-expanded={deprioExpanded()}>
						<EyeOff size={18} class="text-[var(--text-muted)]" />
						<h3 class="tier-title">Deprioritized</h3>
						<span class="badge">{triage.deprioritized.counts.total}</span>
						<span class="tier-sub">Not worth acting on right now — each row says why</span>
						<ChevronDown size={14} class="row-chevron {deprioExpanded() ? 'open' : ''}" />
					</button>

					{#if deprioExpanded()}
						<div class="tier-head deprio-tools">
							<div class="watch-search">
								<Search size={13} class="search-icon" />
								<input
									type="text"
									class="input"
									placeholder="Filter deprioritized…"
									bind:value={deprioSearch}
									oninput={onDeprioSearchInput}
								/>
							</div>
						</div>

						{#if triage.deprioritized.rows.length === 0}
							<div class="watch-empty">
								{#if deprioSearch.trim()}
									No deprioritized assets match "{deprioSearch}".
								{:else}
									Nothing has been deprioritized.
								{/if}
							</div>
						{:else}
							<div class="tier-rows compact">
								{#each triage.deprioritized.rows as row}
									{@render triageRow(row, 'info', true)}
								{/each}
							</div>

							{#if triage.deprioritized.counts.total > triage.deprioritized.limit}
								<div class="pagination">
									<button type="button" class="btn btn-ghost" onclick={goDeprioPrev} disabled={deprioOffset === 0}>← Prev</button>
									<span class="pagination-info">
										{deprioOffset + 1}–{Math.min(deprioOffset + triage.deprioritized.limit, triage.deprioritized.counts.total)} of {triage.deprioritized.counts.total}
									</span>
									<button type="button" class="btn btn-ghost" onclick={goDeprioNext} disabled={deprioOffset + triage.deprioritized.limit >= triage.deprioritized.counts.total}>Next →</button>
								</div>
							{/if}
						{/if}
					{/if}
				</div>
				{/if}
			{/if}

			<!-- Cluster lens — read-only rollup, not part of the tiers.
			     Answers "which cluster is worst" while the fix itself
			     happens on the image rows above. -->
			{#if activeTab === 'all' && triage.clusters.length > 0}
				<div class="tier" data-tier="clusters">
					<div class="tier-head">
						<span class="flex items-center text-[var(--text-muted)]"><KubernetesIcon size={18} /></span>
						<h3 class="tier-title">Clusters</h3>
						<span class="badge">{triage.clusters.length}</span>
						<span class="tier-sub">Rollup of the images running there — fix the images above, not the cluster</span>
					</div>
					<div class="tier-rows compact">
						{#each triage.clusters as row}
							{@render triageRow(row, 'info', true)}
						{/each}
					</div>
				</div>
			{/if}
		</section>
	{/if}
</div>

<VulnAdvisoryDialog bind:open={vulnDialogOpen} vulnId={vulnDialogId} />

<FindingChat bind:open={chatOpen} assetType={chatAsset.type} assetId={chatAsset.id} assetSlug={chatAsset.slug} />

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
	.tier-title {
		font-size: 0.95rem;
		font-weight: 600;
		color: var(--text-bright);
		letter-spacing: 0.02em;
	}
	.tier-sub {
		font-size: 0.75rem;
		color: var(--text-muted);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}
	/* The deprioritized header doubles as its collapse toggle. */
	.tier-head-toggle {
		width: 100%;
		border: 0;
		background: transparent;
		color: inherit;
		font: inherit;
		text-align: left;
		cursor: pointer;
	}
	.tier-head-toggle :global(.row-chevron) {
		margin-left: auto;
	}
	.deprio-tools {
		justify-content: flex-end;
	}

	.tier-rows {
		display: flex;
		flex-direction: column;
		gap: 0.85rem;
	}
	.tier-rows.compact {
		gap: 0.6rem;
	}

	/* Cards: tinted surfaces with a neutral border. Severity is carried
	   by the dot + chip tones, never by border colors or edge stripes. */
	.card {
		border-radius: 0.85rem;
		border: 1px solid #3e3b3b;
		background-color: var(--main-content-bg);
		overflow: hidden;
		transition: background-color 120ms ease;
	}
	:global(html.light) .card {
		border-color: #d7dde4;
	}
	.card:not(.open):hover {
		background-color: var(--hover-bg-subtle);
	}

	.card-head {
		width: 100%;
		display: flex;
		align-items: center;
		gap: 0.9rem;
		padding: 0.8rem 1rem;
		border: 0;
		background: transparent;
		color: inherit;
		font: inherit;
		text-align: left;
		cursor: pointer;
	}
	.card.compact .card-head {
		padding: 0.55rem 0.85rem;
		font-size: 0.85rem;
	}

	/* Asset icon in a quiet tile; the tier level tints the glyph,
	   nothing else — no borders, no stripes. */
	.icon-tile {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 2.6rem;
		height: 2.6rem;
		flex-shrink: 0;
	}
	.card.compact .icon-tile {
		width: 2.1rem;
		height: 2.1rem;
	}
	.icon-tile[data-level='critical'] {
		color: var(--error);
	}
	.icon-tile[data-level='warning'] {
		color: var(--warning);
	}
	.icon-tile[data-level='info'] {
		color: var(--text-muted);
	}

	.card-main {
		display: flex;
		flex-direction: column;
		gap: 0.3rem;
		min-width: 0;
		flex: 1 1 auto;
	}
	.card-top {
		display: flex;
		align-items: baseline;
		gap: 0.5rem;
		min-width: 0;
	}
	.card-meta {
		font-size: 0.72rem;
		color: var(--text-muted);
		white-space: nowrap;
		overflow: hidden;
		text-overflow: ellipsis;
	}
	.card.compact .card-meta {
		display: none;
	}
	.asset-slug {
		font-weight: 600;
		color: var(--text-bright);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.asset-kind {
		font-size: 0.62rem;
		font-weight: 700;
		text-transform: uppercase;
		letter-spacing: 0.1em;
		color: var(--text-muted);
		flex-shrink: 0;
	}

	/* Abstract attack path: entry ▸ surface ▸ weakness ▸ fix. */
	.path-strip {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.3rem;
		min-width: 0;
		padding-top: 0.1rem;
	}
	.path-sep {
		color: var(--text-muted);
		font-size: 0.58rem;
		opacity: 0.7;
	}
	.chip {
		font-size: 0.7rem;
		font-weight: 600;
		padding: 0.12rem 0.5rem;
		border-radius: 999px;
		white-space: nowrap;
	}
	.chip-error {
		color: var(--error);
		background: color-mix(in srgb, var(--error) 13%, transparent);
	}
	.chip-warning {
		color: var(--warning);
		background: color-mix(in srgb, var(--warning) 13%, transparent);
	}
	.chip-ok {
		color: var(--success);
		background: color-mix(in srgb, var(--success) 13%, transparent);
	}
	.chip-muted {
		color: var(--text-muted);
		background: color-mix(in srgb, var(--text-muted) 11%, transparent);
	}

	.card-side {
		display: inline-flex;
		align-items: center;
		gap: 0.45rem;
		color: var(--text-muted);
		flex-shrink: 0;
	}
	.card-open {
		display: inline-flex;
		align-items: center;
		padding: 0.3rem;
		border-radius: 0.45rem;
		color: var(--text-muted);
		transition: color 120ms ease, background 120ms ease;
	}
	.card-open:hover {
		color: var(--text-bright);
		background: color-mix(in srgb, var(--accent) 14%, transparent);
	}
	.row-chevron {
		transition: transform 120ms ease, color 120ms ease;
	}
	:global(.row-chevron.open) {
		transform: rotate(180deg);
		color: var(--accent);
	}

	/* Expanded body: the concrete attack-path trace, staged like a
	   threat model — Entry / Runs in / Weakness / Action / Posture. */
	.card-body {
		display: flex;
		flex-direction: column;
		gap: 0.6rem;
		padding: 0.15rem 1rem 1rem 4.5rem;
	}
	.card.compact .card-body {
		padding-left: 3.8rem;
	}
	.stage {
		display: grid;
		grid-template-columns: 84px minmax(0, 1fr);
		gap: 0.8rem;
		align-items: start;
	}
	.stage-label {
		font-size: 0.6rem;
		font-weight: 700;
		text-transform: uppercase;
		letter-spacing: 0.13em;
		color: var(--text-tertiary);
		padding-top: 0.2rem;
	}
	.stage-body {
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
	}
	.stage-text {
		font-size: 0.8rem;
		color: var(--text-secondary);
		line-height: 1.45;
	}
	.stage-muted {
		font-size: 0.78rem;
		color: var(--text-muted);
		line-height: 1.45;
	}
	.stage-hint {
		font-size: 0.66rem;
		color: var(--text-muted);
	}
	/* The AI advisory is the headline of the expansion — give it air
	   above and below so it reads before the evidence stages. */
	.stage-advisory {
		padding: 0.9rem 0 1.1rem;
	}
	.advisory-text {
		font-size: 0.86rem;
		color: var(--text-bright);
		max-width: 80%;
	}
	.card-actions {
		display: flex;
		justify-content: flex-end;
		padding-top: 0.2rem;
	}
	.chat-open-btn {
		display: inline-flex;
		align-items: center;
		gap: 0.35rem;
		align-self: flex-start;
		border: 0;
		background: none;
		padding: 0;
		font-size: 0.72rem;
		font-weight: 600;
		color: var(--accent);
		cursor: pointer;
		transition: opacity 120ms ease;
	}
	.chat-open-btn:hover {
		opacity: 0.75;
	}

	.detail-loading,
	.detail-empty {
		font-size: 0.78rem;
		color: var(--text-muted);
	}
	.detail-empty a {
		color: var(--accent);
		text-decoration: none;
	}
	.detail-retry {
		margin-left: 0.5rem;
		padding: 0.1rem 0.5rem;
		font-size: 0.72rem;
		color: var(--accent);
		background: transparent;
		border: 1px solid var(--accent);
		border-radius: 0.25rem;
		cursor: pointer;
	}
	.detail-retry:hover {
		background: var(--accent);
		color: var(--bg);
	}

	.host-chips {
		display: flex;
		flex-wrap: wrap;
		gap: 0.35rem;
	}
	.host-chip {
		display: inline-flex;
		align-items: center;
		gap: 0.3rem;
		font-size: 0.75rem;
		font-variant-numeric: tabular-nums;
		padding: 0.2rem 0.55rem;
		border-radius: 999px;
		background: color-mix(in srgb, var(--warning) 9%, transparent);
		color: var(--text-secondary);
	}

	/* One grid for all CVE lines: columns size to their widest cell
	   (aligned like a table) but the table hugs its content instead
	   of stretching across the card. Each .vuln-line contributes its
	   five cells via display: contents. */
	.vuln-lines {
		display: grid;
		grid-template-columns: repeat(5, max-content);
		column-gap: 1.1rem;
		row-gap: 0.3rem;
		align-items: center;
		width: fit-content;
		max-width: 100%;
		font-size: 0.78rem;
		overflow-x: auto;
	}
	.vuln-line {
		display: contents;
	}
	.vuln-line.dim > :global(*) {
		opacity: 0.55;
	}
	.vuln-badges {
		display: inline-flex;
		align-items: center;
		gap: 0.35rem;
	}
	.vuln-id {
		font-weight: 600;
		color: var(--accent);
		text-decoration: none;
		white-space: nowrap;
		border: 0;
		background: none;
		padding: 0;
		font: inherit;
		font-weight: 600;
		text-align: left;
		cursor: pointer;
	}
	.vuln-id:hover {
		text-decoration: underline;
	}
	.vuln-pkg {
		color: var(--text-muted);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 30ch;
	}
	.vuln-fix {
		color: var(--success);
		white-space: nowrap;
		font-variant-numeric: tabular-nums;
	}
	.vuln-fix.none {
		color: var(--text-muted);
	}
	.sev {
		font-size: 0.66rem;
		font-weight: 700;
		letter-spacing: 0.05em;
	}
	.sev-critical {
		color: var(--error);
	}
	.sev-high {
		color: var(--warning);
	}
	.sev-medium {
		color: var(--text-secondary);
	}
	.sev-low {
		color: var(--text-muted);
	}

	.offpath-toggle {
		align-self: flex-start;
		border: 0;
		background: none;
		padding: 0;
		font-size: 0.72rem;
		color: var(--text-muted);
		text-decoration: underline dotted;
		cursor: pointer;
		transition: color 120ms ease;
	}
	.offpath-toggle:hover {
		color: var(--text-secondary);
	}

	.context-pills {
		display: flex;
		flex-wrap: wrap;
		gap: 0.35rem;
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
		border-radius: 0.85rem;
		background: color-mix(in srgb, var(--bg2) 55%, transparent);
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
