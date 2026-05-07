<script lang="ts">
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { ShieldX, ShieldAlert, Shield, GitBranch, Container, SlidersHorizontal, Search, ExternalLink } from 'lucide-svelte';
	import { slide } from 'svelte/transition';
	import { cubicOut } from 'svelte/easing';
	import DonutChart from '$lib/components/DonutChart.svelte';
	import LineChart from '$lib/components/LineChart.svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';
	import VulnBadges from '$lib/components/VulnBadges.svelte';
	import EmptyRepos from '$lib/components/icons/EmptyRepos.svelte';
	import EmptyVulns from '$lib/components/icons/EmptyVulns.svelte';
	import ImageDrawer from '$lib/components/ImageDrawer.svelte';
	import Toggle from '$lib/components/Toggle.svelte';
	import MultiSelect from '$lib/components/MultiSelect.svelte';
	import type { MultiSelectOption } from '$lib/components/MultiSelect.svelte';
	import Select from '$lib/components/Select.svelte';
	import type { SelectOption } from '$lib/components/Select.svelte';
	import Loading from '$lib/components/Loading.svelte';

	type TrendPoint = {
		date: string;
		critical: number;
		high: number;
		medium: number;
		low: number;
	};

	type Summary = {
		total_vulns: number;
		total_critical: number;
		total_high: number;
		total_medium: number;
		total_low: number;
		total_unknown: number;
		scanned_sboms: number;
		last_scanned_at: string | null;
	};

	type RepoRow = {
		repo_id: string;
		repo_slug: string;
		critical_count: number;
		high_count: number;
		medium_count: number;
		low_count: number;
		unknown_count: number;
		last_scanned_at: string | null;
	};

	type ImageRow = {
		registry: string;
		image: string;
		digest: string;
		digest_id?: string;
		tags: string;
		cluster_count: number;
		namespace_count: number;
		container_count: number;
		last_seen: string;
		vuln_critical: number;
		vuln_high: number;
		vuln_medium: number;
		vuln_low: number;
		vuln_unknown: number;
	};

	type VulnAsset = {
		type: 'repo' | 'image';
		id: string;
		slug: string;
	};

	type VulnGroup = {
		vuln_id: string;
		severity: string;
		pkg_name: string;
		installed_version: string;
		fixed_version: string;
		title: string;
		description: string;
		sources: string[];
		assets: VulnAsset[];
		// Aliases come from the backend's vuln_metadata lookup — cross-
		// references across CVE / GHSA / BIT / OSV prefixes for the
		// same advisory. Omitted when no enrichment row exists.
		aliases?: string[];
		repo_count: number;
		image_count: number;
	};

	type VulnListResponse = {
		total: number;
		limit: number;
		offset: number;
		items: VulnGroup[];
	};

	const VULN_PAGE_SIZE = 100;

	let summary: Summary | null = null;
	let repos: RepoRow[] = [];
	let trend: TrendPoint[] = [];
	let vulnTotal = 0;
	let vulnPages = new Map<number, VulnGroup[]>();
	let vulnInflight = new Set<number>();
	let vulnFilterVersion = 0;
	let vulnLoaded = false;
	let vulnError = '';
	let images: ImageRow[] = [];
	let hideClean = true;
	let loading = true;
	let vulnsLoading = false;
	let imagesLoading = false;
	let error = '';
	let activeTab = 'vulnerabilities';
	let imageDrawerOpen = false;
	let imageDrawerId = '';

	// Pending scroll restores — each is set when the snapshot restore
	// captures a non-zero scrollTop for the corresponding tab, then
	// applied by a reactive block once the tab's scroll element is
	// bound AND its data has landed (setting scrollTop on an empty
	// container would stick at 0). Cleared on application so they
	// fire exactly once per snapshot restore.
	let restoreRepoScroll: number | null = null;
	let restoreImageScroll: number | null = null;
	let restoreVulnScroll: number | null = null;

	// SvelteKit snapshot: preserves filter + search + tab + scroll
	// state when the user navigates away (e.g. into a CVE detail
	// page) and back via history.back(). The inner-div scrolls on
	// each tab aren't covered by SvelteKit's window-level scroll
	// restoration, so we capture / restore them explicitly.
	//
	// vulnPages is deliberately not captured: the page contents
	// depend on server-side scan state that may have changed during
	// the user's side-trip; dropping the cached pages forces a fresh
	// fetch with the restored filters applied, which is the right
	// freshness trade. The virt slice reactively re-triggers page
	// fetches for whatever visible range the restored scrollTop
	// implies.
	export const snapshot = {
		capture: () => ({
			activeTab,
			vulnSearch,
			vulnSelectedSeverities,
			vulnSelectedSources,
			vulnSelectedYears,
			vulnFixAvailable,
			vulnKEVOnly,
			vulnEPSSMin,
			imageSearch,
			imageSelectedRegistries,
			imageSelectedSeverities,
			hideClean,
			scroll: {
				repo: repoScrollTop,
				image: imageScrollTop,
				vuln: vulnScrollTop,
			},
		}),
		restore: (value: {
			activeTab?: string;
			vulnSearch?: string;
			vulnSelectedSeverities?: string[];
			vulnSelectedSources?: string[];
			vulnSelectedYears?: string[];
			vulnFixAvailable?: boolean;
			vulnKEVOnly?: boolean;
			vulnEPSSMin?: string;
			imageSearch?: string;
			imageSelectedRegistries?: string[];
			imageSelectedSeverities?: string[];
			hideClean?: boolean;
			scroll?: { repo?: number; image?: number; vuln?: number };
		}) => {
			if (value.activeTab !== undefined) activeTab = value.activeTab;
			if (value.vulnSearch !== undefined) vulnSearch = value.vulnSearch;
			if (value.vulnSelectedSeverities) vulnSelectedSeverities = value.vulnSelectedSeverities;
			if (value.vulnSelectedSources) vulnSelectedSources = value.vulnSelectedSources;
			if (value.vulnSelectedYears) vulnSelectedYears = value.vulnSelectedYears;
			if (value.vulnFixAvailable !== undefined) vulnFixAvailable = value.vulnFixAvailable;
			if (value.vulnKEVOnly !== undefined) vulnKEVOnly = value.vulnKEVOnly;
			if (value.vulnEPSSMin !== undefined) vulnEPSSMin = value.vulnEPSSMin;
			if (value.imageSearch !== undefined) imageSearch = value.imageSearch;
			if (value.imageSelectedRegistries) imageSelectedRegistries = value.imageSelectedRegistries;
			if (value.imageSelectedSeverities) imageSelectedSeverities = value.imageSelectedSeverities;
			if (value.hideClean !== undefined) hideClean = value.hideClean;
			if (value.scroll) {
				if (value.scroll.repo) restoreRepoScroll = value.scroll.repo;
				if (value.scroll.image) restoreImageScroll = value.scroll.image;
				if (value.scroll.vuln) restoreVulnScroll = value.scroll.vuln;
			}
		},
	};

	// --- Virtual scroll helpers for tables ---
	// ROW_HEIGHT = flat single-line rows (repos, images). VULN_ROW_HEIGHT
	// is taller because those rows stack title+pkg+fix inside one tr.
	// OVERSCAN keeps a handful of rows rendered above/below the viewport
	// so fast scrolls don't flash empty rows while the slice updates.
	const ROW_HEIGHT = 48;
	const VULN_ROW_HEIGHT = 96;
	const OVERSCAN = 10;

	type Virt = { start: number; end: number; topPad: number; bottomPad: number };
	function virtSlice(total: number, rowHeight: number, scrollTop: number, viewH: number): Virt {
		const start = Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN);
		const end = Math.min(total, Math.ceil((scrollTop + viewH) / rowHeight) + OVERSCAN);
		return {
			start,
			end,
			topPad: start * rowHeight,
			bottomPad: Math.max(0, (total - end) * rowHeight),
		};
	}

	let repoScrollEl: HTMLDivElement | undefined;
	let repoScrollTop = 0;
	let repoViewH = 600;
	let imageScrollEl: HTMLDivElement | undefined;
	let imageScrollTop = 0;
	let imageViewH = 600;
	let vulnScrollEl: HTMLDivElement | undefined;
	let vulnScrollTop = 0;
	let vulnViewH = 600;

	// Per-tab filter state. Each tab owns its own filter-open + per-field
	// selections so switching tabs doesn't clobber the other's filters.
	let repoFilterOpen = false;
	let repoSearch = '';
	let repoSelectedSeverities: string[] = [];
	let repoHideClean = false;

	let imageFilterOpen = false;
	let imageSearch = '';
	let imageSelectedRegistries: string[] = [];
	let imageSelectedSeverities: string[] = [];

	let vulnFilterOpen = false;
	let vulnSearch = '';
	let vulnSelectedSeverities: string[] = [];
	let vulnSelectedSources: string[] = [];
	let vulnSelectedYears: string[] = [];
	let vulnFixAvailable = false;
	// Known-exploited filter: shows only advisories listed in the CISA
	// KEV catalog (i.e., observed in real-world attacks). Backed by the
	// kev=1 query param on /api/vuln/list.
	let vulnKEVOnly = false;
	// EPSS minimum score: empty string = "Any", otherwise the floor
	// passed to /api/vuln/list as epss_min. EPSS is FIRST.org's daily
	// 0–1 prediction of exploitation in the next 30 days.
	let vulnEPSSMin = '';

	const vulnEPSSOptions: SelectOption[] = [
		{ value: '', label: 'Any' },
		{ value: '0.01', label: '≥ 1%' },
		{ value: '0.1', label: '≥ 10%' },
		{ value: '0.5', label: '≥ 50%' },
		{ value: '0.9', label: '≥ 90%' },
	];

	const severityFilterOptions: MultiSelectOption[] = [
		{ value: 'CRITICAL', label: 'Critical' },
		{ value: 'HIGH', label: 'High' },
		{ value: 'MEDIUM', label: 'Medium' },
		{ value: 'LOW', label: 'Low' },
		{ value: 'UNKNOWN', label: 'Unknown' },
	];

	const includesCI = (haystack: string | undefined | null, needle: string) =>
		(haystack ?? '').toLowerCase().includes(needle.toLowerCase());

	const severityOrder: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };

	// Paginated fetch: each page = VULN_PAGE_SIZE groups from the server.
	// filterVersion increments on any filter change so stale responses
	// (arriving after the user typed something new) are discarded.
	async function fetchVulnPage(page: number) {
		if (page < 0) return;
		if (vulnPages.has(page) || vulnInflight.has(page)) return;
		vulnInflight.add(page);
		if (page === 0) {
			vulnsLoading = true;
			vulnError = '';
		}
		const filterAtRequest = vulnFilterVersion;
		const params = new URLSearchParams({
			limit: String(VULN_PAGE_SIZE),
			offset: String(page * VULN_PAGE_SIZE)
		});
		if (vulnSelectedSeverities.length) params.set('severity', vulnSelectedSeverities.join(','));
		if (vulnSelectedSources.length) params.set('source', vulnSelectedSources.join(','));
		if (vulnSelectedYears.length) params.set('year', vulnSelectedYears.join(','));
		if (vulnFixAvailable) params.set('fix', '1');
		if (vulnKEVOnly) params.set('kev', '1');
		if (vulnEPSSMin) params.set('epss_min', vulnEPSSMin);
		const q = vulnSearch.trim();
		if (q) params.set('q', q);
		try {
			const res = await fetch(`/api/vuln/list?${params}`, { credentials: 'include' });
			if (filterAtRequest !== vulnFilterVersion) return;
			if (!res.ok) {
				if (page === 0) {
					vulnError = res.status === 504 || res.status === 502
						? 'Upstream request timed out — narrow your filters or try again.'
						: `Failed to load vulnerabilities (HTTP ${res.status}).`;
				}
				return;
			}
			const data = (await res.json()) as VulnListResponse;
			vulnTotal = data.total ?? 0;
			const next = new Map(vulnPages);
			next.set(page, data.items ?? []);
			vulnPages = next;
			vulnLoaded = true;
		} catch {
			if (filterAtRequest === vulnFilterVersion && page === 0) {
				vulnError = 'Network error — try again.';
			}
		} finally {
			vulnInflight.delete(page);
			if (page === 0) vulnsLoading = false;
		}
	}

	function resetVulnPages() {
		vulnFilterVersion++;
		vulnPages = new Map();
		vulnInflight = new Set();
		vulnTotal = 0;
		vulnLoaded = false;
		vulnError = '';
		if (vulnScrollEl) vulnScrollEl.scrollTop = 0;
		vulnScrollTop = 0;
		void fetchVulnPage(0);
	}

	// Debounced search: typing shouldn't fire a request per keystroke.
	let vulnSearchTimer: ReturnType<typeof setTimeout> | null = null;
	let vulnSearchDebounced = '';
	$: {
		if (vulnSearchTimer) clearTimeout(vulnSearchTimer);
		const v = vulnSearch;
		vulnSearchTimer = setTimeout(() => { vulnSearchDebounced = v; }, 250);
	}

	// Primary link: internal detail page so operators land on affected
	// repos / clusters / contributors, not a bare advisory page. The
	// route lives at /vuln/[id] (shorter than /vulnerabilities/
	// for the manual-typing case).
	const vulnDetailHref = (id: string) => `/vuln/${encodeURIComponent(id)}`;
	// Secondary external link kept as a small icon next to the ID.
	const vulnUpstreamUrl = (id: string) => {
		if (id.startsWith('CVE-')) return `https://www.cve.org/CVERecord?id=${id}`;
		if (id.startsWith('GHSA-')) return `https://github.com/advisories/${id}`;
		return `https://osv.dev/vulnerability/${id}`;
	};

	const fmt = (n: number) => n.toLocaleString('en-US').replace(/,/g, ' ');

	const fmtRelative = (iso: string | null) => {
		if (!iso) return '—';
		const diff = Date.now() - new Date(iso).getTime();
		const days = Math.floor(diff / 86_400_000);
		if (days === 0) return 'today';
		if (days === 1) return 'yesterday';
		if (days < 30) return `${days}d ago`;
		return `${Math.floor(days / 30)}mo ago`;
	};

	const openRepo = (repoId: string) => {
		if (!repoId) return;
		goto(`/providers/repo?repo_id=${encodeURIComponent(repoId)}`);
	};

	const severityClass = (s: string) => {
		switch (s?.toUpperCase()) {
			case 'CRITICAL': return 'border-red-500/30 bg-red-500/5';
			case 'HIGH':     return 'border-orange-500/30 bg-orange-500/5';
			case 'MEDIUM':   return 'border-yellow-500/30 bg-yellow-500/5';
			case 'LOW':      return 'border-[var(--border-color)]/50 bg-transparent';
			default:         return 'border-[var(--border-color)]/40 bg-transparent';
		}
	};

	const severityIcon = (s: string) => {
		switch (s?.toUpperCase()) {
			case 'CRITICAL': return { color: 'text-red-400' };
			case 'HIGH':     return { color: 'text-orange-400' };
			case 'MEDIUM':   return { color: 'text-yellow-400' };
			default:         return { color: 'text-[var(--text-muted)]' };
		}
	};

	const loadImages = async () => {
		if (images.length > 0) return;
		imagesLoading = true;
		try {
			const res = await fetch('/api/clusters/images/detail', { credentials: 'include' });
			if (res.ok) images = (await res.json()) ?? [];
		} catch {
			// ignore
		} finally {
			imagesLoading = false;
		}
	};

	$: if (activeTab === 'images') loadImages();

	$: vulnFiltersKey = JSON.stringify([
		vulnSearchDebounced,
		vulnSelectedSeverities.slice().sort(),
		vulnSelectedSources.slice().sort(),
		vulnSelectedYears.slice().sort(),
		vulnFixAvailable,
		vulnKEVOnly,
		vulnEPSSMin
	]);
	// Combined initial-fetch + filter-change watcher. Splitting these into
	// two reactive blocks caused a double request on mount: the first
	// would mark page 0 in-flight, then the filter-key watcher would see
	// vulnFiltersKey transition from its '' seed to the computed JSON,
	// observe the in-flight flag, and call resetVulnPages — which clears
	// the in-flight set and refetches.
	let prevVulnFiltersKey = '';
	$: if (activeTab === 'vulnerabilities') {
		if (vulnFiltersKey !== prevVulnFiltersKey) {
			prevVulnFiltersKey = vulnFiltersKey;
			if (vulnLoaded || vulnInflight.has(0)) {
				resetVulnPages();
			} else if (!vulnError) {
				void fetchVulnPage(0);
			}
		} else if (!vulnLoaded && !vulnInflight.has(0) && !vulnError) {
			void fetchVulnPage(0);
		}
	}

	// Images filtered + sorted by severity weight (critical > high > medium > low).
	$: filteredImages = (() => {
		const w = (img: ImageRow) =>
			img.vuln_critical * 1e9 + img.vuln_high * 1e6 + img.vuln_medium * 1e3 + img.vuln_low;
		let list = hideClean ? images.filter((i) => w(i) > 0) : images.slice();
		const q = imageSearch.trim();
		if (q) list = list.filter((i) => includesCI(i.registry, q) || includesCI(i.image, q) || includesCI(i.digest, q) || includesCI(i.tags, q));
		if (imageSelectedRegistries.length > 0) {
			const set = new Set(imageSelectedRegistries);
			list = list.filter((i) => set.has(i.registry || '—'));
		}
		if (imageSelectedSeverities.length > 0) {
			const sevs = new Set(imageSelectedSeverities);
			list = list.filter((i) =>
				(sevs.has('CRITICAL') && i.vuln_critical > 0) ||
				(sevs.has('HIGH') && i.vuln_high > 0) ||
				(sevs.has('MEDIUM') && i.vuln_medium > 0) ||
				(sevs.has('LOW') && i.vuln_low > 0) ||
				(sevs.has('UNKNOWN') && i.vuln_unknown > 0)
			);
		}
		return list.sort((a, b) => w(b) - w(a));
	})();

	// Repo table has an inline .filter(...) in the template; hoist it
	// so the virt slice math uses the same list the UI renders.
	$: filteredRepos = (() => {
		let list = repos.filter((r) => r.repo_slug !== r.repo_id && r.repo_slug);
		const q = repoSearch.trim();
		if (q) list = list.filter((r) => includesCI(r.repo_slug, q));
		if (repoHideClean) {
			list = list.filter((r) =>
				r.critical_count + r.high_count + r.medium_count + r.low_count + r.unknown_count > 0
			);
		}
		if (repoSelectedSeverities.length > 0) {
			const sevs = new Set(repoSelectedSeverities);
			list = list.filter((r) =>
				(sevs.has('CRITICAL') && r.critical_count > 0) ||
				(sevs.has('HIGH') && r.high_count > 0) ||
				(sevs.has('MEDIUM') && r.medium_count > 0) ||
				(sevs.has('LOW') && r.low_count > 0) ||
				(sevs.has('UNKNOWN') && r.unknown_count > 0)
			);
		}
		return list;
	})();

	// Server-side filtering now — filteredVulns no longer exists. A pure
	// lookup (no side effects): fetches are kicked off by the reactive
	// block watching vulnVirt so a keyed each-block doesn't silently skip
	// re-running when vulnPages updates.
	function getVulnAt(idx: number, pages: Map<number, VulnGroup[]>): VulnGroup | undefined {
		const page = Math.floor(idx / VULN_PAGE_SIZE);
		const within = idx % VULN_PAGE_SIZE;
		return pages.get(page)?.[within];
	}

	// Dynamic MultiSelect options derived from the current data set.
	$: imageRegistryFilterOptions = [...new Set(images.map((i) => i.registry || '—'))]
		.sort()
		.map((r) => ({ value: r, label: r } as MultiSelectOption));

	// Source + year filter options come from /api/vuln/facets so we
	// only ever show values that actually appear in the data — no
	// stale "trivy" option after the sbom-scanner migrated to grype,
	// no 2015-2025 dropdown when the oldest row is from 2019.
	let vulnSourceFilterOptions: MultiSelectOption[] = [];
	let vulnYearFilterOptions: MultiSelectOption[] = [];
	let facetsLoaded = false;

	async function loadVulnFacets() {
		if (facetsLoaded) return;
		try {
			const res = await fetch('/api/vuln/facets', { credentials: 'include' });
			if (!res.ok) return;
			const data = (await res.json()) as { sources: string[]; years: string[] };
			vulnSourceFilterOptions = (data.sources ?? []).map((s) => ({ value: s, label: s }));
			vulnYearFilterOptions = (data.years ?? []).map((y) => ({ value: y, label: y }));
			facetsLoaded = true;
		} catch {
			// swallow — dropdowns stay empty; user can retry by toggling tab
		}
	}

	// Badge counts per tab.
	$: repoActiveFilterCount =
		(repoSearch.trim() ? 1 : 0) +
		(repoHideClean ? 1 : 0) +
		(repoSelectedSeverities.length > 0 ? 1 : 0);

	$: imageActiveFilterCount =
		(imageSearch.trim() ? 1 : 0) +
		(hideClean ? 1 : 0) +
		(imageSelectedRegistries.length > 0 ? 1 : 0) +
		(imageSelectedSeverities.length > 0 ? 1 : 0);

	$: vulnActiveFilterCount =
		(vulnSearch.trim() ? 1 : 0) +
		(vulnSelectedSeverities.length > 0 ? 1 : 0) +
		(vulnSelectedSources.length > 0 ? 1 : 0) +
		(vulnSelectedYears.length > 0 ? 1 : 0) +
		(vulnFixAvailable ? 1 : 0) +
		(vulnKEVOnly ? 1 : 0) +
		(vulnEPSSMin ? 1 : 0);

	function clearRepoFilters() {
		repoSearch = ''; repoSelectedSeverities = []; repoHideClean = false;
	}
	function clearImageFilters() {
		imageSearch = ''; imageSelectedRegistries = []; imageSelectedSeverities = []; hideClean = true;
	}
	function clearVulnFilters() {
		vulnSearch = ''; vulnSelectedSeverities = []; vulnSelectedSources = [];
		vulnSelectedYears = []; vulnFixAvailable = false; vulnKEVOnly = false;
		vulnEPSSMin = '';
	}

	$: repoVirt = virtSlice(filteredRepos.length, ROW_HEIGHT, repoScrollTop, repoViewH);
	$: imageVirt = virtSlice(filteredImages.length, ROW_HEIGHT, imageScrollTop, imageViewH);
	$: vulnVirt = virtSlice(vulnTotal, VULN_ROW_HEIGHT, vulnScrollTop, vulnViewH);

	// Apply pending scroll restores once the target tab's DOM has
	// mounted (scrollEl bound) and its data has landed (rows/items
	// count > 0). The snapshot restore runs before either of those
	// conditions is true, so we can't just scroll in restore(); we
	// wait here for the reactive chain to catch up.
	//
	// Setting scrollTop on the element triggers the onscroll handler
	// which writes back into xxxScrollTop — hence we also update the
	// state directly so the virt slice reacts immediately rather than
	// on the next browser paint.
	$: if (restoreRepoScroll !== null && repoScrollEl && filteredRepos.length > 0) {
		repoScrollEl.scrollTop = restoreRepoScroll;
		repoScrollTop = restoreRepoScroll;
		restoreRepoScroll = null;
	}
	$: if (restoreImageScroll !== null && imageScrollEl && filteredImages.length > 0) {
		imageScrollEl.scrollTop = restoreImageScroll;
		imageScrollTop = restoreImageScroll;
		restoreImageScroll = null;
	}
	$: if (restoreVulnScroll !== null && vulnScrollEl && vulnTotal > 0) {
		vulnScrollEl.scrollTop = restoreVulnScroll;
		vulnScrollTop = restoreVulnScroll;
		restoreVulnScroll = null;
	}

	// Whenever the visible window shifts, kick off fetches for any
	// page that isn't yet cached. The virt slice overscan already
	// lookaheads ~10 rows above/below, but page boundaries mean we
	// may also need to fetch the next page as soon as any of its rows
	// enter the window.
	$: if (vulnTotal > 0 && vulnVirt.end > vulnVirt.start) {
		const startPage = Math.floor(vulnVirt.start / VULN_PAGE_SIZE);
		const endPage = Math.floor((vulnVirt.end - 1) / VULN_PAGE_SIZE);
		for (let p = startPage; p <= endPage; p++) {
			if (!vulnPages.has(p) && !vulnInflight.has(p)) void fetchVulnPage(p);
		}
	}

	// Pre-resolve the visible slice reactively against vulnPages so that
	// rows re-render when a page fetch lands. A {@const getVulnAt(idx)}
	// inside a keyed {#each ... (idx)} block does NOT re-evaluate on
	// existing rows when only vulnPages changes (Svelte reconciles same
	// keys as unchanged), so fast scrolls left rows stuck on "loading…"
	// even after the fetch resolved.
	$: vulnRows = (() => {
		const rows: Array<{ idx: number; group: VulnGroup | undefined }> = [];
		for (let i = vulnVirt.start; i < vulnVirt.end; i++) {
			rows.push({ idx: i, group: getVulnAt(i, vulnPages) });
		}
		return rows;
	})();

	const shortDigest = (d: string) => (d && d.length > 14 ? d.slice(0, 14) + '…' : d ?? '');
	const parseTags = (t: string) => (t ? t.split(',').map((x) => x.trim()).filter(Boolean) : []);

	const openImageDrawer = (digestId: string | undefined) => {
		if (!digestId) return;
		if (imageDrawerOpen && imageDrawerId === digestId) {
			imageDrawerOpen = false;
			imageDrawerId = '';
		} else {
			imageDrawerId = digestId;
			imageDrawerOpen = true;
		}
	};

	// Toggle a value in a string array — used by the severity pill
	// buttons to flip selection state. Returns a new array so Svelte's
	// reactivity picks it up.
	function togglePill(list: string[], value: string): string[] {
		const next = list.filter((v) => v !== value);
		return next.length === list.length ? [...list, value] : next;
	}

	onMount(async () => {
		try {
			const [sumRes, reposRes, trendRes] = await Promise.all([
				fetch('/api/vuln/summary', { credentials: 'include' }),
				fetch('/api/vuln/repos', { credentials: 'include' }),
				fetch('/api/vuln/trend?days=30', { credentials: 'include' })
			]);

			if (!sumRes.ok || !reposRes.ok || !trendRes.ok) {
				error = 'Failed to load vulnerability data';
				return;
			}

			summary = await sumRes.json();
			repos = await reposRes.json();
			trend = await trendRes.json();
		} catch (e) {
			error = 'Failed to fetch data';
		} finally {
			loading = false;
		}

		// Facets are cheap + independent of the three main loads, so fire
		// them alongside rather than blocking the dashboard render.
		void loadVulnFacets();
	});
</script>

<svelte:head>
	<title>Vulnerabilities — Spam Monitor</title>
</svelte:head>

<div class="space-y-4">
	<!-- Stats + charts panel -->
	<article class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<div class="flex items-center gap-3">
				<ShieldX class="h-10 w-10 flex-shrink-0 text-[var(--accent)]" />
				<div>
					<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Vulnerabilities</h1>
					<p class="text-sm text-[var(--text-tertiary)]">Scan results across all SBOMs.</p>
				</div>
			</div>
		</header>

		{#if loading}
			<div class="flex items-center justify-center py-20">
				<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
			</div>
		{:else if error}
			<div class="rounded-2xl border border-[var(--red)]/30 bg-[var(--red)]/10 px-4 py-3 text-sm text-[var(--red)]">{error}</div>
		{:else}
			<!-- Metric cards -->
			<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Total</h3>
					<p class="text-3xl font-bold text-[var(--text-bright)]">{fmt(summary?.total_vulns ?? 0)}</p>
					<p class="text-xs text-[var(--text-muted)]">across {summary?.scanned_sboms ?? 0} SBOMs</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Critical</h3>
					<p class="text-3xl font-bold text-red-500">{fmt(summary?.total_critical ?? 0)}</p>
					<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><ShieldX class="h-3 w-3 text-red-500" /> Immediate action required</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">High</h3>
					<p class="text-3xl font-bold text-orange-500">{fmt(summary?.total_high ?? 0)}</p>
					<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><ShieldAlert class="h-3 w-3 text-orange-500" /> High severity</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Medium</h3>
					<p class="text-3xl font-bold text-yellow-500">{fmt(summary?.total_medium ?? 0)}</p>
					<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><Shield class="h-3 w-3 text-yellow-500" /> Needs scheduled remediation</p>
				</div>
				<div class="metric-card space-y-1 rounded-2xl p-4">
					<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Low + Unknown</h3>
					<p class="text-3xl font-bold text-[var(--text-secondary)]">{fmt((summary?.total_low ?? 0) + (summary?.total_unknown ?? 0))}</p>
					<p class="flex items-center gap-1 text-xs text-[var(--text-muted)]"><Shield class="h-3 w-3 text-[var(--text-secondary)]" /> Lower priority or unclassified</p>
				</div>
			</div>

			<!-- Charts -->
			<div class="grid grid-cols-1 gap-6 lg:grid-cols-3">
				<div class="metric-card rounded-2xl p-5">
					{#if summary}
						<DonutChart
							title="Severity distribution"
							total={summary.total_vulns}
							segments={[
								{ label: 'Critical', value: summary.total_critical, color: 'var(--red)' },
								{ label: 'High', value: summary.total_high, color: 'var(--orange)' },
								{ label: 'Medium', value: summary.total_medium, color: 'var(--yellow)' },
								{ label: 'Low', value: summary.total_low, color: 'var(--blue)' },
								{ label: 'Unknown', value: summary.total_unknown, color: 'var(--gray)' }
							]}
						/>
					{/if}
				</div>
				<div class="metric-card rounded-2xl p-5 lg:col-span-2">
					<LineChart title="30-day trend" data={trend} />
				</div>
			</div>

			<!-- Tab selector -->
			<div class="pt-2">
				<TabSelector
					options={[
						{ value: 'vulnerabilities', label: 'Vulnerabilities' },
						{ value: 'repositories', label: 'Repositories' },
						{ value: 'images', label: 'Images' }
					]}
					bind:value={activeTab}
				/>
			</div>
		{/if}
	</article>

	<!-- Table panel -->
	{#if !loading && !error}
		<section class="panel-surface flex flex-col gap-6 px-6 py-8 sm:px-10 sm:py-10 h-[calc(100vh-7rem)]">
			<header class="flex items-start justify-between gap-4">
				<div>
					<h2 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Findings</h2>
					<p class="text-sm text-[var(--text-tertiary)]">
						{#if activeTab === 'vulnerabilities' && vulnLoaded && vulnTotal > 0}
							{fmt(vulnTotal)} unique {vulnTotal === 1 ? 'vulnerability' : 'vulnerabilities'}
						{:else}
							Vulnerability scan results from the latest scans.
						{/if}
					</p>
				</div>
				{#if activeTab === 'repositories' && repos.length > 0}
					<button
						type="button"
						class="host-filter-toggle"
						class:active={repoFilterOpen}
						onclick={() => (repoFilterOpen = !repoFilterOpen)}
						aria-expanded={repoFilterOpen}
						aria-label="Toggle filters"
					>
						<SlidersHorizontal size={14} />
						<span>Filters</span>
						{#if repoActiveFilterCount > 0}<span class="host-filter-badge">{repoActiveFilterCount}</span>{/if}
					</button>
				{:else if activeTab === 'images' && images.length > 0}
					<button
						type="button"
						class="host-filter-toggle"
						class:active={imageFilterOpen}
						onclick={() => (imageFilterOpen = !imageFilterOpen)}
						aria-expanded={imageFilterOpen}
						aria-label="Toggle filters"
					>
						<SlidersHorizontal size={14} />
						<span>Filters</span>
						{#if imageActiveFilterCount > 0}<span class="host-filter-badge">{imageActiveFilterCount}</span>{/if}
					</button>
				{:else if activeTab === 'vulnerabilities' && (vulnTotal > 0 || vulnActiveFilterCount > 0)}
					<button
						type="button"
						class="host-filter-toggle"
						class:active={vulnFilterOpen}
						onclick={() => (vulnFilterOpen = !vulnFilterOpen)}
						aria-expanded={vulnFilterOpen}
						aria-label="Toggle filters"
					>
						<SlidersHorizontal size={14} />
						<span>Filters</span>
						{#if vulnActiveFilterCount > 0}<span class="host-filter-badge">{vulnActiveFilterCount}</span>{/if}
					</button>
				{/if}
			</header>

			{#if activeTab === 'repositories' && repoFilterOpen}
				<div transition:slide={{ duration: 220, easing: cubicOut }} class="pb-2">
					<div class="flex flex-wrap items-start gap-6">
						<div class="flex flex-col gap-1">
							<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Search</span>
							<div class="relative flex items-center">
								<Search size={13} class="pointer-events-none absolute left-2.5 text-[var(--text-muted)]" />
								<input type="text" class="host-search-input" placeholder="Repo slug…" bind:value={repoSearch} />
							</div>
						</div>
						<div class="flex flex-col gap-1">
							<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Has severity</span>
							<div class="flex flex-wrap items-center gap-2 h-[28px]">
								{#each severityFilterOptions as opt (opt.value)}
									<button
										type="button"
										class={`btn btn-sm ${repoSelectedSeverities.includes(opt.value) ? 'btn-secondary filter-active' : 'btn-ghost'}`}
										onclick={() => { repoSelectedSeverities = togglePill(repoSelectedSeverities, opt.value); }}
									>
										{opt.label}
									</button>
								{/each}
							</div>
						</div>
						<div class="flex flex-col gap-1">
							<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Clean repos</span>
							<div class="flex items-center h-[28px]">
								<Toggle bind:checked={repoHideClean} label="Only with findings" />
							</div>
						</div>
						{#if repoActiveFilterCount > 0}
							<div class="flex items-center gap-3 ml-auto" style="padding-top: calc(0.65rem * 1.2 + 0.25rem);">
								<button type="button" class="host-clear-filters" onclick={clearRepoFilters}>Clear all</button>
							</div>
						{/if}
					</div>
				</div>
			{:else if activeTab === 'images' && imageFilterOpen}
				<div transition:slide={{ duration: 220, easing: cubicOut }} class="pb-2">
					<div class="flex flex-wrap items-start gap-6">
						<div class="flex flex-col gap-1">
							<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Search</span>
							<div class="relative flex items-center">
								<Search size={13} class="pointer-events-none absolute left-2.5 text-[var(--text-muted)]" />
								<input type="text" class="host-search-input" placeholder="Registry, image, digest, tag…" bind:value={imageSearch} />
							</div>
						</div>
						<div class="flex flex-col gap-1">
							<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Registry</span>
							<MultiSelect bind:selected={imageSelectedRegistries} options={imageRegistryFilterOptions} placeholder="All registries" size="sm" />
						</div>
						<div class="flex flex-col gap-1">
							<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Severity</span>
							<div class="flex flex-wrap items-center gap-2 h-[28px]">
								{#each severityFilterOptions as opt (opt.value)}
									<button
										type="button"
										class={`btn btn-sm ${imageSelectedSeverities.includes(opt.value) ? 'btn-secondary filter-active' : 'btn-ghost'}`}
										onclick={() => { imageSelectedSeverities = togglePill(imageSelectedSeverities, opt.value); }}
									>
										{opt.label}
									</button>
								{/each}
							</div>
						</div>
						<div class="flex flex-col gap-1">
							<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Clean images</span>
							<div class="flex items-center h-[28px]">
								<Toggle bind:checked={hideClean} label="Only with vulns" />
							</div>
						</div>
						{#if imageActiveFilterCount > 0}
							<div class="flex items-center gap-3 ml-auto" style="padding-top: calc(0.65rem * 1.2 + 0.25rem);">
								<button type="button" class="host-clear-filters" onclick={clearImageFilters}>Clear all</button>
							</div>
						{/if}
					</div>
				</div>
			{:else if activeTab === 'vulnerabilities' && vulnFilterOpen}
				<div transition:slide={{ duration: 220, easing: cubicOut }} class="pb-2">
					<div class="flex flex-wrap items-start gap-6">
						<div class="flex flex-col gap-1">
							<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Search</span>
							<div class="relative flex items-center">
								<Search size={13} class="pointer-events-none absolute left-2.5 text-[var(--text-muted)]" />
								<input type="text" class="host-search-input host-search-input-compact" placeholder="CVE, package, repo…" bind:value={vulnSearch} />
							</div>
						</div>
						<div class="flex flex-col gap-1">
							<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Severity</span>
							<div class="flex flex-wrap items-center gap-2 h-[28px]">
								{#each severityFilterOptions as opt (opt.value)}
									<button
										type="button"
										class={`btn btn-sm ${vulnSelectedSeverities.includes(opt.value) ? 'btn-secondary filter-active' : 'btn-ghost'}`}
										onclick={() => { vulnSelectedSeverities = togglePill(vulnSelectedSeverities, opt.value); }}
									>
										{opt.label}
									</button>
								{/each}
							</div>
						</div>
						<div class="flex flex-col gap-1">
							<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Source</span>
							<MultiSelect bind:selected={vulnSelectedSources} options={vulnSourceFilterOptions} placeholder="Any" size="sm" />
						</div>
						<div class="flex flex-col gap-1">
							<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">CVE year</span>
							<MultiSelect bind:selected={vulnSelectedYears} options={vulnYearFilterOptions} placeholder="Any" size="sm" />
						</div>
						<div class="flex flex-col gap-1">
							<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Has fix</span>
							<div class="flex items-center h-[28px]">
								<Toggle bind:checked={vulnFixAvailable} label="Fixable only" />
							</div>
						</div>
						<div class="flex flex-col gap-1">
							<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5" title="Listed in CISA's Known Exploited Vulnerabilities catalog — observed in real-world attacks.">Exploitation</span>
							<div class="flex items-center h-[28px]">
								<Toggle bind:checked={vulnKEVOnly} label="Known exploited" />
							</div>
						</div>
						<div class="flex flex-col gap-1">
							<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5" title="EPSS — FIRST.org's daily-scored probability that a CVE will be exploited in the next 30 days.">EPSS ≥</span>
							<div class="flex items-center h-[28px]">
								<Select bind:value={vulnEPSSMin} options={vulnEPSSOptions} size="sm" />
							</div>
						</div>
						{#if vulnActiveFilterCount > 0}
							<div class="flex items-center gap-3 ml-auto" style="padding-top: calc(0.65rem * 1.2 + 0.25rem);">
								<button type="button" class="host-clear-filters" onclick={clearVulnFilters}>Clear all</button>
							</div>
						{/if}
					</div>
				</div>
			{/if}

			{#if activeTab === 'repositories'}
				{#if repos.length === 0}
					<div class="flex flex-1 items-center justify-center">
						<div class="flex flex-col items-center gap-3 text-center">
							<EmptyRepos class="text-[var(--text-muted)]" />
							<p class="text-sm text-[var(--text-muted)]">No security scans executed.</p>
						</div>
					</div>
				{:else}
					<div class="relative flex flex-1 flex-col overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
						<div class="flex-1 overflow-y-auto [overflow-anchor:none]" bind:this={repoScrollEl} onscroll={() => { repoScrollTop = repoScrollEl?.scrollTop ?? 0; repoViewH = repoScrollEl?.clientHeight ?? 600; }}>
							<table class="min-w-full table-fixed divide-y divide-[var(--border-color)]/60 text-sm">
								<thead class="sticky top-0 z-[1] bg-[var(--card-bg)] text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
									<tr>
										<th class="w-[40%] px-5 py-3 text-left">Repository</th>
										<th class="w-[12%] px-5 py-3 text-right" style="color:var(--red)">Critical</th>
										<th class="w-[12%] px-5 py-3 text-right" style="color:var(--orange)">High</th>
										<th class="w-[12%] px-5 py-3 text-right" style="color:var(--yellow)">Medium</th>
										<th class="w-[12%] px-5 py-3 text-right" style="color:var(--blue)">Low</th>
										<th class="w-[12%] px-5 py-3 text-right">Last Scanned</th>
									</tr>
								</thead>
								<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
									{#if repoVirt.topPad > 0}<tr style="height:{repoVirt.topPad}px"><td colspan="6"></td></tr>{/if}
									{#each filteredRepos.slice(repoVirt.start, repoVirt.end) as repo}
										<tr
											class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)]"
											style="height:{ROW_HEIGHT}px"
											onclick={() => openRepo(repo.repo_id)}
										>
											<td class="px-5 py-3">
												<div class="flex items-center gap-2">
													<GitBranch class="h-4 w-4 shrink-0 text-[var(--accent)]" />
													<span class="font-semibold text-[var(--text-bright)]">{repo.repo_slug}</span>
												</div>
											</td>
											<td class="px-5 py-3 text-right tabular-nums">
												{#if repo.critical_count > 0}
													<span class="inline-flex items-center rounded-full bg-red-500/10 px-2.5 py-0.5 text-xs font-semibold tabular-nums text-red-400">{fmt(repo.critical_count)}</span>
												{:else}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right tabular-nums">
												{#if repo.high_count > 0}
													<span class="inline-flex items-center rounded-full bg-orange-500/10 px-2.5 py-0.5 text-xs font-semibold tabular-nums text-orange-400">{fmt(repo.high_count)}</span>
												{:else}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right tabular-nums">
												{#if repo.medium_count > 0}
													<span class="inline-flex items-center rounded-full bg-yellow-500/10 px-2.5 py-0.5 text-xs font-semibold tabular-nums text-yellow-400">{fmt(repo.medium_count)}</span>
												{:else}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right tabular-nums">
												{#if repo.low_count > 0}
													<span class="inline-flex items-center rounded-full bg-blue-500/10 px-2.5 py-0.5 text-xs font-semibold tabular-nums text-blue-400">{fmt(repo.low_count)}</span>
												{:else}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right text-xs text-[var(--text-muted)]" title={repo.last_scanned_at ?? ''}>
												{fmtRelative(repo.last_scanned_at)}
											</td>
										</tr>
									{/each}
									{#if repoVirt.bottomPad > 0}<tr style="height:{repoVirt.bottomPad}px"><td colspan="6"></td></tr>{/if}
								</tbody>
							</table>
						</div>
					</div>
				{/if}

			{:else if activeTab === 'images'}
				{#if imagesLoading}
					<div class="flex flex-1 items-center justify-center">
						<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
					</div>
				{:else if filteredImages.length === 0}
					<div class="flex flex-1 items-center justify-center">
						<div class="flex flex-col items-center gap-3 text-center">
							<Container class="h-10 w-10 text-[var(--text-muted)]" />
							<p class="text-sm text-[var(--text-muted)]">{hideClean ? 'No images with vulnerabilities.' : 'No images.'}</p>
							{#if hideClean && images.length > 0}
								<button type="button" class="text-xs text-[var(--accent)] hover:underline" onclick={() => (hideClean = false)}>Show clean images</button>
							{/if}
						</div>
					</div>
				{:else}
					<div class="relative flex flex-1 flex-col overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
						<div class="flex-1 overflow-y-auto [overflow-anchor:none]" bind:this={imageScrollEl} onscroll={() => { imageScrollTop = imageScrollEl?.scrollTop ?? 0; imageViewH = imageScrollEl?.clientHeight ?? 600; }}>
							<table class="min-w-full table-fixed divide-y divide-[var(--border-color)]/60 text-sm">
								<thead class="sticky top-0 z-[1] bg-[var(--card-bg)] text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
									<tr>
										<th class="w-[14%] px-5 py-3 text-left">Registry</th>
										<th class="w-[32%] px-5 py-3 text-left">Image</th>
										<th class="w-[14%] px-5 py-3 text-left">Digest</th>
										<th class="w-[7%] px-5 py-3 text-right" style="color:var(--red)">Critical</th>
										<th class="w-[7%] px-5 py-3 text-right" style="color:var(--orange)">High</th>
										<th class="w-[7%] px-5 py-3 text-right" style="color:var(--yellow)">Medium</th>
										<th class="w-[7%] px-5 py-3 text-right" style="color:var(--blue)">Low</th>
										<th class="w-[12%] px-5 py-3 text-right">Last seen</th>
									</tr>
								</thead>
								<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
									{#if imageVirt.topPad > 0}<tr style="height:{imageVirt.topPad}px"><td colspan="8"></td></tr>{/if}
									{#each filteredImages.slice(imageVirt.start, imageVirt.end) as img}
										<tr
											class="transition hover:bg-[var(--hover-bg-subtle)] {img.digest_id ? 'cursor-pointer' : ''} {imageDrawerOpen && imageDrawerId === img.digest_id ? 'bg-[var(--hover-bg-subtle)]' : ''}"
											style="height:{ROW_HEIGHT}px"
											onclick={() => openImageDrawer(img.digest_id)}
										>
											<td class="truncate px-5 py-3 text-xs text-[var(--text-tertiary)]" title={img.registry}>{img.registry}</td>
											<td class="truncate px-5 py-3 font-semibold text-[var(--text-bright)]" title={img.image}>{img.image}</td>
											<td class="px-5 py-3">
												{#if img.digest}
													<code class="rounded bg-[var(--hover-bg)] px-1.5 py-0.5 text-xs text-[var(--text-secondary)]">{shortDigest(img.digest)}</code>
												{:else}
													<span class="text-xs text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right tabular-nums">
												{#if img.vuln_critical > 0}
													<span class="inline-flex items-center rounded-full bg-red-500/10 px-2.5 py-0.5 text-xs font-semibold text-red-400">{fmt(img.vuln_critical)}</span>
												{:else}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right tabular-nums">
												{#if img.vuln_high > 0}
													<span class="inline-flex items-center rounded-full bg-orange-500/10 px-2.5 py-0.5 text-xs font-semibold text-orange-400">{fmt(img.vuln_high)}</span>
												{:else}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right tabular-nums">
												{#if img.vuln_medium > 0}
													<span class="inline-flex items-center rounded-full bg-yellow-500/10 px-2.5 py-0.5 text-xs font-semibold text-yellow-400">{fmt(img.vuln_medium)}</span>
												{:else}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right tabular-nums">
												{#if img.vuln_low > 0}
													<span class="inline-flex items-center rounded-full bg-blue-500/10 px-2.5 py-0.5 text-xs font-semibold text-blue-400">{fmt(img.vuln_low)}</span>
												{:else}
													<span class="text-[var(--text-muted)]">—</span>
												{/if}
											</td>
											<td class="px-5 py-3 text-right text-xs text-[var(--text-muted)]" title={img.last_seen}>
												{fmtRelative(img.last_seen)}
											</td>
										</tr>
									{/each}
									{#if imageVirt.bottomPad > 0}<tr style="height:{imageVirt.bottomPad}px"><td colspan="8"></td></tr>{/if}
								</tbody>
							</table>
						</div>
					</div>

					{#if imageDrawerOpen && imageDrawerId}
						<div class="fixed top-2 bottom-2 right-2 z-50 flex w-[620px] flex-col overflow-hidden rounded-[10px] border border-[var(--border-color)] bg-[var(--bg-soft)] shadow-xl">
							<ImageDrawer imageId={imageDrawerId} onClose={() => { imageDrawerOpen = false; imageDrawerId = ''; }} />
						</div>
					{/if}
				{/if}

			{:else if activeTab === 'vulnerabilities'}
				{#if vulnError && !vulnLoaded}
					<div class="flex flex-1 items-center justify-center">
						<div class="flex max-w-sm flex-col items-center gap-3 text-center">
							<ShieldAlert class="h-8 w-8 text-[var(--orange)]" />
							<p class="text-sm text-[var(--text-secondary)]">{vulnError}</p>
							<button
								type="button"
								class="text-xs text-[var(--accent)] hover:underline"
								onclick={() => { vulnError = ''; void fetchVulnPage(0); }}
							>Retry</button>
						</div>
					</div>
				{:else if vulnsLoading && !vulnLoaded}
					<div class="flex flex-1 items-center justify-center">
						<Loading message="Loading vulnerabilities" variant="bar" size="sm" />
					</div>
				{:else if vulnLoaded && vulnTotal === 0}
					<div class="flex flex-1 items-center justify-center">
						<div class="flex flex-col items-center gap-3 text-center">
							<EmptyVulns class="text-[var(--text-muted)]" />
							<p class="text-sm text-[var(--text-muted)]">
								{vulnActiveFilterCount > 0 ? 'No vulnerabilities match the current filters.' : 'No vulnerabilities found.'}
							</p>
							{#if vulnActiveFilterCount > 0}
								<button type="button" class="text-xs text-[var(--accent)] hover:underline" onclick={clearVulnFilters}>Clear filters</button>
							{/if}
						</div>
					</div>
				{:else}
					<div class="relative flex flex-1 flex-col overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
						<div class="flex-1 overflow-y-auto [overflow-anchor:none]" bind:this={vulnScrollEl} onscroll={() => { vulnScrollTop = vulnScrollEl?.scrollTop ?? 0; vulnViewH = vulnScrollEl?.clientHeight ?? 600; }}>
							<table class="min-w-full table-fixed divide-y divide-[var(--border-color)]/60 text-sm">
								<thead class="sticky top-0 z-[1] bg-[var(--card-bg)] text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
									<tr>
										<th class="px-5 py-3 text-left w-[22%]">CVE / ID</th>
										<th class="px-5 py-3 text-left w-[10%]">Severity</th>
										<th class="px-5 py-3 text-left">Package &amp; Fix</th>
										<th class="px-5 py-3 text-left w-[28%]">Affected</th>
									</tr>
								</thead>
								<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
									{#if vulnVirt.topPad > 0}<tr style="height:{vulnVirt.topPad}px"><td colspan="4"></td></tr>{/if}
									{#each vulnRows as row (row.idx)}
										{@const g = row.group}
										{#if g}
											<tr class="align-top transition hover:bg-[var(--hover-bg-subtle)] overflow-hidden" style="height:{VULN_ROW_HEIGHT}px">
												<td class="px-5 py-3">
													<div class="flex flex-wrap items-center gap-2">
														<a
															href={vulnDetailHref(g.vuln_id)}
															class="font-mono font-semibold text-[var(--accent)] hover:underline break-all"
														>{g.vuln_id}</a>
														<a
															href={vulnUpstreamUrl(g.vuln_id)}
															target="_blank"
															rel="noopener noreferrer"
															class="text-[var(--text-muted)] transition-colors hover:text-[var(--accent)]"
															aria-label="Open upstream advisory"
															onclick={(e) => e.stopPropagation()}
														>
															<ExternalLink class="h-3 w-3" />
														</a>
														{#each g.sources as src}
															<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-1.5 py-0.5 text-xs">{src}</span>
														{/each}
														{#each g.aliases ?? [] as alias}
															<a
																href={vulnDetailHref(alias)}
																class="inline-flex items-center rounded-full border border-[var(--border-color)]/70 bg-[var(--hover-bg)] px-1.5 py-0.5 font-mono text-[10px] text-[var(--text-tertiary)] transition hover:text-[var(--accent)]"
																title="Alias for this advisory"
															>{alias}</a>
														{/each}
													</div>
													{#if g.title}
														<p class="mt-0.5 text-xs text-[var(--text-muted)] leading-snug">{g.title}</p>
													{/if}
												</td>
												<td class="px-5 py-3 whitespace-nowrap">
													<span class="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium {severityClass(g.severity)} {severityIcon(g.severity).color}">
														{#if g.severity?.toUpperCase() === 'CRITICAL' || g.severity?.toUpperCase() === 'HIGH'}
															<ShieldX class="h-3 w-3" />
														{:else}
															<ShieldAlert class="h-3 w-3" />
														{/if}
														{g.severity}
													</span>
												</td>
												<td class="px-5 py-3">
													<p class="font-mono text-xs text-[var(--text-muted)] break-all">{g.pkg_name}{g.installed_version ? `@${g.installed_version}` : ''}</p>
													{#if g.fixed_version}
														<p class="mt-0.5 font-mono text-xs text-green-400"><span class="font-sans text-[var(--text-muted)]">fix:</span> {g.fixed_version}</p>
													{:else}
														<p class="mt-0.5 text-xs text-[var(--text-muted)]/50">no fix available</p>
													{/if}
												</td>
												<td class="px-5 py-3">
													<div class="flex flex-col gap-1">
														{#each g.assets as a}
															{#if a.type === 'repo'}
																<button
																	type="button"
																	class="flex items-center gap-1.5 text-left text-xs text-[var(--accent)] hover:underline break-all"
																	onclick={() => openRepo(a.id)}
																>
																	<GitBranch class="h-3 w-3 shrink-0" />
																	<span>{a.slug}</span>
																</button>
															{:else}
																<button
																	type="button"
																	class="flex items-center gap-1.5 text-left text-xs text-[var(--text-secondary)] hover:text-[var(--accent)] break-all"
																	onclick={() => openImageDrawer(a.id)}
																>
																	<Container class="h-3 w-3 shrink-0" />
																	<span>{a.slug}</span>
																</button>
															{/if}
														{/each}
													</div>
												</td>
											</tr>
										{:else}
											<tr style="height:{VULN_ROW_HEIGHT}px">
												<td class="px-5 py-3" colspan="4">
													<div class="flex items-center gap-2 text-xs text-[var(--text-muted)]">
														<div class="h-3 w-3 animate-spin rounded-full border border-[var(--text-muted)] border-t-transparent"></div>
														<span>loading…</span>
													</div>
												</td>
											</tr>
										{/if}
									{/each}
									{#if vulnVirt.bottomPad > 0}<tr style="height:{vulnVirt.bottomPad}px"><td colspan="4"></td></tr>{/if}
								</tbody>
							</table>
						</div>
					</div>
				{/if}
			{/if}
		</section>
	{/if}
</div>

<style>
	/* Severity + source pill buttons — mirrors the filter chip pattern
	   on the runs page so the accent tint reads as "selected" across
	   the app. btn / btn-ghost / btn-secondary come from app.css; this
	   only adds the tinted selected state. */
	.filter-active {
		border-color: color-mix(in srgb, var(--accent) 45%, var(--border-color));
		background: color-mix(in srgb, var(--accent) 16%, transparent);
		color: var(--text-bright);
	}

	/* btn-sm: slightly shorter pills so they sit cleanly in the 28px
	   filter row alongside Toggle + Search. */
	:global(.btn-sm) {
		padding: 0.25rem 0.75rem;
		font-size: 0.72rem;
		line-height: 1;
	}

	/* Filter chrome mirrors the clusters page (host-*) so the page feels
	   like one unified tool. */
	.host-filter-toggle {
		display: inline-flex;
		align-items: center;
		gap: 0.4rem;
		padding: 0.35rem 0.75rem;
		border-radius: 999px;
		border: 1px solid var(--border-color);
		background: transparent;
		color: var(--text-secondary);
		font-size: 0.75rem;
		font-weight: 500;
		cursor: pointer;
		transition: border-color 150ms ease, color 150ms ease, background 150ms ease;
		white-space: nowrap;
	}
	.host-filter-toggle:hover {
		color: var(--text-bright);
		border-color: var(--text-tertiary);
	}
	.host-filter-toggle.active {
		background: color-mix(in srgb, var(--accent) 12%, transparent);
		border-color: color-mix(in srgb, var(--accent) 40%, transparent);
		color: var(--accent);
	}

	.host-filter-badge {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 16px;
		height: 16px;
		border-radius: 999px;
		background: var(--accent);
		color: var(--bg-hard);
		font-size: 0.6rem;
		font-weight: 700;
		line-height: 1;
		padding: 0 0.25rem;
	}

	.host-search-input {
		height: 28px;
		width: 100%;
		min-width: 320px;
		border-radius: 999px;
		border: 1px solid var(--border-color);
		background: var(--card-bg);
		padding: 0 0.6rem 0 1.7rem;
		font-size: 0.75rem;
		color: var(--text-secondary);
		transition: border-color 150ms ease, box-shadow 150ms ease;
	}
	.host-search-input::placeholder { color: var(--text-muted); }
	.host-search-input:focus {
		outline: none;
		border-color: var(--accent);
		box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 30%, transparent);
	}
	.host-search-input-compact {
		min-width: 200px;
		width: 200px;
	}

	.host-clear-filters {
		padding: 0.3rem 0.75rem;
		border-radius: 999px;
		border: 1px solid color-mix(in srgb, var(--accent) 50%, transparent);
		background: transparent;
		color: var(--accent);
		font-size: 0.75rem;
		font-weight: 500;
		cursor: pointer;
		transition: background 150ms ease, color 150ms ease, border-color 150ms ease;
	}
	.host-clear-filters:hover {
		background: color-mix(in srgb, var(--red) 14%, transparent);
		border-color: color-mix(in srgb, var(--red) 50%, transparent);
		color: var(--red);
	}
</style>
