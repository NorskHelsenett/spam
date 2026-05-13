<script lang="ts">
	import { onMount, untrack } from 'svelte';
	import { browser } from '$app/environment';
	import { Server, Container, Globe, ChevronDown, ExternalLink, SlidersHorizontal, Search, Bot } from 'lucide-svelte';
	import { slide, fly } from 'svelte/transition';
	import { cubicOut, cubicIn } from 'svelte/easing';
	import HostChainDrawer from '$lib/components/HostChainDrawer.svelte';
	import ClusterChainDrawer from '$lib/components/ClusterChainDrawer.svelte';
	import ImageDrawer from '$lib/components/ImageDrawer.svelte';
	import DeployScamDialog from '$lib/components/DeployScamDialog.svelte';
	import { isAdmin as isAdminStore } from '$lib/stores/session';

	// isAdmin gates the SCAM-deploy empty-state copy. Non-admin users
	// with zero cluster access (typical when ROR hasn't granted them
	// anything) should not see admin-targeted "Deploy a SCAM agent"
	// instructions — that message is correct only when an admin lands
	// on the page with an actually-empty inventory.
	let isAdmin = $state(false);
	$effect(() => {
		const unsub = isAdminStore.subscribe((v) => (isAdmin = v));
		return unsub;
	});

	// --- Virtual scroll helpers for tables ---
	const ROW_HEIGHT = 48;
	const HOST_ROW_HEIGHT = 72;
	const OVERSCAN = 10;

	function useVirtualScroll(totalCount: number, rowHeight: number, scrollTop: number, viewportHeight: number, estimatedTotalCount?: number) {
		const start = Math.max(0, Math.floor(scrollTop / rowHeight) - OVERSCAN);
		const end = Math.min(totalCount, Math.ceil((scrollTop + viewportHeight) / rowHeight) + OVERSCAN);
		// estimatedTotalCount lets a server-paginated list show a true
		// scrollbar length even before all pages are loaded. The bottom
		// padding represents loaded-but-unrendered rows AND unloaded
		// rows below them. Defaults to totalCount when no estimate is
		// known (fully client-side pagination).
		const estimated = Math.max(totalCount, estimatedTotalCount ?? totalCount);
		return {
			start,
			end,
			topPad: start * rowHeight,
			bottomPad: Math.max(0, (estimated - end) * rowHeight),
		};
	}
	import DonutChart from '$lib/components/DonutChart.svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';
	import MultiSelect from '$lib/components/MultiSelect.svelte';
	import type { MultiSelectOption } from '$lib/components/MultiSelect.svelte';
	import Toggle from '$lib/components/Toggle.svelte';
	import Loading from '$lib/components/Loading.svelte';

	type ClusterRow = {
		cluster: string;
		cluster_id: string;
		environment: string;
		containers: number;
		images: number;
		namespaces: number;
		ingress_count: number;
		last_seen: string;
	};

	type RegistryDist = {
		registry: string;
		image_count: number;
	};

	type ImageDetail = {
		registry: string;
		image: string;
		digest: string;
		digest_id?: string; // image_digests.id — present once the reconciler has harvested this digest
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
	// Composite severity sort key. Maps each image to a single number where
	// higher = more severe overall, so table sort puts the nastiest images
	// on top. Weights (1e9, 1e6, 1e3, 1) keep higher severities strictly
	// dominant — one Critical always outranks any number of Highs, etc.
	function vulnSortKey(img: ImageDetail): number {
		return img.vuln_critical * 1e9
		     + img.vuln_high     * 1e6
		     + img.vuln_medium   * 1e3
		     + img.vuln_low;
	}

	// Custom tooltip for the vuln cell — positioned above the cell and
	// themed to match the rest of the panels. Tiny state footprint; shown
	// via onmouseenter / hidden via onmouseleave on the cell.
	type VulnTooltip = { x: number; y: number; img: ImageDetail } | null;
	let vulnTooltip: VulnTooltip = $state(null);
	function vulnTooltipFromCell(el: HTMLElement, img: ImageDetail) {
		const rect = el.getBoundingClientRect();
		vulnTooltip = { x: rect.left + rect.width / 2, y: rect.top, img };
	}
	function hideVulnTooltip() { vulnTooltip = null; }

	// Generic date tooltip — same pattern as vulnTooltip. The "Deployed
	// at" cell shows a relative age (e.g. "14m ago") and this surfaces
	// the absolute timestamp on hover without shipping a full tooltip
	// component.
	type DateTooltip = { x: number; y: number; iso: string } | null;
	let dateTooltip: DateTooltip = $state(null);
	function dateTooltipFromCell(el: HTMLElement, iso: string) {
		const rect = el.getBoundingClientRect();
		dateTooltip = { x: rect.left + rect.width / 2, y: rect.top, iso };
	}
	function hideDateTooltip() { dateTooltip = null; }
	const formatFullDate = (iso: string) => {
		if (!iso) return '';
		const d = new Date(iso);
		if (isNaN(d.getTime())) return '';
		const dy = String(d.getDate()).padStart(2, '0');
		const mo = String(d.getMonth() + 1).padStart(2, '0');
		const yr = String(d.getFullYear());
		const hr = String(d.getHours()).padStart(2, '0');
		const mi = String(d.getMinutes()).padStart(2, '0');
		const sc = String(d.getSeconds()).padStart(2, '0');
		return `${dy}.${mo}.${yr} ${hr}:${mi}:${sc}`;
	};

	type HostResolve = {
		ips: string[];
		is_local: boolean;
		error?: string;
	};

	type HostMeta = {
		title: string;
		has_favicon: boolean;
	};

	// `resolved` / `meta` are inlined by the API from its per-host cache
	// when available (present on every row after the cache warms). When
	// absent, the per-row $effect falls back to /resolve + /meta, which
	// in turn populates the cache for the next list response.
	type HostRow = {
		host: string;
		kind: string;
		name: string;
		namespace: string;
		cluster: string;
		cluster_id: string;
		environment: string;
		tls: boolean;
		lb_ips: string;
		ingress_class: string;
		backends: string;
		workload_count: number;
		last_seen: string;
		resolved?: HostResolve;
		meta?: HostMeta;
	};

	let clusters: ClusterRow[] = $state([]);
	// Unfiltered snapshot of the cluster summary — drives the page-level
	// metric cards and donuts so they stay stable when the user searches.
	// Refreshed alongside `clusters` whenever there is no active cluster
	// search, and explicitly when `includeInactive` toggles.
	let clustersAll: ClusterRow[] = $state([]);
	let registryDist: RegistryDist[] = $state([]);
	let imageDetails: ImageDetail[] = $state([]);
	let hosts: HostRow[] = $state([]);
	let hostResolutions = $state<Record<string, HostResolve>>({});
	let hostMetas = $state<Record<string, HostMeta>>({});
	let loading = $state(true);
	let error = $state('');
	let deployDialogOpen = $state(false);
	let activeTab = $state('clusters');
	let imagesFetched = $state(false);
	let hostsFetched = $state(false);

	// Infinite-scroll state for /api/clusters/images/detail. The endpoint
	// now paginates with ?limit/?offset and returns has_more; we keep
	// loading pages as the user scrolls until the server reports no more.
	// Existing client-side search/registry filters still operate over the
	// accumulated array, so the more the user scrolls the wider their
	// filter set becomes.
	const IMAGE_PAGE_SIZE = 50;
	let imageOffset = $state(0);
	let imageHasMore = $state(false);
	let imageLoadingMore = $state(false);
	let tick = $state(0);
	let chainDrawerOpen = $state(false);
	let chainDrawerRow: HostRow | null = $state(null);

	// Virtual scroll state per tab
	let clusterScrollEl: HTMLDivElement | undefined = $state();
	let clusterScrollTop = $state(0);
	let clusterViewH = $state(600);
	let imageScrollEl: HTMLDivElement | undefined = $state();
	let imageScrollTop = $state(0);
	let imageViewH = $state(600);
	let hostScrollEl: HTMLDivElement | undefined = $state();
	let hostScrollTop = $state(0);
	let hostViewH = $state(600);
	let clusterDrawerOpen = $state(false);
	let clusterDrawerRow: ClusterRow | null = $state(null);
	let imageDrawerOpen = $state(false);
	let imageDrawerId: string | null = $state(null);

	// Pending scroll restores — set by snapshot.restore, applied by
	// the $effect below once the corresponding tab's scroll element
	// has bound AND its data has landed (setting scrollTop on an
	// empty container won't stick). Cleared on application.
	let restoreClusterScroll = $state<number | null>(null);
	let restoreImageScroll = $state<number | null>(null);
	let restoreHostScroll = $state<number | null>(null);

	// SvelteKit snapshot: preserves tab + filter + scroll state when
	// navigating to a detail route (image, host chain, cluster chain)
	// and back via history.back(). The three inner-div scrolls aren't
	// covered by SvelteKit's window-level scroll restoration, so we
	// capture them explicitly.
	export const snapshot = {
		capture: () => ({
			activeTab,
			includeInactive,
			clusterSearch,
			imageSearch,
			imageSelectedRegistries,
			hostSearch,
			hostSelectedClusters,
			hostSelectedNamespaces,
			hostSelectedKinds,
			hostActiveWorkloadsOnly,
			scroll: {
				cluster: clusterScrollTop,
				image: imageScrollTop,
				host: hostScrollTop,
			},
		}),
		restore: (v: {
			activeTab?: string;
			includeInactive?: boolean;
			clusterSearch?: string;
			imageSearch?: string;
			imageSelectedRegistries?: string[];
			hostSearch?: string;
			hostSelectedClusters?: string[];
			hostSelectedNamespaces?: string[];
			hostSelectedKinds?: string[];
			hostActiveWorkloadsOnly?: boolean;
			scroll?: { cluster?: number; image?: number; host?: number };
		}) => {
			if (v.activeTab !== undefined) activeTab = v.activeTab;
			if (v.includeInactive !== undefined) includeInactive = v.includeInactive;
			if (v.clusterSearch !== undefined) clusterSearch = v.clusterSearch;
			if (v.imageSearch !== undefined) imageSearch = v.imageSearch;
			if (v.imageSelectedRegistries) imageSelectedRegistries = v.imageSelectedRegistries;
			if (v.hostSearch !== undefined) hostSearch = v.hostSearch;
			if (v.hostSelectedClusters) hostSelectedClusters = v.hostSelectedClusters;
			if (v.hostSelectedNamespaces) hostSelectedNamespaces = v.hostSelectedNamespaces;
			if (v.hostSelectedKinds) hostSelectedKinds = v.hostSelectedKinds;
			if (v.hostActiveWorkloadsOnly !== undefined) hostActiveWorkloadsOnly = v.hostActiveWorkloadsOnly;
			if (v.scroll) {
				if (v.scroll.cluster) restoreClusterScroll = v.scroll.cluster;
				if (v.scroll.image) restoreImageScroll = v.scroll.image;
				if (v.scroll.host) restoreHostScroll = v.scroll.host;
			}
		},
	};

	function openImageDrawer(digestId: string) {
		if (imageDrawerOpen && imageDrawerId === digestId) {
			imageDrawerOpen = false;
			imageDrawerId = null;
		} else {
			imageDrawerId = digestId;
			imageDrawerOpen = true;
		}
	}

	function openClusterDrawer(row: ClusterRow) {
		if (clusterDrawerOpen && clusterDrawerRow?.cluster_id === row.cluster_id) {
			clusterDrawerOpen = false;
			clusterDrawerRow = null;
		} else {
			clusterDrawerRow = row;
			clusterDrawerOpen = true;
		}
	}

	function openChainDrawer(row: HostRow) {
		if (chainDrawerOpen && chainDrawerRow?.host === row.host && chainDrawerRow?.cluster_id === row.cluster_id && chainDrawerRow?.namespace === row.namespace) {
			chainDrawerOpen = false;
			chainDrawerRow = null;
		} else {
			chainDrawerRow = row;
			chainDrawerOpen = true;
		}
	}

	const palette = [
		'var(--accent)', 'var(--blue)', 'var(--green)',
		'var(--yellow)', 'var(--orange)', 'var(--purple)', 'var(--aqua)'
	];

	// When the "Show inactive (>24h)" toggle is on, every cluster-page
	// endpoint gets ?include_inactive=true so silent clusters and their
	// images/hosts come through. Default is live-only.
	const inactiveQS = () => (includeInactive ? '?include_inactive=true' : '');

	const buildClusterURL = () => {
		const params = new URLSearchParams();
		if (includeInactive) params.set('include_inactive', 'true');
		const q = clusterSearch.trim();
		if (q) params.set('q', q);
		const qs = params.toString();
		return qs ? `/api/clusters/summary?${qs}` : '/api/clusters/summary';
	};

	// Unfiltered cluster + host summaries feed the page-level metric
	// cards and donuts. Loaded once on mount and refreshed on
	// includeInactive toggle — never re-fetched when the user changes a
	// search query, so the cards stay stable while filtering.
	const loadUnfiltered = async () => {
		const params = new URLSearchParams();
		if (includeInactive) params.set('include_inactive', 'true');
		const qs = params.toString() ? `?${params}` : '';
		try {
			const [allClustersRes, allHostsRes] = await Promise.all([
				fetch(`/api/clusters/summary${qs}`, { credentials: 'include' }),
				fetch(`/api/clusters/hosts/summary${qs}`, { credentials: 'include' })
			]);
			if (allClustersRes.ok) {
				const body = await allClustersRes.json().catch(() => null);
				clustersAll = Array.isArray(body) ? body : [];
			}
			if (allHostsRes.ok) {
				const body = await allHostsRes.json().catch(() => null);
				if (body && typeof body === 'object') {
					hostSummaryAll = {
						external: body.external ?? 0,
						internal: body.internal ?? 0,
						pending: body.pending ?? 0,
						total: body.total ?? 0,
						clusters: Array.isArray(body.clusters) ? body.clusters : [],
						namespaces: Array.isArray(body.namespaces) ? body.namespaces : [],
						kinds: Array.isArray(body.kinds) ? body.kinds : []
					};
				}
			}
		} catch { /* silent — page-level cards just stay zeroed */ }
	};

	const loadMain = async () => {
		try {
			const qs = inactiveQS();
			const [clusterRes, regRes] = await Promise.all([
				fetch(buildClusterURL(), { credentials: 'include' }),
				fetch(`/api/clusters/registry-distribution${qs}`, { credentials: 'include' })
			]);
			// Defensive parse: 504s / proxy error pages return non-JSON
			// (HTML), and a `?? []` fallback on an object body would still
			// pass through. Array.isArray locks the expected shape.
			if (clusterRes.ok) {
				const body = await clusterRes.json().catch(() => null);
				clusters = Array.isArray(body) ? body : [];
				// When no cluster search is active, this fetch IS the
				// unfiltered set — reuse it to seed clustersAll without
				// an extra round-trip.
				if (!clusterSearch.trim()) clustersAll = clusters;
			}
			if (regRes.ok) {
				const body = await regRes.json().catch(() => null);
				registryDist = Array.isArray(body) ? body : [];
			}
			// Summary fires immediately for the chip; full host list
			// stays lazy via loadHosts() (called when the Hosts tab
			// renders) since it's only needed for the table.
			loadHostSummary();
		} catch {
			error = 'Failed to load cluster data';
		} finally {
			loading = false;
		}
	};

	// Inflight flags — the hostsFetched / imagesFetched booleans only
	// flip true AFTER the response lands, which leaves a window where
	// two rapid calls (e.g. loadMain's internal call + an explicit call
	// from the same event handler) both pass the guard and fire parallel
	// requests. These flags block re-entry while a fetch is already in
	// flight. Reactive ($state) so the UI can show a spinner while a
	// fetch is in progress.
	let imagesInFlight = $state(false);
	let hostsInFlight = $state(false);

	// imagesPath builds the paginated URL with the include_inactive
	// toggle and the limit/offset cursor. Kept as a helper so loadImages
	// and loadMoreImages share the param construction.
	const imagesPath = (offset: number) => {
		const params = new URLSearchParams();
		if (includeInactive) params.set('include_inactive', 'true');
		params.set('limit', String(IMAGE_PAGE_SIZE));
		params.set('offset', String(offset));
		const q = imageSearch.trim();
		if (q) params.set('q', q);
		if (imageSelectedRegistries.length > 0) params.set('registries', imageSelectedRegistries.join(','));
		params.set('sort', String(imageSortKey));
		params.set('order', imageSortDir);
		return `/api/clusters/images/detail?${params}`;
	};

	type ImageDetailPage = {
		items: ImageDetail[];
		limit: number;
		offset: number;
		has_more: boolean;
		total: number;
	};

	// Fleet-wide total returned by the image-detail endpoint alongside
	// each page. Drives "showing N of M" and the true virtual-scroll
	// height — without it the scrollbar lies about how much content
	// exists below the loaded set.
	let imageTotal = $state(0);

	const loadImages = async () => {
		if (imagesFetched || imagesInFlight) return;
		imagesInFlight = true;
		try {
			const res = await fetch(imagesPath(0), { credentials: 'include' });
			if (res.ok) {
				const page = (await res.json()) as ImageDetailPage;
				imageDetails = page.items ?? [];
				imageOffset = imageDetails.length;
				imageHasMore = Boolean(page.has_more);
				imageTotal = page.total ?? 0;
			}
			imagesFetched = true;
		} catch { /* silent */ }
		finally { imagesInFlight = false; }
	};

	// Pulls the next page and appends to the array. Triggered by the
	// scroll handler when the viewport approaches the end of the
	// rendered virtual list. Guarded against re-entry by
	// imageLoadingMore so rapid scroll events don't fan out duplicate
	// fetches.
	const loadMoreImages = async () => {
		if (!imageHasMore || imageLoadingMore) return;
		imageLoadingMore = true;
		try {
			const res = await fetch(imagesPath(imageOffset), { credentials: 'include' });
			if (res.ok) {
				const page = (await res.json()) as ImageDetailPage;
				if (page.items?.length) {
					imageDetails = [...imageDetails, ...page.items];
					imageOffset = imageDetails.length;
				}
				imageHasMore = Boolean(page.has_more);
				if (page.total != null) imageTotal = page.total;
			}
		} catch { /* silent */ }
		finally { imageLoadingMore = false; }
	};

	// Hosts pagination — page in chunks so the wire payload stays
	// bounded even on large fleets. The backend orders by (host, cluster)
	// so successive offsets are deterministic across requests; the total
	// count for "showing N of M" comes from hostSummary so we don't pay
	// an extra COUNT(*) round trip.
	const hostsPageSize = 200;
	let hostsOffset = $state(0);
	let hostsHasMore = $state(true);
	let hostsLoadingMore = $state(false);

	const loadHostsPage = async (initial: boolean) => {
		if (hostsInFlight || hostsLoadingMore) return;
		if (!initial && !hostsHasMore) return;
		if (initial) hostsInFlight = true; else hostsLoadingMore = true;
		try {
			const offset = initial ? 0 : hostsOffset;
			const qs = buildHostQueryString({
				offset: String(offset),
				limit: String(hostsPageSize),
				sort: String(hostSortKey),
				order: hostSortDir
			});
			const url = `/api/clusters/hosts${qs}`;
			const res = await fetch(url, { credentials: 'include' });
			if (res.ok) {
				const body = await res.json().catch(() => null);
				const page = Array.isArray(body) ? body : [];
				hosts = initial ? page : hosts.concat(page);
				hostsOffset = offset + page.length;
				hostsHasMore = page.length === hostsPageSize;

				const seedRes: Record<string, HostResolve> = {};
				const seedMeta: Record<string, HostMeta> = {};
				for (const h of page) {
					if (h.resolved) seedRes[h.host] = h.resolved;
					if (h.meta) seedMeta[h.host] = h.meta;
				}
				if (Object.keys(seedRes).length) hostResolutions = { ...hostResolutions, ...seedRes };
				if (Object.keys(seedMeta).length) hostMetas = { ...hostMetas, ...seedMeta };
			}
			if (initial) hostsFetched = true;
		} catch { /* silent */ }
		finally {
			if (initial) hostsInFlight = false;
			else hostsLoadingMore = false;
		}
	};

	const loadHosts = () => loadHostsPage(true);
	const loadMoreHosts = () => loadHostsPage(false);

	// Lazy-load metadata only for hosts visible in the virtual scroll viewport.
	$effect(() => {
		const visible = sortedHosts.slice(hostVirt.start, hostVirt.end);
		for (const h of visible) {
			fetchHostResolve(h.host);
			fetchHostMeta(h.host);
		}
	});

	// Infinite scroll: trigger only when the viewport is within the
	// last 20 rows of the currently loaded set. Originally a 75%
	// threshold, which during fast scrolling fired again immediately
	// after each load completed (the new end was past 75% of the new
	// length too) and spammed the endpoint with offset=200, offset=400,
	// offset=600 in rapid succession. The "last 20 rows" trigger is
	// edge-driven instead of ratio-driven, so a single load is enough
	// to push the user back out of the trigger window until they
	// actually scroll further.
	$effect(() => {
		if (!hostsHasMore || hostsLoadingMore || hostsInFlight) return;
		if (sortedHosts.length === 0) return;
		const trigger = Math.max(0, sortedHosts.length - 20);
		// untrack the call so we only re-fire on the guard-state deps
		// + scroll position above, not on internal buildHostQueryString
		// reads.
		if (hostVirt.end >= trigger) untrack(() => loadMoreHosts());
	});

	// In-flight trackers. The cached-result dedup (`if (hostMetas[host])
	// return`) doesn't cover the window between request-start and
	// response-resolve: a rapid sequence of $effect ticks sees
	// hostMetas[host] === undefined and fires duplicate requests for
	// the same host. With the trackers, only one request per host is
	// ever in flight; subsequent calls no-op until the response lands.
	const inFlightResolve = new Set<string>();
	const inFlightMeta = new Set<string>();

	const fetchHostResolve = (host: string) => {
		if (hostResolutions[host] || inFlightResolve.has(host)) return;
		inFlightResolve.add(host);
		fetch(`/api/clusters/hosts/resolve?host=${encodeURIComponent(host)}`, { credentials: 'include' })
			.then((r) => r.json())
			.then((data: HostResolve) => {
				hostResolutions = { ...hostResolutions, [host]: data };
			})
			.catch(() => {
				hostResolutions = { ...hostResolutions, [host]: { ips: [], is_local: false, error: 'failed' } };
			})
			.finally(() => {
				inFlightResolve.delete(host);
			});
	};

	const fetchHostMeta = (host: string) => {
		if (hostMetas[host] || inFlightMeta.has(host)) return;
		inFlightMeta.add(host);
		fetch(`/api/clusters/hosts/meta?host=${encodeURIComponent(host)}`, { credentials: 'include' })
			.then((r) => r.json())
			.then((data: HostMeta) => {
				hostMetas = { ...hostMetas, [host]: data };
			})
			.catch(() => {
				hostMetas = { ...hostMetas, [host]: { title: '', has_favicon: false } };
			})
			.finally(() => {
				inFlightMeta.delete(host);
			});
	};

	const hostUrl = (host: string, tls: boolean) => `${tls ? 'https' : 'http'}://${host}`;
	const faviconProxyUrl = (host: string) => `/api/clusters/hosts/favicon?host=${encodeURIComponent(host)}`;

	onMount(() => {
		if (!browser) return;
		loadMain();
		// loadMain already populates clustersAll + hostSummaryAll when
		// no filter is active (see the !clusterSearch.trim() branch in
		// loadMain and the hostActiveFilterCount===0 branch in
		// loadHostSummary). Only fire the parallel unfiltered fetch
		// when there IS a deep-link search active — otherwise it's a
		// pure duplicate of the loadMain fan-out.
		if (clusterSearch.trim()) loadUnfiltered();

		// Relative-time ticker only — purely a display refresh, no
		// network calls.
		const interval = setInterval(() => tick++, 60_000);

		// We deliberately do NOT subscribe to /api/app/stream here. With
		// hundreds of clusters and thousands of images the per-page
		// fan-out (summary + registry-distribution + hosts + image
		// detail) is expensive enough that re-firing it on every
		// scam_ingest event practically DDoS'd the API. The page now
		// loads once on open; the user can flip the inactive toggle or
		// reload to refresh.
		return () => {
			clearInterval(interval);
		};
	});

	$effect(() => {
		// Same untrack guard as the hosts tab-open effect: prevents
		// loadImages's internal reads from becoming tracked deps and
		// causing a state-write-driven reload loop.
		if (activeTab === 'images') untrack(() => loadImages());
	});

	// Debounced reload whenever any image filter or sort changes. Same
	// pattern as the hosts side — server-side pagination means client
	// can't compute the right list without re-fetching, and we reset
	// the offset cursor so the next page lands correctly aligned with
	// the new ORDER BY.
	let imageFiltersTimer: ReturnType<typeof setTimeout> | null = null;
	$effect(() => {
		const _ = [
			imageSearch,
			imageSelectedRegistries.join(' '),
			imageSortKey,
			imageSortDir
		];
		if (!browser) return;
		if (imageFiltersTimer) clearTimeout(imageFiltersTimer);
		imageFiltersTimer = setTimeout(() => {
			if (activeTab !== 'images' && !imagesFetched) return;
			imagesFetched = false;
			imageOffset = 0;
			imageHasMore = false;
			imageDetails = [];
			imageTotal = 0;
			// Reset scroll to the top of the (about-to-be-empty) list so
			// when the new page lands the user sees the first matching
			// rows. Without this, a stale hostScrollTop / imageScrollTop
			// from the previous (larger) dataset can park the virtual
			// scroll's start index past the new dataset length — the
			// row slice returns empty and the table looks broken until
			// the user manually scrolls back up.
			imageScrollTop = 0;
			if (imageScrollEl) imageScrollEl.scrollTop = 0;
			untrack(() => loadImages());
		}, 200);
		void _;
	});

	// Lazy-load the host list when the Hosts tab is first opened. Calling
	// loadHosts() unconditionally on every tab change would re-fire on
	// every render; the in-flight + hostsFetched guards inside the
	// function make it a single-fire effect.
	$effect(() => {
		// untrack so loadHosts's internal reads (hostsFetched,
		// hostsInFlight, every filter / sort state via the URL builder)
		// don't become deps of this effect. Without it, every successful
		// load re-arms this effect — even though the guards inside
		// loadHosts return early, the effect's tracked-dep set was
		// growing on each call and the eventual write to one of them
		// (filter reload, scroll-driven loadMore, etc.) triggered the
		// offset=0 reload loop reported in prod.
		if (activeTab === 'hosts') untrack(() => loadHosts());
	});

	// Debounced cluster search → reload /clusters/summary with q=.
	// Skip the initial run: $effect always fires once on mount, and
	// onMount() already kicks loadMain() — without this guard the
	// page triggers a duplicate /summary + /registry-distribution +
	// /hosts/summary fan-out 200ms after open.
	let clusterSearchTimer: ReturnType<typeof setTimeout> | null = null;
	let initialClusterSearch = true;
	$effect(() => {
		const q = clusterSearch; // track
		if (!browser) return;
		if (initialClusterSearch) { initialClusterSearch = false; return; }
		if (clusterSearchTimer) clearTimeout(clusterSearchTimer);
		clusterSearchTimer = setTimeout(() => {
			loadMain();
		}, 200);
		void q;
	});

	// Debounced reload whenever any host filter changes (search or any
	// of the categorical multiselects or the active-workloads toggle).
	// 200ms is snappy enough without firing on every keystroke or click.
	// Also refreshes the summary so the chip / "showing N of M" /
	// dropdown options re-aggregate against the new filter scope.
	let hostFiltersTimer: ReturnType<typeof setTimeout> | null = null;
	$effect(() => {
		// Track every filter input so this effect re-runs on change.
		const _ = [
			hostSearch,
			hostSelectedClusters.join(' '),
			hostSelectedNamespaces.join(' '),
			hostSelectedKinds.join(' '),
			hostActiveWorkloadsOnly,
			hostSortKey,
			hostSortDir
		];
		if (!browser) return;
		// Tab + fetched checks run inside the setTimeout (not at effect
		// definition time) so they don't get registered as reactive
		// deps. Reading hostsFetched up here would mean the effect
		// re-runs after every successful load (loadHosts flips
		// hostsFetched back to true), re-arming the setTimeout and
		// firing another offset=0 reload — that was the scroll-time
		// "spamming offset=0&limit=200" loop.
		if (hostFiltersTimer) clearTimeout(hostFiltersTimer);
		hostFiltersTimer = setTimeout(() => {
			if (activeTab !== 'hosts' && !hostsFetched) return;
			hostsFetched = false;
			hostsOffset = 0;
			hostsHasMore = true;
			hosts = [];
			// Reset scroll so the new (potentially smaller) result set
			// renders from the top. Without this, the stale hostScrollTop
			// can land the virtual-scroll start index past the new
			// hosts.length — slice returns empty and the table looks
			// broken until the user manually scrolls back up.
			hostScrollTop = 0;
			if (hostScrollEl) hostScrollEl.scrollTop = 0;
			loadHosts();
			loadHostSummary();
		}, 200);
		void _;
	});

	// When the "Show inactive" toggle flips, invalidate the lazy-load
	// caches and refetch the three top-level payloads so they reflect
	// the new scope.
	let initialInactive = true;
	$effect(() => {
		includeInactive; // track
		if (initialInactive) { initialInactive = false; return; }
		imagesFetched = false;
		hostsFetched = false;
		// Reset infinite-scroll cursor; the toggle changes the underlying
		// row set, so accumulated pages are no longer valid.
		imageDetails = [];
		imageOffset = 0;
		imageHasMore = false;
		loadMain();
		// Unfiltered snapshot has to refresh too — the activity scope
		// changed so the totals shown on the page-level cards are stale.
		loadUnfiltered();
		if (activeTab === 'images') loadImages();
	});

	// Page-level metric cards bind to the unfiltered set so they don't
	// shift around while the user types in the cluster search.
	const totalImages = $derived(clustersAll.reduce((s, c) => s + c.images, 0));
	const totalContainers = $derived(clustersAll.reduce((s, c) => s + c.containers, 0));

	const registrySegments = $derived(
		registryDist.map((r, i) => ({
			label: r.registry,
			value: r.image_count,
			color: palette[i % palette.length]
		}))
	);
	const registryTotal = $derived(registryDist.reduce((s, r) => s + r.image_count, 0));

	const isPrivateIP = (ip: string): boolean => {
		const parts = ip.split('.').map(Number);
		if (parts.length !== 4) return false;
		if (parts[0] === 10) return true;
		if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
		if (parts[0] === 192 && parts[1] === 168) return true;
		if (parts[0] === 127) return true;
		return false;
	};

	// Exposure counts come from /api/clusters/hosts/summary — a tiny
	// aggregate endpoint, so the chip renders without waiting on the
	// 1MB hosts list (which the Hosts tab still loads lazily). The
	// classification (LB IP first, then cached DNS) lives server-side
	// so "pending" reflects genuinely unknown hosts rather than
	// "haven't scrolled there yet" — see HostSummaryHandler. The same
	// response also carries the distinct values for the filter
	// dropdowns, since with server-side pagination the loaded rows
	// don't represent the full set of clusters/namespaces/kinds.
	type HostFacetOption = { id: string; label: string };
	let hostSummary = $state<{
		external: number;
		internal: number;
		pending: number;
		total: number;
		clusters: HostFacetOption[];
		namespaces: string[];
		kinds: string[];
	}>({ external: 0, internal: 0, pending: 0, total: 0, clusters: [], namespaces: [], kinds: [] });
	// Unfiltered host summary — drives the page-level Hosts card and
	// Network exposure donut so they don't shift while the user filters.
	let hostSummaryAll = $state<{
		external: number;
		internal: number;
		pending: number;
		total: number;
		clusters: HostFacetOption[];
		namespaces: string[];
		kinds: string[];
	}>({ external: 0, internal: 0, pending: 0, total: 0, clusters: [], namespaces: [], kinds: [] });

	const buildHostQueryString = (extra?: Record<string, string>): string => {
		const params = new URLSearchParams();
		if (includeInactive) params.set('include_inactive', 'true');
		const q = hostSearch.trim();
		if (q) params.set('q', q);
		if (hostSelectedClusters.length > 0) params.set('cluster_ids', hostSelectedClusters.join(','));
		if (hostSelectedNamespaces.length > 0) params.set('namespaces', hostSelectedNamespaces.join(','));
		if (hostSelectedKinds.length > 0) params.set('kinds', hostSelectedKinds.join(','));
		if (hostActiveWorkloadsOnly) params.set('active_workloads_only', 'true');
		// Sort applies only to the paginated list endpoint, not the
		// summary — summary aggregates over the whole set regardless.
		// Callers that don't want sort pass extra without it; the
		// summary call deliberately omits these params.
		if (extra) for (const [k, v] of Object.entries(extra)) params.set(k, v);
		const s = params.toString();
		return s ? `?${s}` : '';
	};

	const loadHostSummary = async () => {
		try {
			const res = await fetch(`/api/clusters/hosts/summary${buildHostQueryString()}`, { credentials: 'include' });
			if (res.ok) {
				const body = await res.json().catch(() => null);
				if (body && typeof body === 'object') {
					hostSummary = {
						external: body.external ?? 0,
						internal: body.internal ?? 0,
						pending: body.pending ?? 0,
						total: body.total ?? 0,
						clusters: Array.isArray(body.clusters) ? body.clusters : [],
						namespaces: Array.isArray(body.namespaces) ? body.namespaces : [],
						kinds: Array.isArray(body.kinds) ? body.kinds : []
					};
					// When no host filter is active this fetch IS the
					// unfiltered set — reuse it to seed hostSummaryAll
					// without an extra round-trip.
					if (hostActiveFilterCount === 0) hostSummaryAll = hostSummary;
				}
			}
		} catch { /* silent — chip just stays zeroed */ }
	};

	// Page-level Hosts card and Network exposure donut bind to the
	// unfiltered summary so they don't update while the user filters
	// inside the Hosts tab.
	const exposureCounts = $derived(hostSummaryAll);
	const uniqueHosts = $derived(hostSummaryAll.total);
	const exposureSegments = $derived([
		{ label: 'External', value: exposureCounts.external, color: 'var(--red)' },
		{ label: 'Internal', value: exposureCounts.internal, color: 'var(--green)' }
	]);
	const exposureTotal = $derived(exposureCounts.external + exposureCounts.internal + exposureCounts.pending);

	const timeAgo = (iso: string, _tick: number) => {
		if (!iso) return '';
		const diff = Date.now() - new Date(iso).getTime();
		const mins = Math.floor(diff / 60000);
		if (mins < 1) return 'just now';
		if (mins < 60) return `${mins}m ago`;
		const hours = Math.floor(mins / 60);
		if (hours < 24) return `${hours}h ago`;
		return `${Math.floor(hours / 24)}d ago`;
	};

	const shortDigest = (d: string) => {
		if (!d) return '';
		const hash = d.startsWith('sha256:') ? d.slice(7) : d;
		return hash.slice(0, 12);
	};

	const parseTags = (t: string) => t ? t.split(',').filter(Boolean) : [];

	// --- Cluster filters ---
	let clusterFilterOpen = $state(false);
	let clusterSearch = $state('');
	// When true, include clusters whose agent has been silent longer than
	// the server's live window (24h default). Reissues the cluster-page
	// fetches with ?include_inactive=true — see $effect below.
	let includeInactive = $state(false);

	const clusterActiveFilterCount = $derived(
		(clusterSearch.trim() ? 1 : 0) + (includeInactive ? 1 : 0)
	);

	// Cluster search is server-side via buildClusterURL — the filter
	// below stays as a passthrough so the existing render path (which
	// reads filteredClusters) keeps working without further changes.
	const filteredClusters = $derived(clusters);

	const clearClusterFilters = () => {
		clusterSearch = '';
		includeInactive = false;
	};

	// --- Image filters ---
	let imageFilterOpen = $state(false);
	let imageSearch = $state('');
	let imageSelectedRegistries: string[] = $state([]);

	// Registry options come from /api/clusters/registry-distribution
	// (registryDist), which already aggregates every registry across
	// the fleet — not from the loaded image page, which would miss
	// registries on unloaded pages. Sorted by name so the dropdown
	// order is stable; the registry-distribution endpoint sorts by
	// count for the donut chart.
	const imageRegistryOptions: MultiSelectOption[] = $derived(
		[...registryDist].sort((a, b) => a.registry.localeCompare(b.registry)).map((r) => ({ value: r.registry, label: r.registry }))
	);

	const imageActiveFilterCount = $derived(
		(imageSearch.trim() ? 1 : 0) + (imageSelectedRegistries.length > 0 ? 1 : 0)
	);

	// Image search + registry filter are server-side via imagesPath().
	// Keep filteredImages as a passthrough so render code unchanged.
	const filteredImages = $derived(imageDetails);

	const clearImageFilters = () => {
		imageSearch = '';
		imageSelectedRegistries = [];
	};

	// --- Host filters ---
	let hostFilterOpen = $state(false);
	let hostSearch = $state('');
	let hostSelectedClusters: string[] = $state([]);
	let hostSelectedNamespaces: string[] = $state([]);
	let hostSelectedKinds: string[] = $state([]);
	let hostActiveWorkloadsOnly = $state(false);

	// Filter dropdown options come from the host summary endpoint —
	// it scans every host the caller can see, regardless of pagination.
	// Loaded-rows-based options would miss values from unloaded pages
	// and silently exclude valid filter targets.
	const hostClusterOptions: MultiSelectOption[] = $derived(
		hostSummary.clusters.map((c) => ({ value: c.id, label: c.label }))
	);
	const hostNamespaceOptions: MultiSelectOption[] = $derived(
		hostSummary.namespaces.map((n) => ({ value: n, label: n }))
	);
	const hostKindOptions: MultiSelectOption[] = $derived(
		hostSummary.kinds.map((k) => ({ value: k, label: k }))
	);

	const hostActiveFilterCount = $derived(
		(hostSearch.trim() ? 1 : 0) +
		(hostSelectedClusters.length > 0 ? 1 : 0) +
		(hostSelectedNamespaces.length > 0 ? 1 : 0) +
		(hostSelectedKinds.length > 0 ? 1 : 0) +
		(hostActiveWorkloadsOnly ? 1 : 0)
	);

	// All host filters (search + clusters + namespaces + kinds +
	// active-workloads-only) are applied server-side via the
	// buildHostQueryString helper. filteredHosts is now a passthrough
	// so the existing render path keeps working without changes.
	const filteredHosts = $derived(hosts);

	const clearHostFilters = () => {
		hostSearch = '';
		hostSelectedClusters = [];
		hostSelectedNamespaces = [];
		hostSelectedKinds = [];
		hostActiveWorkloadsOnly = false;
	};

	// --- Sorting ---
	type SortDir = 'asc' | 'desc';
	let clusterSortKey = $state<keyof ClusterRow>('cluster');
	let clusterSortDir = $state<SortDir>('asc');
	// 'vulns' is synthetic — sorted via vulnSortKey rather than a
	// direct column access (keyof ImageDetail).
	type ImageSortKey = keyof ImageDetail | 'vulns';
	let imageSortKey = $state<ImageSortKey>('container_count');
	let imageSortDir = $state<SortDir>('desc');
	let hostSortKey = $state<keyof HostRow>('cluster');
	let hostSortDir = $state<SortDir>('asc');

	const cmp = (a: any, b: any, dir: SortDir): number => {
		if (a == null && b == null) return 0;
		if (a == null) return 1;
		if (b == null) return -1;
		const result = typeof a === 'string' ? a.localeCompare(b) : (a as number) - (b as number);
		return dir === 'asc' ? result : -result;
	};

	const sc = (k: keyof ClusterRow) => () => {
		if (clusterSortKey === k) { clusterSortDir = clusterSortDir === 'asc' ? 'desc' : 'asc'; }
		else { clusterSortKey = k; clusterSortDir = 'desc'; }
	};

	const si = (k: ImageSortKey) => () => {
		if (imageSortKey === k) { imageSortDir = imageSortDir === 'asc' ? 'desc' : 'asc'; }
		else { imageSortKey = k; imageSortDir = 'desc'; }
	};

	const sh = (k: keyof HostRow) => () => {
		if (hostSortKey === k) { hostSortDir = hostSortDir === 'asc' ? 'desc' : 'asc'; }
		else { hostSortKey = k; hostSortDir = 'asc'; }
	};

	const sortedClusters = $derived(
		[...filteredClusters].sort((a, b) => cmp(a[clusterSortKey], b[clusterSortKey], clusterSortDir))
	);

	// Image sort is applied server-side via the sort+order query params
	// (see imagesPath + the imageFiltersTimer debounce). 'vulns' resolves
	// to vuln_weight in the inventory_with_vulns CTE so the severity-
	// weighted order matches the old client-side vulnSortKey but spans
	// the entire dataset rather than the loaded page. Rendering in
	// array order keeps the client view in sync with the server's order.
	const sortedImages = $derived(filteredImages);

	// Host sort is applied server-side via the sort+order query params;
	// rendering the loaded page in array order keeps client and server
	// in agreement.
	const sortedHosts = $derived(filteredHosts);

	// Virtual scroll ranges (must be after sorted* declarations)
	let clusterVirt = $derived(useVirtualScroll(sortedClusters.length, ROW_HEIGHT, clusterScrollTop, clusterViewH));
	let imageVirt = $derived(useVirtualScroll(sortedImages.length, ROW_HEIGHT, imageScrollTop, imageViewH, imageTotal));
	let hostVirt = $derived(useVirtualScroll(sortedHosts.length, HOST_ROW_HEIGHT, hostScrollTop, hostViewH, hostSummary.total));

	// Apply pending scroll restores once the target tab's DOM has
	// mounted (scrollEl bound) and its data has landed (rows > 0).
	// Each $effect fires exactly once per snapshot restore: the self-
	// clearing null assignment flips the guard so the effect doesn't
	// re-run on subsequent data changes.
	$effect(() => {
		if (restoreClusterScroll !== null && clusterScrollEl && sortedClusters.length > 0) {
			clusterScrollEl.scrollTop = restoreClusterScroll;
			clusterScrollTop = restoreClusterScroll;
			restoreClusterScroll = null;
		}
	});
	$effect(() => {
		if (restoreImageScroll !== null && imageScrollEl && sortedImages.length > 0) {
			imageScrollEl.scrollTop = restoreImageScroll;
			imageScrollTop = restoreImageScroll;
			restoreImageScroll = null;
		}
	});
	$effect(() => {
		if (restoreHostScroll !== null && hostScrollEl && sortedHosts.length > 0) {
			hostScrollEl.scrollTop = restoreHostScroll;
			hostScrollTop = restoreHostScroll;
			restoreHostScroll = null;
		}
	});
</script>

<svelte:head>
	<title>Clusters &middot; Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Clusters</h1>
			<p class="text-sm text-[var(--text-tertiary)]">Live container image inventory from SCAM agents.</p>
		</header>

		{#if loading}
			<div class="flex flex-col items-center justify-center gap-5 py-24">
				<Server class="h-12 w-12 text-[var(--yellow)]" />
				<p class="text-base font-medium text-[var(--text-secondary)]">Waiting for cluster data</p>
				<p class="text-sm text-[var(--text-muted)]">Connecting to SCAM agents...</p>
				<div class="w-48 overflow-hidden rounded-full bg-[var(--bg2)]/30">
					<div class="loading-bar h-1 rounded-full bg-[var(--yellow)]"></div>
				</div>
			</div>
		{:else if error}
			<div class="flex flex-col items-center justify-center py-24">
				<Server class="h-12 w-12 text-[var(--error)]" />
				<p class="mt-5 text-base font-medium text-[var(--text-secondary)]">{error}</p>
			</div>
		{:else if clustersAll.length === 0 && isAdmin}
			<div class="flex flex-col items-center justify-center gap-5 py-24">
				<Bot class="h-12 w-12 text-[var(--yellow)]" />
				<p class="text-base font-medium text-[var(--text-secondary)]">No cluster data yet</p>
				<p class="text-sm text-[var(--text-muted)]">Deploy a SCAM agent to start collecting container inventory.</p>
				<div class="w-48 overflow-hidden rounded-full bg-[var(--bg2)]/30">
					<div class="loading-bar h-1 rounded-full bg-[var(--yellow)]"></div>
				</div>
				<button
					type="button"
					class="mt-2 inline-flex items-center gap-2 rounded-full border border-[var(--accent)]/40 bg-[var(--accent)]/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-[var(--accent)] transition hover:bg-[var(--accent)]/20"
					onclick={() => (deployDialogOpen = true)}
				>
					Show install instructions
				</button>
			</div>
		{:else if clustersAll.length === 0}
			<div class="flex flex-col items-center justify-center gap-4 py-24 text-center">
				<Bot class="h-12 w-12 text-[var(--text-tertiary)]" />
				<p class="text-base font-medium text-[var(--text-secondary)]">No clusters available</p>
				<p class="max-w-md text-sm text-[var(--text-muted)]">
					Your account doesn't have read access to any clusters yet. Ask an administrator to grant you access in ROR.
				</p>
			</div>
		{:else}
			<!-- Metric cards -->
			<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
				<article class="metric-card p-4">
					<div class="flex items-center gap-2">
						<Server class="h-4 w-4 text-[var(--accent)]" />
						<h2 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Clusters</h2>
					</div>
					<p class="mt-2 text-2xl font-bold text-[var(--text-bright)]">{clustersAll.length}</p>
					<p class="mt-1 text-xs text-[var(--text-muted)]">Reporting agents</p>
				</article>
				<article class="metric-card p-4">
					<div class="flex items-center gap-2">
						<Container class="h-4 w-4 text-[var(--blue)]" />
						<h2 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Images</h2>
					</div>
					<p class="mt-2 text-2xl font-bold text-[var(--text-bright)]">{totalImages}</p>
					<p class="mt-1 text-xs text-[var(--text-muted)]">Unique by digest</p>
				</article>
				<article class="metric-card p-4">
					<div class="flex items-center gap-2">
						<Container class="h-4 w-4 text-[var(--green)]" />
						<h2 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Containers</h2>
					</div>
					<p class="mt-2 text-2xl font-bold text-[var(--text-bright)]">{totalContainers}</p>
					<p class="mt-1 text-xs text-[var(--text-muted)]">Running instances</p>
				</article>
				<article class="metric-card p-4">
					<div class="flex items-center gap-2">
						<Globe class="h-4 w-4 text-[var(--red)]" />
						<h2 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Hosts</h2>
					</div>
					<p class="mt-2 text-2xl font-bold text-[var(--text-bright)]">{uniqueHosts}</p>
					<p class="mt-1 text-xs text-[var(--text-muted)]">Unique hostnames</p>
				</article>
			</div>

			<!-- Charts -->
			<div class="grid gap-6 lg:grid-cols-2">
				{#if registryTotal > 0}
					<div class="metric-card rounded-2xl p-5">
						<DonutChart title="Registry distribution" total={registryTotal} segments={registrySegments} />
					</div>
				{/if}
				{#if exposureTotal > 0}
					<div class="metric-card rounded-2xl p-5">
						<DonutChart title="Network exposure" total={exposureTotal} segments={exposureSegments} />
					</div>
				{/if}
			</div>

			<!-- Tab selector -->
			<TabSelector
				bind:value={activeTab}
				options={[
					{ value: 'clusters', label: 'Clusters' },
					{ value: 'images', label: 'Images' },
					{ value: 'hosts', label: 'Hosts' }
				]}
			/>
		{/if}
	</section>

	<!-- Tables -->
	{#if !loading && !error && clustersAll.length > 0}
		{#if activeTab === 'clusters'}
			<section class="panel-surface space-y-4 px-6 py-6 sm:px-10 sm:py-8" style:min-height={clusterDrawerOpen ? '80vh' : undefined}>
				<header class="flex items-start justify-between gap-4">
					<div>
						<h2 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Clusters</h2>
						<p class="text-sm text-[var(--text-tertiary)]">
							Reporting SCAM agents and their inventory.
							{#if clusterActiveFilterCount > 0}
								<span class="text-[var(--text-muted)]">&middot; showing {clusters.length} of {clustersAll.length}</span>
							{/if}
						</p>
					</div>
					<button
						type="button"
						class="host-filter-toggle"
						class:active={clusterFilterOpen}
						onclick={() => (clusterFilterOpen = !clusterFilterOpen)}
						aria-expanded={clusterFilterOpen}
						aria-label="Toggle filters"
					>
						<SlidersHorizontal size={14} />
						<span>Filters</span>
						{#if clusterActiveFilterCount > 0}
							<span class="host-filter-badge">{clusterActiveFilterCount}</span>
						{/if}
					</button>
				</header>

				{#if clusterFilterOpen}
					<div transition:slide={{ duration: 220, easing: cubicOut }} class="pb-2">
						<div class="flex flex-wrap items-start gap-6">
							<div class="flex flex-col gap-1">
								<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Search</span>
								<div class="relative flex items-center">
									<Search size={13} class="pointer-events-none absolute left-2.5 text-[var(--text-muted)]" />
									<input
										type="text"
										class="host-search-input"
										placeholder="Cluster name, environment…"
										bind:value={clusterSearch}
									/>
								</div>
							</div>

							<div class="flex flex-col gap-1">
								<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Activity</span>
								<div class="flex items-center h-[28px]">
									<Toggle bind:checked={includeInactive} label="Show inactive (>24h)" />
								</div>
							</div>

							{#if clusterActiveFilterCount > 0}
								<div class="flex items-center gap-3 ml-auto" style="padding-top: calc(0.65rem * 1.2 + 0.25rem);">
									<button type="button" class="host-clear-filters" onclick={clearClusterFilters}>Clear all</button>
								</div>
							{/if}
						</div>
					</div>
				{/if}

				{#if clusters.length === 0 && clusterActiveFilterCount > 0}
					<div class="flex flex-col items-center justify-center gap-3 py-16">
						<Search class="h-10 w-10 text-[var(--text-muted)]" />
						<p class="text-base font-medium text-[var(--text-secondary)]">{clusterSearch.trim() ? `No clusters match “${clusterSearch.trim()}”` : 'No clusters match your filters'}</p>
						<p class="text-sm text-[var(--text-muted)]">Try a different search term or clear the filter.</p>
						<button type="button" class="mt-2 host-clear-filters" onclick={clearClusterFilters}>Clear all filters</button>
					</div>
				{:else}
				<div class="overflow-auto" style="max-height: 70vh;" bind:this={clusterScrollEl} onscroll={() => { clusterScrollTop = clusterScrollEl?.scrollTop ?? 0; clusterViewH = clusterScrollEl?.clientHeight ?? 600; }}>
					<table class="min-w-full table-fixed divide-y divide-[var(--border-color)]/30 text-sm">
						<thead class="sticky top-0 z-[1] bg-[var(--card-bg)] text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
							<tr>
								<th class="sortable-th w-[28%] px-5 py-3 text-left" onclick={sc('cluster')}>Cluster <ChevronDown class="sort-icon {clusterSortKey === 'cluster' ? 'active' : ''} {clusterSortKey === 'cluster' && clusterSortDir === 'asc' ? 'flipped' : ''}" /></th>
								<th class="sortable-th w-[15%] px-5 py-3 text-left" onclick={sc('environment')}>Environment <ChevronDown class="sort-icon {clusterSortKey === 'environment' ? 'active' : ''} {clusterSortKey === 'environment' && clusterSortDir === 'asc' ? 'flipped' : ''}" /></th>
								<th class="sortable-th w-[10%] px-5 py-3 text-right" onclick={sc('images')}>Images <ChevronDown class="sort-icon {clusterSortKey === 'images' ? 'active' : ''} {clusterSortKey === 'images' && clusterSortDir === 'asc' ? 'flipped' : ''}" /></th>
								<th class="sortable-th w-[12%] px-5 py-3 text-right" onclick={sc('containers')}>Containers <ChevronDown class="sort-icon {clusterSortKey === 'containers' ? 'active' : ''} {clusterSortKey === 'containers' && clusterSortDir === 'asc' ? 'flipped' : ''}" /></th>
								<th class="sortable-th w-[12%] px-5 py-3 text-right" onclick={sc('namespaces')}>Namespaces <ChevronDown class="sort-icon {clusterSortKey === 'namespaces' ? 'active' : ''} {clusterSortKey === 'namespaces' && clusterSortDir === 'asc' ? 'flipped' : ''}" /></th>
								<th class="sortable-th w-[10%] px-5 py-3 text-right" onclick={sc('ingress_count')}>Routes <ChevronDown class="sort-icon {clusterSortKey === 'ingress_count' ? 'active' : ''} {clusterSortKey === 'ingress_count' && clusterSortDir === 'asc' ? 'flipped' : ''}" /></th>
								<th class="sortable-th w-[13%] px-5 py-3 text-left" onclick={sc('last_seen')}>Last seen <ChevronDown class="sort-icon {clusterSortKey === 'last_seen' ? 'active' : ''} {clusterSortKey === 'last_seen' && clusterSortDir === 'asc' ? 'flipped' : ''}" /></th>
							</tr>
						</thead>
						<tbody class="text-[var(--text-secondary)]">
							{#if clusterVirt.topPad > 0}<tr style="height:{clusterVirt.topPad}px"><td colspan="7"></td></tr>{/if}
							{#each sortedClusters.slice(clusterVirt.start, clusterVirt.end) as c}
								<tr class="cursor-pointer border-b border-[var(--border-color)]/15 transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)] {clusterDrawerOpen && clusterDrawerRow?.cluster_id === c.cluster_id ? 'bg-[var(--hover-bg-subtle)]' : ''}" style="height:{ROW_HEIGHT}px;max-height:{ROW_HEIGHT}px" onclick={() => openClusterDrawer(c)}>
									<td class="px-5 py-3 font-semibold text-[var(--text-bright)]">{c.cluster || c.cluster_id}</td>
									<td class="px-5 py-3">
										{#if c.environment}
											<span class="rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs">{c.environment}</span>
										{:else}
											<span class="text-[var(--text-muted)]">&mdash;</span>
										{/if}
									</td>
									<td class="px-5 py-3 text-right font-semibold">{c.images}</td>
									<td class="px-5 py-3 text-right">{c.containers}</td>
									<td class="px-5 py-3 text-right">{c.namespaces}</td>
									<td class="px-5 py-3 text-right">{c.ingress_count}</td>
									<td class="px-5 py-3 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">{timeAgo(c.last_seen, tick)}</td>
								</tr>
							{/each}
							{#if clusterVirt.bottomPad > 0}<tr style="height:{clusterVirt.bottomPad}px"><td colspan="7"></td></tr>{/if}
						</tbody>
					</table>
				</div>
				{/if}

				{#if clusterDrawerOpen && clusterDrawerRow}
					<div
						class="fixed top-2 bottom-2 right-2 z-50 flex w-[780px] flex-col overflow-hidden rounded-[10px] border border-[var(--border-color)] bg-[var(--bg-soft)] shadow-xl"
						transition:slide={{ duration: 220, easing: cubicOut, axis: 'x' }}
					>
						<ClusterChainDrawer
							cluster={clusterDrawerRow.cluster}
							clusterId={clusterDrawerRow.cluster_id}
							onClose={() => { clusterDrawerOpen = false; clusterDrawerRow = null; }}
						/>
					</div>
				{/if}
			</section>
		{:else if activeTab === 'images'}
			<section class="panel-surface space-y-4 px-6 py-6 sm:px-10 sm:py-8" style:min-height={imageDrawerOpen ? '80vh' : undefined}>
				{#if imageDetails.length > 0 || imageActiveFilterCount > 0 || imagesFetched || imagesInFlight}
					<header class="flex items-start justify-between gap-4">
						<div>
							<h2 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Images</h2>
							<p class="text-sm text-[var(--text-tertiary)]">
								Container images across all clusters.
								{#if imageActiveFilterCount > 0}
									<span class="text-[var(--text-muted)]">&middot; {imageTotal} matching</span>
								{/if}
							</p>
						</div>
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
							{#if imageActiveFilterCount > 0}
								<span class="host-filter-badge">{imageActiveFilterCount}</span>
							{/if}
						</button>
					</header>

					{#if imageFilterOpen}
						<div transition:slide={{ duration: 220, easing: cubicOut }} class="pb-2">
							<div class="flex flex-wrap items-start gap-6">
								<div class="flex flex-col gap-1">
									<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Search</span>
									<div class="relative flex items-center">
										<Search size={13} class="pointer-events-none absolute left-2.5 text-[var(--text-muted)]" />
										<input
											type="text"
											class="host-search-input"
											placeholder="Image name, tag, digest…"
											bind:value={imageSearch}
										/>
									</div>
								</div>

								<div class="flex flex-col gap-1">
									<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Registry</span>
									<MultiSelect bind:selected={imageSelectedRegistries} options={imageRegistryOptions} placeholder="All registries" size="sm" />
								</div>

								{#if imageActiveFilterCount > 0}
									<div class="flex items-center gap-3 ml-auto" style="padding-top: calc(0.65rem * 1.2 + 0.25rem);">
										<button type="button" class="host-clear-filters" onclick={clearImageFilters}>Clear all</button>
									</div>
								{/if}
							</div>
						</div>
					{/if}
				{/if}

				{#if imageDetails.length === 0 && (imagesInFlight || !imagesFetched)}
					<Loading message="Loading images" variant="spinner" size="md" />
				{:else if imageDetails.length === 0 && imageActiveFilterCount > 0}
					<div class="flex flex-col items-center justify-center gap-3 py-16">
						<Search class="h-10 w-10 text-[var(--text-muted)]" />
						<p class="text-base font-medium text-[var(--text-secondary)]">No images match your filters</p>
						<p class="text-sm text-[var(--text-muted)]">Adjust the filters above or clear them to see every image.</p>
						<button type="button" class="mt-2 host-clear-filters" onclick={clearImageFilters}>Clear all filters</button>
					</div>
				{:else if imageDetails.length === 0}
					<div class="flex flex-col items-center justify-center gap-3 py-16">
						<Container class="h-10 w-10 text-[var(--yellow)]" />
						<p class="text-base font-medium text-[var(--text-secondary)]">No images</p>
						<p class="text-sm text-[var(--text-muted)]">No container images with resolved digests yet.</p>
					</div>
				{:else}
					<div class="overflow-auto [overflow-anchor:none]" style="max-height: 70vh;" bind:this={imageScrollEl} onscroll={() => {
						imageScrollTop = imageScrollEl?.scrollTop ?? 0;
						imageViewH = imageScrollEl?.clientHeight ?? 600;
						// Infinite scroll: when the viewport is within ~10
						// rows of the bottom of the rendered list, fetch
						// the next page. The guard inside loadMoreImages
						// keeps rapid scroll from fanning out fetches.
						if (imageHasMore && !imageLoadingMore) {
							// "Near bottom of loaded rows" — gauge by the loaded
							// count, not the true total, because the scroll
							// container extends to imageTotal but unloaded
							// rows past imageDetails.length are blank padding.
							// Trigger when we approach the loaded boundary.
							const loadedContentH = imageDetails.length * ROW_HEIGHT;
							const distanceToLoaded = loadedContentH - imageScrollTop - imageViewH;
							if (distanceToLoaded < ROW_HEIGHT * 10) loadMoreImages();
						}
					}}>
					<table class="min-w-full table-fixed divide-y divide-[var(--border-color)]/30 text-sm">
							<thead class="sticky top-0 z-[1] bg-[var(--card-bg)] text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
								<tr>
									<th class="sortable-th w-[12%] px-5 py-3 text-left" onclick={si('registry')}>Registry <ChevronDown class="sort-icon {imageSortKey === 'registry' ? 'active' : ''} {imageSortKey === 'registry' && imageSortDir === 'asc' ? 'flipped' : ''}" /></th>
									<th class="sortable-th w-[min(22%,368px)] px-5 py-3 text-left" onclick={si('image')}>Image <ChevronDown class="sort-icon {imageSortKey === 'image' ? 'active' : ''} {imageSortKey === 'image' && imageSortDir === 'asc' ? 'flipped' : ''}" /></th>
									<th class="w-[12%] px-5 py-3 text-left">Digest</th>
									<th class="w-[12%] px-5 py-3 text-left">Tags</th>
									<th class="sortable-th w-[12%] px-5 py-3 text-left" onclick={si('vulns')}>Vulns <ChevronDown class="sort-icon {imageSortKey === 'vulns' ? 'active' : ''} {imageSortKey === 'vulns' && imageSortDir === 'asc' ? 'flipped' : ''}" /></th>
									<th class="sortable-th w-[9%] px-5 py-3 text-right" onclick={si('cluster_count')}>Clusters <ChevronDown class="sort-icon {imageSortKey === 'cluster_count' ? 'active' : ''} {imageSortKey === 'cluster_count' && imageSortDir === 'asc' ? 'flipped' : ''}" /></th>
									<th class="sortable-th w-[10%] px-5 py-3 text-right" onclick={si('container_count')}>Containers <ChevronDown class="sort-icon {imageSortKey === 'container_count' ? 'active' : ''} {imageSortKey === 'container_count' && imageSortDir === 'asc' ? 'flipped' : ''}" /></th>
									<th class="sortable-th w-[11%] px-5 py-3 text-left" onclick={si('last_seen')}>Deployed at <ChevronDown class="sort-icon {imageSortKey === 'last_seen' ? 'active' : ''} {imageSortKey === 'last_seen' && imageSortDir === 'asc' ? 'flipped' : ''}" /></th>
								</tr>
							</thead>
							<tbody class="text-[var(--text-secondary)]">
								{#if imageVirt.topPad > 0}<tr style="height:{imageVirt.topPad}px"><td colspan="8"></td></tr>{/if}
								{#each sortedImages.slice(imageVirt.start, imageVirt.end) as img}
									<tr
										class="border-b border-[var(--border-color)]/15 transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)] {img.digest_id ? 'cursor-pointer' : ''} {imageDrawerOpen && imageDrawerId === img.digest_id ? 'bg-[var(--hover-bg-subtle)]' : ''}"
										style="height:{ROW_HEIGHT}px;max-height:{ROW_HEIGHT}px"
										onclick={() => { if (img.digest_id) openImageDrawer(img.digest_id); }}
									>
										<td class="truncate px-5 py-3 text-xs text-[var(--text-tertiary)]" title={img.registry}>{img.registry}</td>
										<td class="truncate px-0 py-3 font-semibold text-[var(--text-bright)]" title={img.image}>
											{#if img.digest_id}
												<a class="hover:text-[var(--accent)] hover:underline" href={`/images/${img.digest_id}`} onclick={(e) => e.stopPropagation()}>{img.image}</a>
											{:else}
												{img.image}
											{/if}
										</td>
										<td class="px-5 py-3">
											{#if img.digest}
												<code class="rounded bg-[var(--hover-bg)] px-1.5 py-0.5 text-xs text-[var(--text-secondary)]">{shortDigest(img.digest)}</code>
											{:else}
												<span class="text-xs text-[var(--text-muted)]" title="The kubelet has not resolved a digest for this image. This typically happens when the image was pulled from a local cache (imagePullPolicy: IfNotPresent) or the container hasn't started yet.">unresolved</span>
											{/if}
										</td>
										<td class="overflow-hidden px-5 py-3">
											<div class="flex flex-nowrap gap-1 overflow-hidden">
												{#each parseTags(img.tags) as tag}
													<span class="whitespace-nowrap rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs text-[var(--text-secondary)]">{tag}</span>
												{/each}
											</div>
										</td>
										<td class="px-5 py-3">
											{#if (img.vuln_critical + img.vuln_high + img.vuln_medium + img.vuln_low + img.vuln_unknown) === 0}
												<span class="text-xs text-[var(--text-muted)]">—</span>
											{:else}
												<div
													class="vuln-cell inline-flex items-center gap-1.5 font-mono tabular-nums text-xs"
													onmouseenter={(e) => vulnTooltipFromCell(e.currentTarget as HTMLElement, img)}
													onmouseleave={hideVulnTooltip}
												>
													<span class={img.vuln_critical > 0 ? 'text-red-400 font-semibold' : 'text-[var(--text-muted)]'}>{img.vuln_critical}</span>
													<span class="text-[var(--text-muted)]">·</span>
													<span class={img.vuln_high > 0 ? 'text-orange-400 font-semibold' : 'text-[var(--text-muted)]'}>{img.vuln_high}</span>
													<span class="text-[var(--text-muted)]">·</span>
													<span class={img.vuln_medium > 0 ? 'text-amber-400' : 'text-[var(--text-muted)]'}>{img.vuln_medium}</span>
													<span class="text-[var(--text-muted)]">·</span>
													<span class={img.vuln_low > 0 ? 'text-sky-400' : 'text-[var(--text-muted)]'}>{img.vuln_low}</span>
												</div>
											{/if}
										</td>
										<td class="px-5 py-3 text-right">{img.cluster_count}</td>
										<td class="px-5 py-3 text-right font-semibold">{img.container_count}</td>
										<td class="px-5 py-3 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
											<span
												class="date-cell"
												onmouseenter={(e) => dateTooltipFromCell(e.currentTarget as HTMLElement, img.last_seen)}
												onmouseleave={hideDateTooltip}
											>{timeAgo(img.last_seen, tick)}</span>
										</td>
									</tr>
								{/each}
								{#if imageVirt.bottomPad > 0}<tr style="height:{imageVirt.bottomPad}px"><td colspan="8"></td></tr>{/if}
							</tbody>
						</table>
						{#if imageLoadingMore}
							<div class="flex items-center justify-center gap-2 py-3 text-xs text-[var(--text-muted)]">
								<div class="h-3 w-3 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
								<span>Loading more images…</span>
							</div>
						{:else if !imageHasMore && imageDetails.length >= IMAGE_PAGE_SIZE}
							<div class="py-3 text-center text-xs text-[var(--text-muted)]">All {imageDetails.length} images loaded.</div>
						{/if}
					</div>
				{/if}

				{#if imageDrawerOpen && imageDrawerId}
					<div
						class="fixed top-2 bottom-2 right-2 z-50 flex w-[620px] flex-col overflow-hidden rounded-[10px] border border-[var(--border-color)] bg-[var(--bg-soft)] shadow-xl"
						transition:slide={{ duration: 220, easing: cubicOut, axis: 'x' }}
					>
						<ImageDrawer
							imageId={imageDrawerId}
							onClose={() => { imageDrawerOpen = false; imageDrawerId = null; }}
						/>
					</div>
				{/if}
			</section>
		{:else if activeTab === 'hosts'}
			<section class="panel-surface space-y-4 px-6 py-6 sm:px-10 sm:py-8" style:min-height={chainDrawerOpen ? '80vh' : undefined}>
				{#if hosts.length > 0 || hostActiveFilterCount > 0 || hostsFetched || hostsInFlight}
					<header class="flex items-start justify-between gap-4">
						<div>
							<h2 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Hosts</h2>
							<p class="text-sm text-[var(--text-tertiary)]">
								Hostnames exposed via Ingress and route resources.
								{#if hostActiveFilterCount > 0}
									<span class="text-[var(--text-muted)]">&middot; {hostSummary.total} matching</span>
								{/if}
							</p>
						</div>
						<button
							type="button"
							class="host-filter-toggle"
							class:active={hostFilterOpen}
							onclick={() => (hostFilterOpen = !hostFilterOpen)}
							aria-expanded={hostFilterOpen}
							aria-label="Toggle filters"
						>
							<SlidersHorizontal size={14} />
							<span>Filters</span>
							{#if hostActiveFilterCount > 0}
								<span class="host-filter-badge">{hostActiveFilterCount}</span>
							{/if}
						</button>
					</header>

					{#if hostFilterOpen}
						<div transition:slide={{ duration: 220, easing: cubicOut }} class="pb-2">
							<div class="flex flex-wrap items-start gap-6">
								<div class="flex flex-col gap-1">
									<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Search</span>
									<div class="relative flex items-center">
										<Search size={13} class="pointer-events-none absolute left-2.5 text-[var(--text-muted)]" />
										<input
											type="text"
											class="host-search-input"
											placeholder="Host, cluster, backend, namespace…"
											bind:value={hostSearch}
										/>
									</div>
								</div>

								<div class="flex flex-col gap-1">
									<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Cluster</span>
									<MultiSelect bind:selected={hostSelectedClusters} options={hostClusterOptions} placeholder="All clusters" size="sm" />
								</div>

								<div class="flex flex-col gap-1">
									<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Namespace</span>
									<MultiSelect bind:selected={hostSelectedNamespaces} options={hostNamespaceOptions} placeholder="All namespaces" size="sm" />
								</div>

								<div class="flex flex-col gap-1">
									<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Kind</span>
									<MultiSelect bind:selected={hostSelectedKinds} options={hostKindOptions} placeholder="All kinds" size="sm" />
								</div>

								<div class="flex flex-col gap-1">
									<span class="text-[0.65rem] font-semibold uppercase tracking-[0.12em] text-[var(--text-tertiary)] pl-0.5">Workloads</span>
									<div class="flex items-center h-[28px]">
										<Toggle bind:checked={hostActiveWorkloadsOnly} label="Active only" />
									</div>
								</div>

								{#if hostActiveFilterCount > 0}
									<div class="flex items-center gap-3 ml-auto" style="padding-top: calc(0.65rem * 1.2 + 0.25rem);">
										<button
											type="button"
											class="host-clear-filters"
											onclick={clearHostFilters}
										>
											Clear all
										</button>
									</div>
								{/if}
							</div>
						</div>
					{/if}
				{/if}

				{#if hosts.length === 0 && (hostsInFlight || !hostsFetched)}
					<Loading message="Loading hosts" variant="spinner" size="md" />
				{:else if hosts.length === 0 && hostActiveFilterCount > 0}
					<div class="flex flex-col items-center justify-center gap-3 py-16">
						<Search class="h-10 w-10 text-[var(--text-muted)]" />
						<p class="text-base font-medium text-[var(--text-secondary)]">No hosts match your filters</p>
						<p class="text-sm text-[var(--text-muted)]">Adjust the filters above or clear them to see every host.</p>
						<button type="button" class="mt-2 host-clear-filters" onclick={clearHostFilters}>Clear all filters</button>
					</div>
				{:else if hosts.length === 0}
					<div class="flex flex-col items-center justify-center gap-3 py-16">
						<Globe class="h-10 w-10 text-[var(--yellow)]" />
						<p class="text-base font-medium text-[var(--text-secondary)]">No hosts</p>
						<p class="text-sm text-[var(--text-muted)]">No exposed FQDNs found from Ingress or route resources.</p>
					</div>
				{:else}
					<div class="overflow-auto [overflow-anchor:none]" style="max-height: 70vh;" bind:this={hostScrollEl} onscroll={() => { hostScrollTop = hostScrollEl?.scrollTop ?? 0; hostViewH = hostScrollEl?.clientHeight ?? 600; }}>
						<table class="min-w-full table-fixed divide-y divide-[var(--border-color)]/30 text-sm">
							<thead class="sticky top-0 z-[1] bg-[var(--card-bg)] text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
								<tr>
									<th class="w-[48px] py-3 pl-5 pr-0"></th>
									<th class="sortable-th w-[30%] px-5 py-3 text-left" onclick={sh('host')}>Host <ChevronDown class="sort-icon {hostSortKey === 'host' ? 'active' : ''} {hostSortKey === 'host' && hostSortDir === 'asc' ? 'flipped' : ''}" /></th>
									<th class="w-[22%] px-5 py-3 text-left">IP</th>
									<th class="sortable-th w-[15%] px-5 py-3 text-left" onclick={sh('namespace')}>Namespace <ChevronDown class="sort-icon {hostSortKey === 'namespace' ? 'active' : ''} {hostSortKey === 'namespace' && hostSortDir === 'asc' ? 'flipped' : ''}" /></th>
									<th class="sortable-th w-[17%] px-5 py-3 text-left" onclick={sh('name')}>Name <ChevronDown class="sort-icon {hostSortKey === 'name' ? 'active' : ''} {hostSortKey === 'name' && hostSortDir === 'asc' ? 'flipped' : ''}" /></th>
									<th class="sortable-th w-[16%] px-5 py-3 text-left" onclick={sh('cluster')}>Cluster <ChevronDown class="sort-icon {hostSortKey === 'cluster' ? 'active' : ''} {hostSortKey === 'cluster' && hostSortDir === 'asc' ? 'flipped' : ''}" /></th>
								</tr>
							</thead>
							<tbody class="text-[var(--text-secondary)]">
								{#if hostVirt.topPad > 0}<tr style="height:{hostVirt.topPad}px"><td colspan="6"></td></tr>{/if}
								{#each sortedHosts.slice(hostVirt.start, hostVirt.end) as h}
									{@const resolved = hostResolutions[h.host]}
									{@const meta = hostMetas[h.host]}
									<tr class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)] {chainDrawerOpen && chainDrawerRow?.host === h.host && chainDrawerRow?.cluster_id === h.cluster_id ? 'bg-[var(--hover-bg-subtle)]' : ''}" style="height:{HOST_ROW_HEIGHT}px;max-height:{HOST_ROW_HEIGHT}px;{h.backends && h.workload_count === 0 ? ' opacity: 0.4;' : ''}" onclick={() => openChainDrawer(h)}>
										<td class="w-12 py-3 pl-5 pr-0">
											<div class="flex h-7 w-7 items-center justify-center">
												{#if meta?.has_favicon}
													<img
														src={faviconProxyUrl(h.host)}
														alt=""
														class="h-6 w-6 rounded"
													/>
												{/if}
											</div>
										</td>
										<td class="px-5 py-3">
											<div class="min-w-0">
												<span class="inline-flex items-center gap-1.5">
													<span class="font-semibold text-[var(--text-bright)]">{h.host}</span>
													<a
														href={hostUrl(h.host, h.tls)}
														target="_blank"
														rel="noopener noreferrer"
														class="text-[var(--text-muted)] transition-colors hover:text-[var(--accent)]"
													><ExternalLink class="h-3 w-3" /></a>
												</span>
												{#if meta?.title}
													<div class="mt-0.5 truncate text-xs text-[var(--text-tertiary)]">{meta.title}</div>
												{/if}
											</div>
										</td>
										<td class="px-5 py-3 text-xs overflow-hidden">
											<div class="flex items-center gap-3 overflow-hidden">
												<span class="w-6 text-[10px] uppercase tracking-wider text-[var(--text-tertiary)]">lb</span>
												{#if h.lb_ips}
													<code class="truncate text-[var(--text-secondary)]" title={h.lb_ips}>{h.lb_ips}</code>
													{#if !(resolved && !resolved.error)}
														{#if isPrivateIP(h.lb_ips.split(',')[0].trim())}
															<span class="rounded-full bg-[var(--blue)]/15 px-1.5 py-0.5 text-[10px] font-medium text-[var(--blue)]">local</span>
														{:else}
															<span class="rounded-full bg-[var(--green)]/15 px-1.5 py-0.5 text-[10px] font-medium text-[var(--green)]">external</span>
														{/if}
													{/if}
												{:else}
													<span class="text-[var(--text-tertiary)]">&mdash;</span>
												{/if}
											</div>
											<div class="mt-1 flex items-center gap-3">
												<span class="w-6 text-[10px] uppercase tracking-wider text-[var(--text-tertiary)]">dns</span>
												{#if resolved}
													{#if resolved.error}
														<span class="text-[var(--text-tertiary)]">unresolvable</span>
													{:else}
														<code class="text-[var(--text-secondary)]">{resolved.ips[0]}</code>
														{#if resolved.is_local}
															<span class="rounded-full bg-[var(--blue)]/15 px-1.5 py-0.5 text-[10px] font-medium text-[var(--blue)]">local</span>
														{:else}
															<span class="rounded-full bg-[var(--green)]/15 px-1.5 py-0.5 text-[10px] font-medium text-[var(--green)]">external</span>
														{/if}
													{/if}
												{:else}
													<span class="inline-block h-3 w-16 animate-pulse rounded bg-[var(--bg3)]/40"></span>
												{/if}
											</div>
										</td>
										<td class="px-5 py-3">{h.namespace}</td>
										<td class="px-5 py-3">{h.name}</td>
										<td class="px-5 py-3">{h.cluster || h.cluster_id}</td>
									</tr>
								{/each}
								{#if hostVirt.bottomPad > 0}<tr style="height:{hostVirt.bottomPad}px"><td colspan="6"></td></tr>{/if}
							</tbody>
						</table>
					</div>
				{/if}

				{#if chainDrawerOpen && chainDrawerRow}
					<div
						class="fixed top-2 bottom-2 right-2 z-50 flex w-[780px] flex-col overflow-hidden rounded-[10px] border border-[var(--border-color)] bg-[var(--bg-soft)] shadow-xl"
						transition:slide={{ duration: 220, easing: cubicOut, axis: 'x' }}
					>
						<HostChainDrawer
							host={chainDrawerRow.host}
							clusterId={chainDrawerRow.cluster_id}
							namespace={chainDrawerRow.namespace}
							kind={chainDrawerRow.kind}
							name={chainDrawerRow.name}
							onClose={() => { chainDrawerOpen = false; chainDrawerRow = null; }}
						/>
					</div>
				{/if}
			</section>
		{/if}
	{/if}

</div>

<DeployScamDialog bind:open={deployDialogOpen} />

<!-- Date tooltip for "Deployed at" cells. Top-level so it escapes
     the images table's scroll overflow. -->
{#if dateTooltip}
	{@const d = dateTooltip}
	<div
		class="pointer-events-none fixed z-[60] -translate-x-1/2 -translate-y-full rounded-lg border border-[var(--border-color)] bg-[var(--bg-soft)] px-3 py-2 shadow-xl"
		style="left: {d.x}px; top: {d.y - 8}px;"
	>
		<div class="mb-1 text-[10px] uppercase tracking-[0.2em] text-[var(--text-tertiary)]">Deployed at</div>
		<div class="font-mono text-xs tabular-nums text-[var(--text-bright)]">{formatFullDate(d.iso)}</div>
	</div>
{/if}

<!-- Vuln tooltip. Top-level so it escapes the scroll overflow of the
     images table; position:fixed anchored to the hovered cell. -->
{#if vulnTooltip}
	{@const t = vulnTooltip}
	<div
		class="pointer-events-none fixed z-[60] -translate-x-1/2 -translate-y-full rounded-lg border border-[var(--border-color)] bg-[var(--bg-soft)] px-3 py-2 shadow-xl"
		style="left: {t.x}px; top: {t.y - 8}px;"
	>
		<div class="mb-1 text-[10px] uppercase tracking-[0.2em] text-[var(--text-tertiary)]">Vulnerabilities</div>
		<div class="grid grid-cols-[auto_auto] gap-x-3 gap-y-0.5 font-mono text-xs tabular-nums">
			<span class="text-red-400">Critical</span><span class="text-right text-[var(--text-bright)]">{t.img.vuln_critical}</span>
			<span class="text-orange-400">High</span><span class="text-right text-[var(--text-bright)]">{t.img.vuln_high}</span>
			<span class="text-amber-400">Medium</span><span class="text-right text-[var(--text-bright)]">{t.img.vuln_medium}</span>
			<span class="text-sky-400">Low</span><span class="text-right text-[var(--text-bright)]">{t.img.vuln_low}</span>
			{#if t.img.vuln_unknown > 0}
				<span class="text-[var(--text-secondary)]">Unknown</span><span class="text-right text-[var(--text-bright)]">{t.img.vuln_unknown}</span>
			{/if}
		</div>
	</div>
{/if}

<style>
	.sortable-th {
		cursor: pointer;
		user-select: none;
		white-space: nowrap;
		transition: color 150ms ease;
	}

	.date-cell {
		cursor: help;
		border-bottom: 1px dotted transparent;
		transition: border-color 120ms ease;
	}

	.date-cell:hover {
		border-bottom-color: var(--text-tertiary);
	}

	.sortable-th:hover {
		color: var(--text-bright);
	}

	:global(.sort-icon) {
		display: inline-block;
		width: 12px;
		height: 12px;
		vertical-align: middle;
		visibility: hidden;
		transition: transform 150ms ease;
	}

	:global(.sort-icon.active) {
		visibility: visible;
	}

	:global(.sort-icon.flipped) {
		transform: rotate(180deg);
	}

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

	.host-search-input::placeholder {
		color: var(--text-muted);
	}

	.host-search-input:focus {
		outline: none;
		border-color: var(--accent);
		box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 30%, transparent);
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

	.loading-bar {
		position: relative;
		width: 35%;
		animation: slide 2s linear infinite alternate;
	}

	@keyframes slide {
		0% {
			left: 0%;
			transform: translateX(-95%);
		}
		100% {
			left: 100%;
			transform: translateX(-5%);
		}
	}
</style>
