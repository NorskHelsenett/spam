<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { page } from '$app/stores';
	import {
		ArrowLeft,
		Server,
		Container,
		Globe,
		Boxes,
		Layers,
		Network,
		Clock,
		ShieldAlert,
		ChevronRight,
		ChevronDown,
		Route,
		ExternalLink,
		ShieldX,
		Shield
	} from 'lucide-svelte';
	import Loading from '$lib/components/Loading.svelte';
	import DonutChart from '$lib/components/DonutChart.svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';
	import VulnBadges from '$lib/components/VulnBadges.svelte';
	import ClusterMap from '$lib/components/ClusterMap.svelte';

	type ContainerVuln = {
		critical: number;
		high: number;
		medium: number;
		low: number;
		total: number;
		kev: number;
		epss: number;
	};
	type ContainerInfo = {
		name: string;
		image: string;
		tag: string;
		digest?: string;
		registry: string;
		vuln?: ContainerVuln;
	};
	type WorkloadGroup = {
		namespace: string;
		owner: string;
		owner_kind: string;
		pod_count: number;
		phase: string;
		containers: ContainerInfo[];
	};
	type NamespaceSummary = {
		namespace: string;
		workloads: number;
		pods: number;
		services: number;
		hosts: number;
	};
	type HostEntry = {
		namespace: string;
		host: string;
		kind: string;
		tls: boolean;
		ingress_class?: string;
	};
	type ClusterDetail = {
		cluster_id: string;
		display_name: string;
		cluster_name?: string;
		ror_metadata?: { slug?: string; cluster_name?: string; env?: string };
		environment?: string;
		last_seen?: string;
		counts: {
			containers: number;
			images: number;
			namespaces: number;
			ingresses: number;
			workloads: number;
			pods: number;
			services: number;
			hosts: number;
		};
		security: {
			critical: number;
			high: number;
			medium: number;
			low: number;
			unknown: number;
			total: number;
		};
		namespaces: NamespaceSummary[];
		workloads: WorkloadGroup[];
		hosts: HostEntry[];
	};

	let detail = $state<ClusterDetail | null>(null);
	let loading = $state(true);
	let error = $state('');
	let tab = $state('namespaces');

	const load = async () => {
		const id = $page.params.id;
		if (!id) {
			error = 'No cluster id in URL';
			loading = false;
			return;
		}
		loading = true;
		error = '';
		try {
			const res = await fetch(`/api/cluster/${encodeURIComponent(id)}`, {
				credentials: 'include'
			});
			if (res.ok) {
				detail = (await res.json()) as ClusterDetail;
			} else if (res.status === 404) {
				error = 'Cluster not found';
			} else {
				error = 'Failed to load cluster data';
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load cluster data';
		} finally {
			loading = false;
		}
	};

	onMount(() => {
		if (browser) load();
	});

	// Self-updating relative clock — `timeAgo` reads `now`, so ticking it
	// on a timer re-renders "Last seen Xm ago" without a reload. 30s keeps
	// the minute-resolution label honest. (A relative label doesn't need a
	// server push; SSE would only matter to refresh last_seen itself.)
	let now = $state(Date.now());
	onMount(() => {
		if (!browser) return;
		const t = setInterval(() => (now = Date.now()), 30_000);
		return () => clearInterval(t);
	});

	const fmt = (n: number | null | undefined) =>
		(n ?? 0).toLocaleString('en-US').replace(/,/g, ' ');

	const timeAgo = (iso: string | undefined) => {
		if (!iso) return '';
		const diff = now - new Date(iso).getTime();
		const mins = Math.floor(diff / 60000);
		if (mins < 1) return 'just now';
		if (mins < 60) return `${mins}m ago`;
		const hours = Math.floor(mins / 60);
		if (hours < 24) return `${hours}h ago`;
		return `${Math.floor(hours / 24)}d ago`;
	};

	// Mini open-graph for exposed hosts. The favicon comes straight from
	// the cached favicon endpoint as an <img src>; the title is fetched
	// lazily from /meta the first time a namespace carrying that host is
	// expanded, then cached per host so re-expands are free.
	type HostMeta = { title?: string; has_favicon?: boolean };
	let hostMeta = $state<Record<string, HostMeta>>({});
	const faviconSrc = (host: string) =>
		`/api/clusters/hosts/favicon?host=${encodeURIComponent(host)}`;
	const loadHostMeta = async (host: string) => {
		if (!host || host in hostMeta) return;
		hostMeta = { ...hostMeta, [host]: {} }; // placeholder dedupes in-flight
		try {
			const res = await fetch(`/api/clusters/hosts/meta?host=${encodeURIComponent(host)}`, {
				credentials: 'include'
			});
			if (res.ok) {
				const m = await res.json();
				hostMeta = { ...hostMeta, [host]: { title: m.title, has_favicon: m.has_favicon } };
			}
		} catch {
			// leave the placeholder; the favicon img + raw host still render
		}
	};

	// Link a container to its image profile page (keyed on the digest).
	const imageHref = (c: ContainerInfo) =>
		c.digest ? `/images/${encodeURIComponent(c.digest)}` : null;

	// EPSS is a 0..1 probability; render as a percentage.
	const epssPct = (epss: number) =>
		epss >= 0.1 ? `${Math.round(epss * 100)}%` : `${(epss * 100).toFixed(1)}%`;

	// --- Vulnerabilities tab (lazy) ---
	// Advisories affecting this cluster's running images, grouped by
	// canonical CVE. Loaded the first time the tab is opened, mirroring how
	// /vulnerabilities lazy-loads its findings — keeps the main page fast.
	type ClusterVuln = {
		vuln_id: string;
		severity: string;
		title?: string;
		description?: string;
		has_fix: boolean;
		image_count: number;
		package_count: number;
		kev: boolean;
		epss: number;
	};
	let vulns = $state<ClusterVuln[] | null>(null);
	let vulnsTruncated = $state(false);
	let vulnsLoading = $state(false);
	let vulnsError = $state('');
	const loadVulns = async () => {
		if (vulns !== null || vulnsLoading) return;
		const id = $page.params.id;
		if (!id) return;
		vulnsLoading = true;
		vulnsError = '';
		try {
			const res = await fetch(`/api/cluster/${encodeURIComponent(id)}/vulnerabilities`, {
				credentials: 'include'
			});
			if (res.ok) {
				const data = await res.json();
				vulns = (data.items ?? []) as ClusterVuln[];
				vulnsTruncated = !!data.truncated;
			} else {
				vulnsError = 'Failed to load vulnerabilities';
			}
		} catch {
			vulnsError = 'Failed to load vulnerabilities';
		} finally {
			vulnsLoading = false;
		}
	};

	// Map tab keeps the component mounted after first open (hidden via CSS)
	// so switching tabs doesn't refetch the chain payload or reset the view.
	let mapMounted = $state(false);

	// "Extremely vulnerable" placeholder heuristic for the map's red shield
	// badges, until a real risk score exists: the image carries a KEV-listed
	// vuln with high EPSS, and its namespace exposes a domain. Keyed by
	// namespace/digest so the same image in an unexposed namespace stays
	// unflagged.
	const EPSS_HIGH = 0.5;
	const riskyKeys = $derived.by(() => {
		const keys = new Set<string>();
		if (!detail) return keys;
		const exposedNs = new Set(detail.hosts.map((h) => h.namespace));
		for (const wl of detail.workloads) {
			if (!exposedNs.has(wl.namespace)) continue;
			for (const c of wl.containers) {
				if (c.digest && c.vuln && c.vuln.kev > 0 && c.vuln.epss >= EPSS_HIGH) {
					keys.add(`${wl.namespace}/${c.digest}`);
				}
			}
		}
		return keys;
	});

	// Lazy work tied to the active tab: warm host open-graph meta when the
	// Hosts tab opens, fetch advisories when the Vulnerabilities tab opens,
	// mount the map the first time it's shown.
	$effect(() => {
		if (tab === 'hosts' && detail) {
			for (const h of detail.hosts) loadHostMeta(h.host);
		} else if (tab === 'vulnerabilities') {
			void loadVulns();
		} else if (tab === 'map') {
			mapMounted = true;
		}
	});

	// Internal advisory page (lands on affected assets); upstream is a
	// secondary external link next to the id — mirrors /vulnerabilities.
	const vulnHref = (id: string) => `/vuln/${encodeURIComponent(id)}`;
	const vulnUpstreamUrl = (id: string) => {
		if (id.startsWith('CVE-')) return `https://www.cve.org/CVERecord?id=${id}`;
		if (id.startsWith('GHSA-')) return `https://github.com/advisories/${id}`;
		return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
	};
	const sevCardClass = (s: string) => {
		switch ((s || '').toUpperCase()) {
			case 'CRITICAL':
				return 'border-red-500/30 bg-red-500/5';
			case 'HIGH':
				return 'border-orange-500/30 bg-orange-500/5';
			case 'MEDIUM':
				return 'border-yellow-500/30 bg-yellow-500/5';
			default:
				return 'border-[var(--border-color)]/50';
		}
	};
	const sevIconComp = (s: string) => {
		switch ((s || '').toUpperCase()) {
			case 'CRITICAL':
				return ShieldX;
			case 'HIGH':
				return ShieldAlert;
			default:
				return Shield;
		}
	};
	const sevColor = (s: string) => {
		switch ((s || '').toUpperCase()) {
			case 'CRITICAL':
				return 'text-red-400';
			case 'HIGH':
				return 'text-orange-400';
			case 'MEDIUM':
				return 'text-yellow-400';
			default:
				return 'text-[var(--text-muted)]';
		}
	};

	// Security donut segments — severity → gruvbox accent, matching the
	// colours used across the vuln surfaces. Zero-value tiers are dropped
	// so the donut and legend stay legible.
	const securitySegments = $derived(
		detail
			? [
					{ label: 'Critical', value: detail.security.critical, color: 'var(--red)' },
					{ label: 'High', value: detail.security.high, color: 'var(--orange)' },
					{ label: 'Medium', value: detail.security.medium, color: 'var(--yellow)' },
					{ label: 'Low', value: detail.security.low, color: 'var(--blue)' },
					{ label: 'Unknown', value: detail.security.unknown, color: 'var(--gray)' }
				].filter((s) => s.value > 0)
			: []
	);

	const tabOptions = $derived([
		{ value: 'namespaces', label: `Namespaces (${detail?.namespaces.length ?? 0})` },
		{ value: 'map', label: 'Map' },
		{ value: 'hosts', label: `Hosts (${detail?.hosts.length ?? 0})` },
		{
			value: 'vulnerabilities',
			label: vulns
				? `Vulnerabilities (${vulns.length}${vulnsTruncated ? '+' : ''})`
				: 'Vulnerabilities'
		}
	]);

	const metricCards = $derived(
		detail
			? [
					{ label: 'Containers', value: fmt(detail.counts.containers), icon: Container },
					{ label: 'Images', value: fmt(detail.counts.images), icon: Boxes },
					{ label: 'Workloads', value: fmt(detail.counts.workloads), icon: Layers },
					{ label: 'Namespaces', value: fmt(detail.counts.namespaces), icon: Server },
					{ label: 'Ingresses', value: fmt(detail.counts.ingresses), icon: Globe },
					{ label: 'Hosts', value: fmt(detail.counts.hosts), icon: Network }
				]
			: []
	);

	const imageLabel = (c: ContainerInfo) => {
		const base = c.registry && c.registry !== 'Docker Hub' ? `${c.registry}/${c.image}` : c.image;
		return c.tag ? `${base}:${c.tag}` : base;
	};

	// Expandable namespace rows — clicking a namespace drills into its
	// running workloads (with containers) and exposed routes. All the data
	// is already in the payload, so we just slice it per namespace.
	let expandedNs = $state<Record<string, boolean>>({});
	const toggleNs = (ns: string) => {
		const open = !expandedNs[ns];
		expandedNs = { ...expandedNs, [ns]: open };
		// Warm the open-graph cache for the hosts in this namespace.
		if (open && detail) {
			for (const h of detail.hosts) {
				if (h.namespace === ns) loadHostMeta(h.host);
			}
		}
	};

	// host_exposure kinds split into the two families the drill-down shows:
	// classic Ingress (incl. Traefik IngressRoute) vs Gateway-API routes.
	const INGRESS_KINDS = new Set(['Ingress', 'IngressRoute', 'IngressRouteTCP']);
	const ROUTE_KINDS = new Set(['HTTPRoute', 'GRPCRoute', 'TLSRoute']);

	// Reverse-DNS ordering: compare hosts by their dot-labels reversed, so
	// rows group under a shared parent domain — the apex first, then its
	// children ordered by subdomain. e.g. example.com, a.example.com,
	// b.example.com, then api.other.org, other.org. A shared label prefix
	// means the shorter (parent) name sorts ahead of its children.
	const byDomain = (a: HostEntry, b: HostEntry) => {
		const ra = a.host.toLowerCase().split('.').reverse();
		const rb = b.host.toLowerCase().split('.').reverse();
		const n = Math.min(ra.length, rb.length);
		for (let i = 0; i < n; i++) {
			if (ra[i] !== rb[i]) return ra[i] < rb[i] ? -1 : 1;
		}
		if (ra.length !== rb.length) return ra.length - rb.length;
		return a.namespace.localeCompare(b.namespace) || a.kind.localeCompare(b.kind);
	};
	const sortedHosts = $derived(detail ? [...detail.hosts].sort(byDomain) : []);

	const nsWorkloads = (ns: string) =>
		detail ? detail.workloads.filter((w) => w.namespace === ns) : [];
	const nsIngresses = (ns: string) =>
		detail
			? detail.hosts.filter((h) => h.namespace === ns && INGRESS_KINDS.has(h.kind)).sort(byDomain)
			: [];
	const nsRoutes = (ns: string) =>
		detail
			? detail.hosts.filter((h) => h.namespace === ns && ROUTE_KINDS.has(h.kind)).sort(byDomain)
			: [];
</script>

<svelte:head>
	<title>{detail?.display_name ?? $page.params.id} &middot; Spam Monitor</title>
</svelte:head>

{#snippet exposureRow(h: HostEntry, showNs: boolean)}
	{@const meta = hostMeta[h.host]}
	<a
		href={(h.tls ? 'https://' : 'http://') + h.host}
		target="_blank"
		rel="noopener noreferrer"
		class="group flex items-center gap-3 rounded-lg px-3 py-2 transition-colors hover:bg-[var(--hover-bg)]/40"
	>
		<img
			src={faviconSrc(h.host)}
			alt=""
			loading="lazy"
			class="h-7 w-7 shrink-0 rounded bg-[var(--bg-surface)] object-contain p-0.5"
			onerror={(e) => ((e.currentTarget as HTMLImageElement).style.visibility = 'hidden')}
		/>
		<div class="min-w-0 flex-1">
			<div class="flex items-center gap-1.5 leading-none">
				<span
					class="truncate font-mono text-[12px] text-[var(--text-secondary)] group-hover:text-[var(--text-bright)]"
				>
					{h.host}
				</span>
				<ExternalLink
					size={11}
					class="shrink-0 text-[var(--text-muted)] opacity-0 transition-opacity group-hover:opacity-100"
				/>
			</div>
			{#if meta?.title}
				<p class="truncate text-[11px] text-[var(--text-muted)]">{meta.title}</p>
			{/if}
		</div>
		<div class="flex shrink-0 items-center gap-2">
			{#if showNs}
				<span class="hidden font-mono text-[11px] text-[var(--text-muted)] sm:inline">{h.namespace}</span>
			{/if}
			{#if h.ingress_class}
				<span class="hidden text-[11px] text-[var(--text-muted)] sm:inline">{h.ingress_class}</span>
			{/if}
			<span
				class="rounded-full border border-[var(--border-color)] px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-[var(--text-muted)]"
			>
				{h.kind}
			</span>
			{#if h.tls}
				<span class="text-[11px] text-[var(--green)]">TLS</span>
			{/if}
		</div>
	</a>
{/snippet}

<div class="space-y-6 sm:space-y-8">
	<nav>
		<a
			href="/clusters"
			class="inline-flex items-center gap-2 text-sm leading-none text-[var(--text-secondary)] transition hover:text-[var(--accent)]"
		>
			<ArrowLeft class="h-4 w-4" /> Back
		</a>
	</nav>

	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
			<div class="min-w-0">
				<h1
					class="flex items-center gap-3 text-2xl font-semibold leading-none text-[var(--text-bright)] sm:text-3xl"
				>
					<Server size={22} class="text-[var(--accent)]" />
					<span class="truncate">{detail?.display_name ?? $page.params.id}</span>
				</h1>
				<div class="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-[var(--text-tertiary)]">
					{#if detail?.environment}
						<span>Environment: <span class="text-[var(--text-secondary)]">{detail.environment}</span></span>
					{/if}
					{#if detail?.ror_metadata?.slug}
						<span>ROR: <span class="text-[var(--text-secondary)]">{detail.ror_metadata.slug}</span></span>
					{/if}
				</div>
				<p class="mt-1 font-mono text-[10px] text-[var(--text-muted)]" title="cluster_id">
					{detail?.cluster_id ?? $page.params.id}
				</p>
			</div>
			{#if detail?.last_seen}
				<div class="flex items-center gap-1.5 text-xs leading-none text-[var(--text-muted)]">
					<Clock size={12} /> Last seen {timeAgo(detail.last_seen)}
				</div>
			{/if}
		</header>

		{#if loading}
			<Loading message="Loading cluster" variant="spinner" size="md" />
		{:else if error}
			<div class="flex flex-col items-center justify-center gap-2 py-12">
				<p class="text-base font-medium text-[var(--text-secondary)]">{error}</p>
				<a href="/clusters" class="mt-2 text-sm text-[var(--accent)] hover:underline">Back to clusters</a>
			</div>
		{:else if detail}
			<div class="grid gap-6 lg:grid-cols-3">
				<!-- Security findings donut -->
				<div class="metric-card flex flex-col rounded-2xl border border-[var(--border-color)]/60 p-5">
					<div class="flex items-center gap-2 text-xs uppercase leading-none tracking-[0.2em] text-[var(--text-muted)]">
						<ShieldAlert size={13} class="text-[var(--accent)]" /> Security findings
					</div>
					{#if detail.security.total > 0}
						<div class="mt-2">
							<DonutChart
								title=""
								total={detail.security.total}
								segments={securitySegments}
							/>
						</div>
					{:else}
						<div class="flex flex-1 flex-col items-center justify-center gap-1 py-8 text-center">
							<p class="text-2xl font-semibold text-[var(--green)]">0</p>
							<p class="text-xs text-[var(--text-tertiary)]">No findings in running images</p>
						</div>
					{/if}
				</div>

				<!-- Metric cards -->
				<div class="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:col-span-2">
					{#each metricCards as card (card.label)}
						<div class="metric-card rounded-2xl border border-[var(--border-color)]/60 p-4">
							<div class="flex items-center gap-1.5 text-[10px] uppercase leading-none tracking-[0.18em] text-[var(--text-muted)]">
								<card.icon size={12} /> {card.label}
							</div>
							<p class="mt-2 text-2xl font-semibold text-[var(--text-bright)]">{card.value}</p>
						</div>
					{/each}
				</div>
			</div>

			<div class="pt-2">
				<TabSelector options={tabOptions} bind:value={tab} />
			</div>
		{/if}
	</section>

	{#if !loading && !error && detail}
		<section class="panel-surface px-4 py-6 sm:px-8 sm:py-8">
			<!-- Map stays mounted (hidden) after first open so tab switches
			     don't refetch the chain payload or reset pan/zoom. -->
			{#if mapMounted}
				<div class={tab === 'map' ? '' : 'hidden'}>
					<ClusterMap clusterId={detail.cluster_id} {riskyKeys} />
				</div>
			{/if}

			{#if tab === 'namespaces'}
				{#if detail.namespaces.length === 0}
					<p class="py-10 text-center text-sm text-[var(--text-tertiary)]">No namespaces found.</p>
				{:else}
					<div class="overflow-x-auto rounded-xl border border-[var(--border-color)]/40">
						<table class="w-full text-sm">
							<thead>
								<tr class="border-b border-[var(--border-color)]/40 text-left text-[10px] uppercase tracking-[0.18em] text-[var(--text-muted)]">
									<th class="px-4 py-2.5 font-medium">Namespace</th>
									<th class="px-4 py-2.5 text-right font-medium">Workloads</th>
									<th class="px-4 py-2.5 text-right font-medium">Pods</th>
									<th class="px-4 py-2.5 text-right font-medium">Services</th>
									<th class="px-4 py-2.5 text-right font-medium">Hosts</th>
								</tr>
							</thead>
							<tbody>
								{#each detail.namespaces as ns (ns.namespace)}
									{@const open = expandedNs[ns.namespace]}
									{@const wls = nsWorkloads(ns.namespace)}
									{@const ings = nsIngresses(ns.namespace)}
									{@const routes = nsRoutes(ns.namespace)}
									<tr
										class="border-b border-[var(--border-color)]/20 last:border-0 {open
											? 'bg-[var(--hover-bg)]/30'
											: 'hover:bg-[var(--hover-bg)]/40'}"
									>
										<td class="px-2 py-0">
											<button
												type="button"
												class="flex w-full items-center gap-2 px-2 py-2.5 text-left font-medium leading-none text-[var(--text-secondary)] transition-colors hover:text-[var(--text-bright)]"
												aria-expanded={open}
												onclick={() => toggleNs(ns.namespace)}
											>
												{#if open}
													<ChevronDown size={14} class="shrink-0 text-[var(--text-muted)]" />
												{:else}
													<ChevronRight size={14} class="shrink-0 text-[var(--text-muted)]" />
												{/if}
												<span class="truncate">{ns.namespace}</span>
											</button>
										</td>
										<td class="px-4 py-2.5 text-right text-[var(--text-tertiary)]">{fmt(ns.workloads)}</td>
										<td class="px-4 py-2.5 text-right text-[var(--text-tertiary)]">{fmt(ns.pods)}</td>
										<td class="px-4 py-2.5 text-right text-[var(--text-tertiary)]">{fmt(ns.services)}</td>
										<td class="px-4 py-2.5 text-right text-[var(--text-tertiary)]">{fmt(ns.hosts)}</td>
									</tr>
									{#if open}
										<tr class="border-b border-[var(--border-color)]/20 last:border-0">
											<td colspan="5" class="bg-[var(--hover-bg)]/15 px-4 pb-5 pt-1 sm:px-6">
												<div class="space-y-5 sm:pl-4">
													{#if ings.length === 0 && routes.length === 0 && wls.length === 0}
														<p class="text-xs text-[var(--text-muted)]">Nothing running in this namespace.</p>
													{/if}

													<!-- Ingresses — only when present -->
													{#if ings.length > 0}
														<div>
															<div class="mb-2 flex items-center gap-1.5 text-[10px] uppercase leading-none tracking-[0.18em] text-[var(--text-muted)]">
																<Globe size={12} /> Ingresses ({ings.length})
															</div>
															<div class="flex flex-col gap-1.5">
																{#each ings as h, i (h.kind + '/' + h.host + '#' + i)}
																	{@render exposureRow(h, false)}
																{/each}
															</div>
														</div>
													{/if}

													<!-- HTTPRoutes — only when present -->
													{#if routes.length > 0}
														<div>
															<div class="mb-2 flex items-center gap-1.5 text-[10px] uppercase leading-none tracking-[0.18em] text-[var(--text-muted)]">
																<Route size={12} /> HTTPRoutes ({routes.length})
															</div>
															<div class="flex flex-col gap-1.5">
																{#each routes as h, i (h.kind + '/' + h.host + '#' + i)}
																	{@render exposureRow(h, false)}
																{/each}
															</div>
														</div>
													{/if}

													<!-- Workloads + containers -->
													{#if wls.length > 0}
														<div>
															<div class="mb-2 flex items-center gap-1.5 text-[10px] uppercase leading-none tracking-[0.18em] text-[var(--text-muted)]">
																<Layers size={12} /> Workloads ({wls.length})
															</div>
															<div class="space-y-1.5">
																{#each wls as wl (wl.owner_kind + '/' + wl.owner)}
																	<div class="rounded-lg border border-[var(--border-color)]/40 px-3 py-2">
																		<div class="flex flex-wrap items-center gap-2">
																			<span class="text-sm font-medium text-[var(--text-secondary)]">{wl.owner || '—'}</span>
																			<span class="rounded-full border border-[var(--border-color)] px-1.5 py-0.5 text-[9px] uppercase tracking-wide text-[var(--text-muted)]">{wl.owner_kind || '—'}</span>
																			<span class="text-[11px] text-[var(--text-muted)]">{fmt(wl.pod_count)} {wl.pod_count === 1 ? 'pod' : 'pods'}</span>
																		</div>
																		{#if wl.containers.length}
																			<div class="mt-1.5 flex flex-col gap-1.5 border-t border-[var(--border-color)]/30 pt-1.5">
																				{#each wl.containers as c (c.name + c.image)}
																					{@const href = imageHref(c)}
																					<div class="flex flex-wrap items-baseline gap-x-2 gap-y-1 leading-none">
																						<Container size={11} class="shrink-0 self-center text-[var(--text-muted)]" />
																						<span class="text-xs text-[var(--text-tertiary)]">{c.name}</span>
																						{#if href}
																							<a
																								{href}
																								class="inline-flex items-baseline gap-1 font-mono text-[11px] text-[var(--accent)] hover:underline"
																							>
																								{imageLabel(c)}
																								<ExternalLink size={10} class="opacity-60" />
																							</a>
																						{:else}
																							<span class="font-mono text-[11px] text-[var(--text-muted)]">{imageLabel(c)}</span>
																						{/if}
																						{#if c.vuln && c.vuln.total > 0}
																							<span class="ml-1 inline-flex flex-wrap items-baseline gap-x-2 gap-y-1">
																								<VulnBadges
																									critical={c.vuln.critical}
																									high={c.vuln.high}
																									medium={c.vuln.medium}
																									low={c.vuln.low}
																									size="sm"
																								/>
																								<span class="text-[10px] text-[var(--text-muted)]">{fmt(c.vuln.total)} total</span>
																								{#if c.vuln.kev > 0}
																									<span
																										class="inline-flex items-center gap-0.5 rounded bg-red-500/15 px-1.5 py-0.5 text-[10px] font-semibold leading-none text-red-400"
																										title="In the CISA Known Exploited Vulnerabilities catalog"
																									>
																										<ShieldX class="h-3 w-3" /> KEV {c.vuln.kev}
																									</span>
																								{/if}
																								{#if c.vuln.epss > 0}
																									<span
																										class="text-[10px] text-[var(--text-muted)]"
																										title="Max EPSS — modeled probability of exploitation in the next 30 days"
																									>
																										EPSS {epssPct(c.vuln.epss)}
																									</span>
																								{/if}
																							</span>
																						{/if}
																					</div>
																				{/each}
																			</div>
																		{/if}
																	</div>
																{/each}
															</div>
														</div>
													{/if}
												</div>
											</td>
										</tr>
									{/if}
								{/each}
							</tbody>
						</table>
					</div>
				{/if}
			{:else if tab === 'hosts'}
				{#if detail.hosts.length === 0}
					<p class="py-10 text-center text-sm text-[var(--text-tertiary)]">No exposed hosts found.</p>
				{:else}
					<div class="flex flex-col gap-1.5">
						{#each sortedHosts as h, i (h.namespace + '/' + h.kind + '/' + h.host + '#' + i)}
							{@render exposureRow(h, true)}
						{/each}
					</div>
				{/if}
			{:else if tab === 'vulnerabilities'}
				{#if vulnsLoading}
					<Loading message="Loading vulnerabilities" variant="spinner" size="md" />
				{:else if vulnsError}
					<p class="py-10 text-center text-sm text-[var(--text-tertiary)]">{vulnsError}</p>
				{:else if !vulns || vulns.length === 0}
					<p class="py-10 text-center text-sm text-[var(--text-tertiary)]">
						No vulnerabilities found in running images.
					</p>
				{:else}
					<p class="mb-3 text-xs leading-none text-[var(--text-muted)]">
						Advisories affecting images running in this cluster, grouped by CVE.{vulnsTruncated
							? ` Showing the top ${fmt(vulns.length)}.`
							: ''}
					</p>
					<div class="flex flex-col gap-2">
						{#each vulns as v (v.vuln_id)}
							{@const Icon = sevIconComp(v.severity)}
							<div class="rounded-xl border {sevCardClass(v.severity)} px-4 py-3">
								<div class="flex flex-wrap items-center gap-x-2 gap-y-1 leading-none">
									<Icon class="h-3.5 w-3.5 shrink-0 {sevColor(v.severity)}" />
									<a
										href={vulnHref(v.vuln_id)}
										class="font-mono text-sm font-semibold text-[var(--text-bright)] hover:text-[var(--accent)] hover:underline"
									>
										{v.vuln_id}
									</a>
									<a
										href={vulnUpstreamUrl(v.vuln_id)}
										target="_blank"
										rel="noopener noreferrer"
										class="text-[var(--text-muted)] transition-colors hover:text-[var(--text-secondary)]"
										title="Open upstream advisory"
									>
										<ExternalLink size={12} />
									</a>
									<span
										class="rounded-full border px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wide {sevColor(
											v.severity
										)}"
									>
										{v.severity}
									</span>
									{#if v.kev}
										<span
											class="inline-flex items-center gap-0.5 rounded bg-red-500/15 px-1.5 py-0.5 text-[10px] font-semibold leading-none text-red-400"
											title="In the CISA Known Exploited Vulnerabilities catalog"
										>
											<ShieldX class="h-3 w-3" /> KEV
										</span>
									{/if}
									{#if v.epss > 0}
										<span
											class="text-[10px] text-[var(--text-muted)]"
											title="Max EPSS — modeled probability of exploitation in the next 30 days"
										>
											EPSS {epssPct(v.epss)}
										</span>
									{/if}
									<span class="ml-auto text-[10px] text-[var(--text-muted)]">
										{fmt(v.image_count)}
										{v.image_count === 1 ? 'image' : 'images'}{v.has_fix ? ' · fix available' : ''}
									</span>
								</div>
								{#if v.title}
									<p class="mt-1.5 text-xs text-[var(--text-secondary)]">{v.title}</p>
								{/if}
								{#if v.description}
									<p class="mt-1 line-clamp-2 text-[11px] leading-relaxed text-[var(--text-muted)]">
										{v.description}
									</p>
								{/if}
							</div>
						{/each}
					</div>
				{/if}
			{/if}
		</section>
	{/if}
</div>
