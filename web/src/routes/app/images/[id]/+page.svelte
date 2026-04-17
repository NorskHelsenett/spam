<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { page } from '$app/stores';
	import { ArrowLeft, Container, ExternalLink, Loader2, XCircle, CheckCircle, Clock, Server, History, GitBranch } from 'lucide-svelte';
	import ImageScanDetail from '$lib/components/ImageScanDetail.svelte';

	type LinkedRepo = {
		repo_id: string;
		provider: string;
		org: string;
		slug: string;
		base_url?: string;
		provider_id?: string;
		source?: string;
		revision?: string;
	};

	type ScanHistoryRow = {
		job_id: string;
		status: string;
		created_at: string;
		finished_at?: string;
		vuln_count: number;
	};

	type ClusterUsageRow = {
		cluster: string;
		namespace: string;
		pod_count: number;
		first_seen: string;
		last_seen: string;
	};

	type ImageDetail = {
		id: string;
		registry: string;
		repository: string;
		digest: string;
		created_at: string;
		linked_repo?: LinkedRepo;
		scan_history?: ScanHistoryRow[];
		latest_scan_id?: string;
		cluster_usage?: ClusterUsageRow[];
	};

	let image: ImageDetail | null = $state(null);
	let latestScan: any = $state(null);
	let loading = $state(true);
	let error = $state('');

	const shortDigest = (digest: string) => {
		const i = digest.indexOf(':');
		if (i < 0) return digest;
		return digest.slice(0, i + 13);
	};

	const statusIcon = (s: string) => {
		switch (s) {
			case 'SUCCEEDED': return CheckCircle;
			case 'FAILED':    return XCircle;
			case 'RUNNING':   return Loader2;
			default:          return Clock;
		}
	};
	const statusColor = (s: string) => {
		switch (s) {
			case 'SUCCEEDED': return 'var(--success)';
			case 'FAILED':    return 'var(--error)';
			case 'RUNNING':   return 'var(--accent)';
			default:          return 'var(--text-tertiary)';
		}
	};

	const copyText = async (text: string) => {
		try { await navigator.clipboard.writeText(text); } catch { /* ignore */ }
	};

	const loadImage = async () => {
		const id = $page.params.id;
		if (!id) return;
		try {
			const res = await fetch(`/api/images/${id}`, { credentials: 'include' });
			if (!res.ok) {
				error = res.status === 404 ? 'Image not found' : 'Failed to load image';
				return;
			}
			image = await res.json();
			if (image?.latest_scan_id) {
				const scanRes = await fetch(`/api/runs/${image.latest_scan_id}`, { credentials: 'include' });
				if (scanRes.ok) latestScan = await scanRes.json();
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load image';
		} finally {
			loading = false;
		}
	};

	onMount(() => { if (browser) loadImage(); });

	const formatDate = (iso: string) => new Date(iso).toLocaleString();
	const formatDuration = (start: string, end?: string) => {
		const s = new Date(start).getTime();
		const e = end ? new Date(end).getTime() : Date.now();
		const secs = Math.max(0, Math.floor((e - s) / 1000));
		if (secs < 60) return `${secs}s`;
		const m = Math.floor(secs / 60);
		return `${m}m ${secs % 60}s`;
	};
</script>

<svelte:head>
	<title>{image ? `${image.registry}/${image.repository}` : 'Image'} • Spam</title>
</svelte:head>

<div class="space-y-6">
	<button type="button" class="inline-flex items-center gap-2 text-sm text-[var(--text-secondary)] transition hover:text-[var(--accent)]" onclick={() => history.back()}>
		<ArrowLeft class="h-4 w-4" />
		Back
	</button>

	{#if loading}
		<div class="flex items-center justify-center py-20"><Loader2 class="h-8 w-8 animate-spin text-[var(--accent)]" /></div>
	{:else if error}
		<div class="panel-surface p-8 text-center">
			<XCircle class="mx-auto h-12 w-12 text-[var(--error)]" />
			<p class="mt-4 text-[var(--text-secondary)]">{error}</p>
		</div>
	{:else if image}
		<!-- Image header -->
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-6">
			<div class="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
				<div class="min-w-0 flex-1">
					<div class="mb-2 flex items-center gap-2 text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
						<Container size={14} />
						<span>Container image</span>
					</div>
					<h1 class="break-all text-2xl font-semibold text-[var(--text-bright)]">
						{image.registry}/{image.repository}
					</h1>
					<div class="mt-2 flex flex-wrap items-center gap-2 text-xs text-[var(--text-tertiary)]">
						<code class="rounded bg-[var(--hover-bg-subtle)] px-2 py-0.5 font-mono">{shortDigest(image.digest)}</code>
						<button type="button" class="btn btn-ghost btn-xs" onclick={() => copyText(image!.digest)} title="Copy full digest">Copy</button>
					</div>
					<div class="mt-2 text-xs text-[var(--text-tertiary)]">First seen: {formatDate(image.created_at)}</div>
				</div>
				{#if image.linked_repo}
					<a
						class="btn btn-secondary btn-sm"
						href={`/app/providers/repo?repo_id=${image.linked_repo.repo_id}${image.linked_repo.provider_id ? `&provider_id=${image.linked_repo.provider_id}` : ''}`}
					>
						<GitBranch class="h-4 w-4" />
						{image.linked_repo.org}/{image.linked_repo.slug}
						<ExternalLink class="h-3 w-3" />
					</a>
				{/if}
			</div>
		</div>

		<!-- Cluster usage -->
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-6">
			<header class="mb-3 flex items-center gap-2">
				<Server size={16} />
				<h2 class="text-sm font-semibold text-[var(--text-bright)]">Where this image runs</h2>
				<span class="text-xs text-[var(--text-tertiary)]">
					{image.cluster_usage?.length ?? 0} namespace{(image.cluster_usage?.length ?? 0) === 1 ? '' : 's'}
				</span>
			</header>
			{#if !image.cluster_usage || image.cluster_usage.length === 0}
				<p class="py-4 text-center text-sm text-[var(--text-tertiary)]">Not observed in any cluster yet.</p>
			{:else}
				<div class="overflow-hidden rounded-lg border border-[var(--border-color)]/40">
					<table class="min-w-full divide-y divide-[var(--border-color)]/40 text-xs">
						<thead class="text-[10px] uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
							<tr>
								<th class="px-3 py-2 text-left">Cluster</th>
								<th class="px-3 py-2 text-left">Namespace</th>
								<th class="px-3 py-2 text-right">Pods</th>
								<th class="px-3 py-2 text-left">First seen</th>
								<th class="px-3 py-2 text-left">Last seen</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-[var(--border-color)]/20 text-[var(--text-secondary)]">
							{#each image.cluster_usage as u}
								<tr class="hover:bg-[var(--hover-bg-subtle)]">
									<td class="px-3 py-1.5 font-mono text-[var(--text-bright)]">{u.cluster || '-'}</td>
									<td class="px-3 py-1.5 font-mono">{u.namespace || '-'}</td>
									<td class="px-3 py-1.5 text-right">{u.pod_count}</td>
									<td class="px-3 py-1.5">{formatDate(u.first_seen)}</td>
									<td class="px-3 py-1.5">{formatDate(u.last_seen)}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</div>

		<!-- Scan history -->
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-6">
			<header class="mb-3 flex items-center gap-2">
				<History size={16} />
				<h2 class="text-sm font-semibold text-[var(--text-bright)]">Scan history</h2>
				<span class="text-xs text-[var(--text-tertiary)]">
					{image.scan_history?.length ?? 0} run{(image.scan_history?.length ?? 0) === 1 ? '' : 's'}
				</span>
			</header>
			{#if !image.scan_history || image.scan_history.length === 0}
				<p class="py-4 text-center text-sm text-[var(--text-tertiary)]">No scans for this digest yet.</p>
			{:else}
				<div class="overflow-hidden rounded-lg border border-[var(--border-color)]/40">
					<table class="min-w-full divide-y divide-[var(--border-color)]/40 text-xs">
						<thead class="text-[10px] uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
							<tr>
								<th class="px-3 py-2 text-left">Run</th>
								<th class="px-3 py-2 text-left">Status</th>
								<th class="px-3 py-2 text-right">Vulns</th>
								<th class="px-3 py-2 text-left">Created</th>
								<th class="px-3 py-2 text-left">Duration</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-[var(--border-color)]/20 text-[var(--text-secondary)]">
							{#each image.scan_history as s}
								{@const Icon = statusIcon(s.status)}
								<tr class="cursor-pointer hover:bg-[var(--hover-bg-subtle)]" onclick={() => location.assign(`/app/runs/${s.job_id}`)}>
									<td class="px-3 py-1.5 font-mono text-[var(--text-bright)]">
										<a class="hover:underline" href={`/app/runs/${s.job_id}`} onclick={(e) => e.stopPropagation()}>{s.job_id.slice(0, 8)}</a>
									</td>
									<td class="px-3 py-1.5">
										<span class="inline-flex items-center gap-1" style={`color: ${statusColor(s.status)}`}>
											<Icon size={14} class={s.status === 'RUNNING' ? 'animate-spin' : ''} />
											{s.status}
										</span>
									</td>
									<td class="px-3 py-1.5 text-right font-mono">{s.vuln_count}</td>
									<td class="px-3 py-1.5">{formatDate(s.created_at)}</td>
									<td class="px-3 py-1.5 font-mono">{s.finished_at ? formatDuration(s.created_at, s.finished_at) : '-'}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</div>

		<!-- Latest scan — full detail inline, reusing the scan detail component -->
		{#if latestScan}
			<div class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
				Latest scan · <a class="text-[var(--accent)] hover:underline" href={`/app/runs/${latestScan.id}`}>open run</a>
			</div>
			<ImageScanDetail run={latestScan} />
		{:else}
			<p class="text-sm text-[var(--text-tertiary)]">No successful scan yet — findings will appear here once one completes.</p>
		{/if}
	{/if}
</div>
