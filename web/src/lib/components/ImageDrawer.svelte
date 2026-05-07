<script lang="ts">
	import { X, Container, ExternalLink, ShieldAlert, GitBranch } from 'lucide-svelte';

	type LinkedRepo = {
		repo_id: string;
		provider: string;
		org: string;
		slug: string;
		base_url?: string;
		provider_id?: string;
		source: string;
		revision?: string;
	};

	type Contributor = {
		login?: string;
		name?: string;
		email?: string;
		avatar_url?: string;
		profile_url?: string;
		contributions?: number;
	};

	type ScanHistoryRow = {
		job_id: string;
		status: string;
		created_at: string;
		finished_at?: string;
		vuln_count: number;
	};

	type ClusterUsage = {
		cluster: string;
		namespace: string;
		pod_count: number;
		first_seen: string;
		last_seen: string;
	};

	type VulnSeverity = {
		critical: number;
		high: number;
		medium: number;
		low: number;
		unknown: number;
		total: number;
	};

	type ImageDetail = {
		id: string;
		registry: string;
		repository: string;
		digest: string;
		created_at: string;
		linked_repo?: LinkedRepo;
		linked_repo_contributors?: Contributor[];
		scan_history?: ScanHistoryRow[];
		latest_scan_id?: string;
		vuln_severity?: VulnSeverity;
		cluster_usage?: ClusterUsage[];
	};

	let {
		imageId,
		onClose = () => {}
	}: {
		imageId: string;
		onClose?: () => void;
	} = $props();

	let detail: ImageDetail | null = $state(null);
	let loading = $state(true);
	let error = $state('');

	$effect(() => {
		if (!imageId) return;
		loading = true;
		error = '';
		detail = null;
		fetch(`/api/images/${imageId}`, { credentials: 'include' })
			.then((r) => {
				if (!r.ok) throw new Error(`${r.status}`);
				return r.json();
			})
			.then((data) => {
				detail = data;
			})
			.catch((e) => {
				error = e.message || 'Failed to load';
			})
			.finally(() => {
				loading = false;
			});
	});

	const shortDigest = (d?: string) => (d ? d.slice(0, 20) + '…' : '—');
	const fmtDate = (s?: string) => (s ? new Date(s).toLocaleString() : '—');

	const repoDeepLink = (lr: LinkedRepo) => {
		const params = new URLSearchParams({
			provider: lr.provider,
			path: `${lr.org}/${lr.slug}`,
		});
		if (lr.base_url) params.set('base_url', lr.base_url);
		if (lr.provider_id) params.set('provider_id', lr.provider_id);
		return `/providers/repo?${params.toString()}`;
	};
</script>

<div class="flex h-full flex-col overflow-hidden rounded-l-[10px] bg-[var(--bg-soft)]">
	<!-- Header -->
	<div class="shrink-0 pb-2 pl-7 pr-7 pt-7">
		<div class="flex items-start gap-3">
			<Container class="mt-0.5 h-5 w-5 shrink-0 text-[var(--accent)]" />
			<div class="min-w-0 flex-1">
				<h3 class="truncate text-base font-semibold text-[var(--text-bright)]">
					{detail ? `${detail.registry}/${detail.repository}` : 'Image'}
				</h3>
				<p class="mt-0.5 font-mono text-xs text-[var(--text-tertiary)]">
					{detail ? shortDigest(detail.digest) : '—'}
				</p>
			</div>
			<a
				class="flex h-8 items-center gap-1.5 rounded-lg border border-[var(--border-color)]/60 px-2.5 text-xs text-[var(--text-secondary)] transition hover:border-[var(--accent)]/40 hover:text-[var(--accent)]"
				href={`/images/${imageId}`}
				title="Open full image page"
			>
				Full page
				<ExternalLink class="h-3 w-3" />
			</a>
			<button
				type="button"
				class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition hover:bg-[var(--hover-bg)]"
				onclick={onClose}
				aria-label="Close"
			>
				<X size={18} stroke-width={2} />
			</button>
		</div>
	</div>

	<!-- Body -->
	<div class="flex-1 overflow-y-auto bg-[var(--bg-soft)] px-7 pb-8">
		{#if loading}
			<div class="flex h-48 items-center justify-center">
				<div class="h-5 w-5 animate-spin rounded-full border-2 border-[var(--border-color)] border-t-[var(--accent)]"></div>
			</div>
		{:else if error}
			<div class="flex h-48 items-center justify-center text-sm text-[var(--text-tertiary)]">
				Failed to load image details
			</div>
		{:else if detail}
			<!-- Vulnerability summary -->
			<div class="mt-2">
				<h4 class="mb-2 flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">
					<ShieldAlert class="h-3.5 w-3.5" />
					Vulnerabilities
				</h4>
				{#if detail.vuln_severity && detail.vuln_severity.total > 0}
					<div class="flex flex-wrap gap-2 text-xs">
						{#if detail.vuln_severity.critical > 0}
							<span class="rounded-full bg-red-500/15 px-2.5 py-1 font-medium text-red-300">Critical · {detail.vuln_severity.critical}</span>
						{/if}
						{#if detail.vuln_severity.high > 0}
							<span class="rounded-full bg-orange-500/15 px-2.5 py-1 font-medium text-orange-300">High · {detail.vuln_severity.high}</span>
						{/if}
						{#if detail.vuln_severity.medium > 0}
							<span class="rounded-full bg-amber-500/15 px-2.5 py-1 font-medium text-amber-300">Medium · {detail.vuln_severity.medium}</span>
						{/if}
						{#if detail.vuln_severity.low > 0}
							<span class="rounded-full bg-sky-500/15 px-2.5 py-1 font-medium text-sky-300">Low · {detail.vuln_severity.low}</span>
						{/if}
						{#if detail.vuln_severity.unknown > 0}
							<span class="rounded-full bg-[var(--hover-bg)] px-2.5 py-1 font-medium text-[var(--text-secondary)]">Unknown · {detail.vuln_severity.unknown}</span>
						{/if}
						<span class="rounded-full bg-[var(--hover-bg-subtle)] px-2.5 py-1 text-[var(--text-tertiary)]">Total · {detail.vuln_severity.total}</span>
					</div>
				{:else if detail.latest_scan_id}
					<p class="text-xs text-[var(--text-muted)]">No findings in the latest scan.</p>
				{:else}
					<p class="text-xs text-[var(--text-muted)]">Image has not been scanned yet.</p>
				{/if}
			</div>

			<!-- Linked repo + contributors -->
			{#if detail.linked_repo}
				<div class="mt-5">
					<h4 class="mb-2 flex items-center gap-2 text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">
						<GitBranch class="h-3.5 w-3.5" />
						Source repo
					</h4>
					<a
						href={repoDeepLink(detail.linked_repo)}
						class="block rounded-lg border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40 px-3 py-2 transition hover:border-[var(--accent)]/40 hover:bg-[var(--hover-bg-subtle)]"
					>
						<div class="flex items-center justify-between gap-2">
							<span class="truncate font-mono text-sm text-[var(--text-bright)]">
								{detail.linked_repo.org}/{detail.linked_repo.slug}
							</span>
							<span class="text-[10px] uppercase tracking-wider text-[var(--text-tertiary)]">{detail.linked_repo.provider}</span>
						</div>
						{#if detail.linked_repo.revision}
							<p class="mt-1 font-mono text-[11px] text-[var(--text-tertiary)]" title="org.opencontainers.image.revision">
								{detail.linked_repo.revision.slice(0, 12)}
							</p>
						{/if}
					</a>

					{#if detail.linked_repo_contributors && detail.linked_repo_contributors.length > 0}
						<p class="mt-3 text-[10px] uppercase tracking-[0.2em] text-[var(--text-tertiary)]">Recent committers</p>
						<div class="mt-1 flex flex-wrap gap-2">
							{#each detail.linked_repo_contributors as c}
								{@const label = c.login || c.name || c.email || '?'}
								<div class="flex items-center gap-2 rounded-full border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40 py-0.5 pl-0.5 pr-2.5">
									{#if c.avatar_url}
										<img src={c.avatar_url} alt={label} class="h-6 w-6 rounded-full" />
									{:else}
										<div class="flex h-6 w-6 items-center justify-center rounded-full bg-[var(--accent)]/20 text-[10px] font-medium text-[var(--accent)]">
											{label.charAt(0).toUpperCase()}
										</div>
									{/if}
									<span class="text-xs text-[var(--text-secondary)]">{label}</span>
									{#if c.contributions}
										<span class="text-[10px] text-[var(--text-tertiary)]">· {c.contributions}</span>
									{/if}
								</div>
							{/each}
						</div>
					{/if}
				</div>
			{:else}
				<div class="mt-5 rounded-lg border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40 px-3 py-3 text-xs text-[var(--text-muted)]">
					No source repo linked. Add the OCI <code class="font-mono">org.opencontainers.image.source</code> label to this build so SPAM can connect image runs back to the repo.
				</div>
			{/if}

			<!-- Cluster usage -->
			{#if detail.cluster_usage && detail.cluster_usage.length > 0}
				<div class="mt-5">
					<h4 class="mb-2 text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Running in</h4>
					<ul class="divide-y divide-[var(--border-color)]/20 rounded-lg border border-[var(--border-color)]/30">
						{#each detail.cluster_usage as u}
							<li class="flex items-center justify-between gap-3 px-3 py-1.5 text-xs">
								<span class="min-w-0 truncate text-[var(--text-secondary)]">
									<span class="font-medium text-[var(--text-bright)]">{u.cluster || '—'}</span>
									<span class="text-[var(--text-muted)]"> / </span>
									<span>{u.namespace || '—'}</span>
								</span>
								<span class="flex-shrink-0 text-[var(--text-tertiary)]">{u.pod_count} pod{u.pod_count === 1 ? '' : 's'}</span>
							</li>
						{/each}
					</ul>
				</div>
			{/if}

			<!-- Scan history -->
			{#if detail.scan_history && detail.scan_history.length > 0}
				<div class="mt-5">
					<h4 class="mb-2 text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Scan history</h4>
					<ul class="space-y-1.5">
						{#each detail.scan_history.slice(0, 5) as h}
							<li class="flex items-center justify-between gap-2 text-xs">
								<a href={`/runs/${h.job_id}`} class="flex min-w-0 items-center gap-2 truncate text-[var(--text-secondary)] hover:text-[var(--accent)]">
									<span
										class="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
										style="color: {h.status === 'SUCCEEDED' ? 'var(--success)' : h.status === 'FAILED' ? 'var(--error)' : 'var(--warning)'}; background: color-mix(in srgb, {h.status === 'SUCCEEDED' ? 'var(--success)' : h.status === 'FAILED' ? 'var(--error)' : 'var(--warning)'} 15%, transparent);"
									>
										{h.status}
									</span>
									<span>{fmtDate(h.finished_at || h.created_at)}</span>
								</a>
								<span class="text-[var(--text-tertiary)]">{h.vuln_count} vulns</span>
							</li>
						{/each}
					</ul>
				</div>
			{/if}
		{/if}
	</div>
</div>
