<script lang="ts">
	import { CheckCircle, XCircle, Clock, Loader2, Download, Package, Shield, AlertTriangle, Tag, ShieldAlert, ShieldCheck, FileCode, Container } from 'lucide-svelte';

	type Artifact = {
		id: string;
		category: string;
		scanner: string;
		filename?: string;
		size: number;
		created_at: string;
	};

	type SeverityCounts = {
		critical: number;
		high: number;
		medium: number;
		low: number;
		unknown: number;
		total: number;
	};

	type VulnRow = {
		vuln_id: string;
		severity: string;
		pkg_name: string;
		installed_version?: string;
		fixed_version?: string;
		title?: string;
		target?: string;
		scanner: string;
	};

	type SecretRow = {
		rule_id: string;
		description?: string;
		file?: string;
		start_line?: number;
		match?: string;
	};

	type SignatureInfo = {
		signed: boolean;
		verified: boolean;
		error?: string;
	};

	type OCIMetadata = {
		created?: string;
		architecture?: string;
		os?: string;
		author?: string;
	};

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

	type ImageScanRun = {
		id: string;
		type?: string;
		status: string;
		repo_path: string;
		error?: string;
		created_at: string;
		started_at?: string;
		finished_at?: string;
		sbom_id?: string;
		image_registry?: string;
		image_repository?: string;
		image_digest?: string;
		image_digest_id?: string;
		image_artifacts?: Artifact[];
		image_scanners?: Record<string, string>;
		image_vuln_counts?: SeverityCounts;
		image_vulns?: VulnRow[];
		image_labels?: Record<string, string>;
		image_oci_metadata?: OCIMetadata;
		image_secrets?: SecretRow[];
		image_signature?: SignatureInfo;
		image_linked_repo?: LinkedRepo;
		sbom_component_count?: number;
	};

	let { run }: { run: ImageScanRun } = $props();

	const getStatusIcon = (status: string) => {
		switch (status) {
			case 'QUEUED': return Clock;
			case 'RUNNING': return Loader2;
			case 'SUCCEEDED': return CheckCircle;
			case 'FAILED': return XCircle;
			default: return Clock;
		}
	};
	const getStatusColor = (status: string) => {
		switch (status) {
			case 'QUEUED': return 'var(--warning)';
			case 'RUNNING': return 'var(--accent)';
			case 'SUCCEEDED': return 'var(--success)';
			case 'FAILED': return 'var(--error)';
			default: return 'var(--text-tertiary)';
		}
	};
	const StatusIcon = $derived(getStatusIcon(run.status));
	const statusColor = $derived(getStatusColor(run.status));

	const severityColor = (s: string): string => {
		switch (s?.toUpperCase()) {
			case 'CRITICAL': return 'rgb(239 68 68)';
			case 'HIGH':     return 'rgb(249 115 22)';
			case 'MEDIUM':   return 'rgb(234 179 8)';
			case 'LOW':      return 'rgb(59 130 246)';
			default:         return 'var(--text-tertiary)';
		}
	};

	const formatDuration = (start?: string, end?: string) => {
		if (!start) return '-';
		const started = new Date(start).getTime();
		const finished = end ? new Date(end).getTime() : Date.now();
		const secs = Math.max(0, Math.floor((finished - started) / 1000));
		if (secs < 60) return `${secs}s`;
		const m = Math.floor(secs / 60);
		const s = secs % 60;
		return `${m}m ${s}s`;
	};

	const shortDigest = (digest?: string) => {
		if (!digest) return '';
		const idx = digest.indexOf(':');
		if (idx < 0) return digest;
		return digest.slice(0, idx + 13);
	};

	const copyText = async (text: string) => {
		try { await navigator.clipboard.writeText(text); } catch { /* ignore */ }
	};

	// Table state
	let vulnSearch = $state('');
	let vulnSeverityFilter = $state<string>('all');
	const visibleVulns = $derived.by(() => {
		const vulns = run.image_vulns ?? [];
		const q = vulnSearch.trim().toLowerCase();
		return vulns.filter(v => {
			if (vulnSeverityFilter !== 'all' && (v.severity?.toUpperCase() ?? 'UNKNOWN') !== vulnSeverityFilter) return false;
			if (!q) return true;
			return (
				v.vuln_id.toLowerCase().includes(q) ||
				v.pkg_name.toLowerCase().includes(q) ||
				(v.title ?? '').toLowerCase().includes(q)
			);
		});
	});

	// Prefer to lift the well-known OCI labels out of the big dump so they read first.
	const labelHighlights = [
		'org.opencontainers.image.title',
		'org.opencontainers.image.description',
		'org.opencontainers.image.version',
		'org.opencontainers.image.source',
		'org.opencontainers.image.url',
		'org.opencontainers.image.vendor',
		'org.opencontainers.image.licenses',
		'org.opencontainers.image.revision',
		'org.opencontainers.image.created'
	];
	const labelEntries = $derived.by(() => {
		const labels = run.image_labels ?? {};
		const keys = Object.keys(labels);
		const highlighted = labelHighlights.filter(k => k in labels).map(k => [k, labels[k]] as const);
		const rest = keys.filter(k => !labelHighlights.includes(k)).sort().map(k => [k, labels[k]] as const);
		return { highlighted, rest };
	});

	const isURL = (v: string) => /^https?:\/\//i.test(v);
</script>

<div class="flex flex-col gap-6">
	<!-- Header card -->
	<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-6">
		<div class="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
			<div class="min-w-0 flex-1">
				<div class="mb-2 flex items-center gap-2 text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
					<span class="rounded-full border border-[var(--accent)]/40 bg-[var(--accent)]/10 px-2 py-0.5 text-[10px] font-semibold text-[var(--accent)]">Image Scan</span>
					<span>Job ID: {run.id.slice(0, 8)}</span>
				</div>
				<h1 class="break-all text-xl font-semibold text-[var(--text-bright)]">
					{run.image_registry}/{run.image_repository}
				</h1>
				<div class="mt-2 flex flex-wrap items-center gap-2 text-xs text-[var(--text-tertiary)]">
					<code class="rounded bg-[var(--hover-bg-subtle)] px-2 py-0.5 font-mono">{shortDigest(run.image_digest)}</code>
					{#if run.image_digest}
						<button type="button" class="btn btn-ghost btn-xs" onclick={() => copyText(run.image_digest!)} title="Copy full digest">Copy</button>
					{/if}
				</div>
			</div>
			<div class="flex flex-col items-end gap-2 text-sm">
				<span class="flex items-center gap-2 text-base font-semibold" style={`color: ${statusColor}`}>
					<StatusIcon size={18} class={run.status === 'RUNNING' ? 'animate-spin' : ''} />
					{run.status}
				</span>
				<span class="text-xs text-[var(--text-tertiary)]">Duration: {formatDuration(run.started_at, run.finished_at)}</span>
				<span class="text-xs text-[var(--text-tertiary)]">Created: {new Date(run.created_at).toLocaleString()}</span>
			</div>
		</div>
		{#if run.error}
			<div class="mt-4 rounded-lg border border-[var(--error)]/30 bg-[var(--error)]/10 p-3 text-sm text-[var(--error)]">
				{run.error}
			</div>
		{/if}
	</div>

	<!-- Summary row: signature + metadata + SBOM + artifacts -->
	<div class="grid gap-3 md:grid-cols-2 lg:grid-cols-4">
		<!-- Signature -->
		<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
			<div class="mb-2 flex items-center gap-2 text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
				<Shield size={14} />
				Signature
			</div>
			{#if run.image_signature}
				<div class="flex items-center gap-2 text-sm">
					{#if run.image_signature.verified}
						<ShieldCheck size={16} class="text-[var(--success)]" />
						<span class="font-semibold text-[var(--text-bright)]">Verified</span>
					{:else if run.image_signature.signed}
						<ShieldCheck size={16} class="text-yellow-400" />
						<span class="font-semibold text-[var(--text-bright)]">Signed (unverified)</span>
					{:else}
						<ShieldAlert size={16} class="text-[var(--text-tertiary)]" />
						<span class="text-[var(--text-secondary)]">Unsigned</span>
					{/if}
				</div>
				{#if run.image_signature.error}
					<p class="mt-2 text-xs text-[var(--text-tertiary)]">cosign: {run.image_signature.error}</p>
				{/if}
			{:else}
				<p class="text-sm text-[var(--text-tertiary)]">Not scanned yet</p>
			{/if}
		</div>

		<!-- OCI metadata -->
		<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
			<div class="mb-2 flex items-center gap-2 text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
				<Container size={14} />
				Image
			</div>
			{#if run.image_oci_metadata}
				<div class="space-y-1 text-xs text-[var(--text-secondary)]">
					{#if run.image_oci_metadata.os || run.image_oci_metadata.architecture}
						<div>{run.image_oci_metadata.os ?? ''}/{run.image_oci_metadata.architecture ?? ''}</div>
					{/if}
					{#if run.image_oci_metadata.created}
						<div>Built: {new Date(run.image_oci_metadata.created).toLocaleString()}</div>
					{/if}
					{#if run.image_oci_metadata.author}
						<div>Author: {run.image_oci_metadata.author}</div>
					{/if}
				</div>
			{:else}
				<p class="text-sm text-[var(--text-tertiary)]">Not available</p>
			{/if}
		</div>

		<!-- SBOM -->
		<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
			<div class="mb-2 flex items-center gap-2 text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
				<Package size={14} />
				SBOM
			</div>
			{#if run.sbom_id}
				<div class="flex items-center justify-between gap-2">
					<div>
						<div class="text-lg font-semibold text-[var(--text-bright)]">{run.sbom_component_count ?? '—'}</div>
						<div class="text-xs text-[var(--text-tertiary)]">components</div>
					</div>
					<a class="btn btn-ghost btn-xs" href={`/api/sboms/${run.sbom_id}/download`} title="Download SBOM">
						<Download size={14} />
					</a>
				</div>
			{:else}
				<p class="text-sm text-[var(--text-tertiary)]">Not generated</p>
			{/if}
		</div>

		<!-- Scanner tools summary -->
		<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
			<div class="mb-2 flex items-center gap-2 text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
				<FileCode size={14} />
				Artifacts
			</div>
			<div class="flex flex-wrap items-center gap-2 text-xs">
				{#each run.image_artifacts ?? [] as art}
					<a
						class="rounded-md border border-[var(--border-color)]/60 px-2 py-0.5 text-[var(--text-secondary)] hover:text-[var(--accent)]"
						href={`/api/image-scans/${run.id}/artifacts/${art.id}/download`}
						title={`${art.category}/${art.scanner}: ${art.size} bytes`}
					>
						{art.scanner}
					</a>
				{/each}
				{#if (run.image_artifacts ?? []).length === 0}
					<span class="text-[var(--text-tertiary)]">none yet</span>
				{/if}
			</div>
		</div>
	</div>

	<!-- Vulnerabilities -->
	<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-6">
		<header class="mb-3 flex flex-wrap items-center justify-between gap-3">
			<div class="flex items-center gap-3">
				<h2 class="text-sm font-semibold text-[var(--text-bright)]">Vulnerabilities</h2>
				{#if run.image_vuln_counts && run.image_vuln_counts.total > 0}
					<div class="flex flex-wrap items-center gap-1.5 text-xs">
						{#each [['Critical', run.image_vuln_counts.critical, 'CRITICAL'], ['High', run.image_vuln_counts.high, 'HIGH'], ['Medium', run.image_vuln_counts.medium, 'MEDIUM'], ['Low', run.image_vuln_counts.low, 'LOW'], ['Unknown', run.image_vuln_counts.unknown, '']] as [label, count, sev]}
							{#if (count as number) > 0}
								<button
									type="button"
									class="rounded-full border px-2 py-0.5"
									style={`color: ${severityColor(sev as string)}; border-color: ${severityColor(sev as string)}40; background: ${severityColor(sev as string)}12;`}
									onclick={() => { vulnSeverityFilter = sev === '' ? 'UNKNOWN' : (sev as string); }}
								>{label}: {count}</button>
							{/if}
						{/each}
					</div>
				{/if}
			</div>
			<div class="flex items-center gap-2">
				<input
					type="search"
					class="input h-8 w-48 py-1 text-xs"
					placeholder="CVE-... / package / title"
					bind:value={vulnSearch}
				/>
				{#if vulnSeverityFilter !== 'all'}
					<button type="button" class="btn btn-ghost btn-xs" onclick={() => { vulnSeverityFilter = 'all'; }}>
						Clear filter
					</button>
				{/if}
			</div>
		</header>
		{#if !run.image_vulns || run.image_vulns.length === 0}
			<p class="py-6 text-center text-sm text-[var(--text-tertiary)]">
				{run.status === 'SUCCEEDED' ? 'No vulnerabilities found.' : 'Findings will appear here once the scan completes.'}
			</p>
		{:else}
			<div class="overflow-hidden rounded-lg border border-[var(--border-color)]/40">
				<table class="min-w-full divide-y divide-[var(--border-color)]/40 text-xs">
					<thead class="text-[10px] uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
						<tr>
							<th class="px-3 py-2 text-left">CVE</th>
							<th class="px-3 py-2 text-left">Severity</th>
							<th class="px-3 py-2 text-left">Package</th>
							<th class="px-3 py-2 text-left">Installed</th>
							<th class="px-3 py-2 text-left">Fixed</th>
							<th class="px-3 py-2 text-left">Title</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-[var(--border-color)]/20 text-[var(--text-secondary)]">
						{#each visibleVulns.slice(0, 500) as v}
							<tr class="hover:bg-[var(--hover-bg-subtle)]">
								<td class="px-3 py-1.5 font-mono text-[var(--text-bright)]">{v.vuln_id}</td>
								<td class="px-3 py-1.5">
									<span class="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase"
										style={`color: ${severityColor(v.severity)}; background: ${severityColor(v.severity)}18;`}>
										{v.severity || 'UNKNOWN'}
									</span>
								</td>
								<td class="px-3 py-1.5 font-mono">{v.pkg_name}</td>
								<td class="px-3 py-1.5 font-mono">{v.installed_version ?? '-'}</td>
								<td class="px-3 py-1.5 font-mono" class:text-[var(--success)]={v.fixed_version}>{v.fixed_version ?? '-'}</td>
								<td class="px-3 py-1.5 text-[var(--text-tertiary)]">{v.title ?? ''}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
			{#if visibleVulns.length > 500}
				<p class="mt-2 text-right text-xs text-[var(--text-tertiary)]">
					Showing first 500 of {visibleVulns.length} matching findings. Download the raw artifact for the full list.
				</p>
			{/if}
		{/if}
	</div>

	<!-- Secrets -->
	<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-6">
		<header class="mb-3 flex items-center gap-2">
			<AlertTriangle size={16} class="text-[var(--warning)]" />
			<h2 class="text-sm font-semibold text-[var(--text-bright)]">Secrets in image filesystem</h2>
			<span class="text-xs text-[var(--text-tertiary)]">
				{run.image_secrets?.length ?? 0} finding{(run.image_secrets?.length ?? 0) === 1 ? '' : 's'}
			</span>
		</header>
		{#if !run.image_secrets || run.image_secrets.length === 0}
			<p class="py-4 text-center text-sm text-[var(--text-tertiary)]">No secrets detected.</p>
		{:else}
			<div class="overflow-hidden rounded-lg border border-[var(--border-color)]/40">
				<table class="min-w-full divide-y divide-[var(--border-color)]/40 text-xs">
					<thead class="text-[10px] uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
						<tr>
							<th class="px-3 py-2 text-left">Rule</th>
							<th class="px-3 py-2 text-left">File</th>
							<th class="px-3 py-2 text-left">Line</th>
							<th class="px-3 py-2 text-left">Match</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-[var(--border-color)]/20 text-[var(--text-secondary)]">
						{#each run.image_secrets as s}
							<tr>
								<td class="px-3 py-1.5 font-mono text-[var(--text-bright)]">{s.rule_id}</td>
								<td class="px-3 py-1.5 font-mono break-all">{s.file ?? '-'}</td>
								<td class="px-3 py-1.5">{s.start_line ?? '-'}</td>
								<td class="px-3 py-1.5 font-mono text-[var(--text-tertiary)]">{s.match ?? ''}</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</div>

	<!-- OCI Labels -->
	<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-6">
		<header class="mb-3 flex items-center gap-2">
			<Tag size={16} />
			<h2 class="text-sm font-semibold text-[var(--text-bright)]">OCI labels</h2>
			<span class="text-xs text-[var(--text-tertiary)]">
				{Object.keys(run.image_labels ?? {}).length} label{Object.keys(run.image_labels ?? {}).length === 1 ? '' : 's'}
			</span>
		</header>

		{#if run.image_linked_repo}
			<!-- Source repo link resolved from org.opencontainers.image.source.
			     Labels are self-attested, hence the "Claimed" framing. -->
			<div class="mb-3 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-[var(--accent)]/40 bg-[var(--accent)]/10 p-3">
				<div class="min-w-0 flex-1">
					<div class="mb-0.5 text-[10px] uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
						Claimed source repository
					</div>
					<div class="flex flex-wrap items-center gap-2 text-sm font-semibold text-[var(--text-bright)]">
						<span class="font-mono">{run.image_linked_repo.org}/{run.image_linked_repo.slug}</span>
						<span class="rounded border border-[var(--border-color)]/60 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-[var(--text-tertiary)]">
							{run.image_linked_repo.provider}
						</span>
					</div>
					{#if run.image_linked_repo.revision}
						<div class="mt-1 font-mono text-xs text-[var(--text-tertiary)]">
							revision
							{#if isURL(run.image_linked_repo.source)}
								<a href={`${run.image_linked_repo.source.replace(/\.git$/, '')}/commit/${run.image_linked_repo.revision}`}
									target="_blank" rel="noopener"
									class="text-[var(--accent)] hover:underline">
									{run.image_linked_repo.revision.slice(0, 10)}
								</a>
							{:else}
								{run.image_linked_repo.revision.slice(0, 10)}
							{/if}
						</div>
					{/if}
				</div>
				<a
					class="btn btn-secondary btn-sm"
					href={`/app/providers/repo?repo_id=${run.image_linked_repo.repo_id}${run.image_linked_repo.provider_id ? `&provider_id=${run.image_linked_repo.provider_id}` : ''}`}
				>
					Open repo →
				</a>
			</div>
		{/if}

		{#if !run.image_labels || Object.keys(run.image_labels).length === 0}
			<p class="py-4 text-center text-sm text-[var(--text-tertiary)]">No labels set on this image.</p>
		{:else}
			<dl class="grid gap-2 md:grid-cols-2">
				{#each labelEntries.highlighted as [k, v]}
					<div class="rounded-lg border border-[var(--accent)]/30 bg-[var(--accent)]/5 p-2">
						<dt class="mb-0.5 text-[10px] uppercase tracking-[0.2em] text-[var(--text-tertiary)]">{k.replace('org.opencontainers.image.', '')}</dt>
						<dd class="break-all text-sm text-[var(--text-bright)]">
							{#if isURL(v)}<a href={v} target="_blank" rel="noopener" class="text-[var(--accent)] hover:underline">{v}</a>{:else}{v}{/if}
						</dd>
					</div>
				{/each}
			</dl>
			{#if labelEntries.rest.length > 0}
				<details class="mt-3 text-xs">
					<summary class="cursor-pointer text-[var(--text-tertiary)]">Other labels ({labelEntries.rest.length})</summary>
					<table class="mt-2 min-w-full text-xs">
						<tbody class="divide-y divide-[var(--border-color)]/20">
							{#each labelEntries.rest as [k, v]}
								<tr>
									<td class="py-1 pr-3 font-mono text-[var(--text-tertiary)]">{k}</td>
									<td class="py-1 break-all font-mono text-[var(--text-secondary)]">{v}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</details>
			{/if}
		{/if}
	</div>
</div>
