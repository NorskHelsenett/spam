<script lang="ts">
	import { CheckCircle, XCircle, Clock, Loader2, Download, Package, Shield, FileCode, Tag, AlertTriangle } from 'lucide-svelte';

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
	};

	let { run }: { run: ImageScanRun } = $props();

	const categoryOrder = ['vuln', 'sbom', 'secrets', 'signature', 'labels'];
	const categoryMeta: Record<string, { label: string; icon: any; color: string; hint: string }> = {
		vuln: { label: 'Vulnerabilities', icon: Shield, color: 'var(--error)', hint: 'CVE findings from the vuln scanner' },
		sbom: { label: 'SBOM', icon: Package, color: 'var(--accent)', hint: 'Software bill of materials' },
		secrets: { label: 'Secrets', icon: AlertTriangle, color: 'var(--warning)', hint: 'Leaked credentials in the image filesystem' },
		signature: { label: 'Signature', icon: CheckCircle, color: 'var(--success)', hint: 'Cosign tree / verification output' },
		labels: { label: 'OCI Labels', icon: Tag, color: 'var(--text-secondary)', hint: 'Image config labels' }
	};

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

	const formatSize = (bytes: number) => {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
		return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
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

	const StatusIcon = $derived(getStatusIcon(run.status));
	const statusColor = $derived(getStatusColor(run.status));

	// Group artifacts by category so multiple scanners (e.g. grype + trivy) in
	// one category render side-by-side.
	const groupedArtifacts = $derived.by(() => {
		const map = new Map<string, Artifact[]>();
		for (const cat of categoryOrder) map.set(cat, []);
		for (const a of run.image_artifacts ?? []) {
			const cat = categoryMeta[a.category] ? a.category : a.category; // pass-through for unknown categories
			if (!map.has(cat)) map.set(cat, []);
			map.get(cat)!.push(a);
		}
		return Array.from(map.entries()).filter(([, v]) => v.length > 0);
	});

	const copyText = async (text: string) => {
		try { await navigator.clipboard.writeText(text); } catch { /* ignore */ }
	};
</script>

<div class="flex flex-col gap-6">
	<!-- Header card: image reference + status -->
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
					<code class="rounded bg-[var(--hover-bg-subtle)] px-2 py-0.5 font-mono">
						{shortDigest(run.image_digest)}
					</code>
					{#if run.image_digest}
						<button
							type="button"
							class="btn btn-ghost btn-xs"
							onclick={() => copyText(run.image_digest!)}
							title="Copy full digest"
						>
							Copy
						</button>
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

	<!-- Vulnerability severity summary -->
	{#if run.image_vuln_counts && run.image_vuln_counts.total > 0}
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
			<div class="mb-2 flex items-center justify-between">
				<h2 class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">Vulnerabilities</h2>
				<span class="text-xs text-[var(--text-tertiary)]">{run.image_vuln_counts.total} total</span>
			</div>
			<div class="flex flex-wrap gap-2">
				{#if run.image_vuln_counts.critical > 0}
					<span class="rounded-full border border-red-500/40 bg-red-500/10 px-3 py-1 text-xs font-semibold text-red-400">
						Critical: {run.image_vuln_counts.critical}
					</span>
				{/if}
				{#if run.image_vuln_counts.high > 0}
					<span class="rounded-full border border-orange-500/40 bg-orange-500/10 px-3 py-1 text-xs font-semibold text-orange-400">
						High: {run.image_vuln_counts.high}
					</span>
				{/if}
				{#if run.image_vuln_counts.medium > 0}
					<span class="rounded-full border border-yellow-500/40 bg-yellow-500/10 px-3 py-1 text-xs font-semibold text-yellow-400">
						Medium: {run.image_vuln_counts.medium}
					</span>
				{/if}
				{#if run.image_vuln_counts.low > 0}
					<span class="rounded-full border border-blue-500/40 bg-blue-500/10 px-3 py-1 text-xs font-semibold text-blue-400">
						Low: {run.image_vuln_counts.low}
					</span>
				{/if}
				{#if run.image_vuln_counts.unknown > 0}
					<span class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs font-semibold text-[var(--text-tertiary)]">
						Unknown: {run.image_vuln_counts.unknown}
					</span>
				{/if}
			</div>
		</div>
	{/if}

	<!-- Scanner selection (if custom) -->
	{#if run.image_scanners && Object.keys(run.image_scanners).length > 0}
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/30 p-4 text-sm">
			<div class="mb-2 text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">Scanner Selection</div>
			<div class="flex flex-wrap gap-2">
				{#each Object.entries(run.image_scanners) as [cat, scanner]}
					<span class="rounded-md border border-[var(--border-color)]/60 px-2 py-1 font-mono text-xs">
						{cat}: <strong>{scanner}</strong>
					</span>
				{/each}
			</div>
		</div>
	{/if}

	<!-- Artifacts -->
	<div>
		<h2 class="mb-3 text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">Scan Artifacts</h2>
		{#if !run.image_artifacts || run.image_artifacts.length === 0}
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/30 p-6 text-center text-sm text-[var(--text-tertiary)]">
				{run.status === 'SUCCEEDED' ? 'No artifacts produced for this scan.' : 'Artifacts will appear here once the scan completes.'}
			</div>
		{:else}
			<div class="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
				{#each groupedArtifacts as [category, items]}
					{@const meta = categoryMeta[category] ?? { label: category, icon: FileCode, color: 'var(--text-secondary)', hint: '' }}
					{@const Icon = meta.icon}
					<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
						<div class="mb-3 flex items-center gap-2">
							<Icon size={18} style={`color: ${meta.color}`} />
							<span class="text-sm font-semibold text-[var(--text-bright)]">{meta.label}</span>
						</div>
						{#if meta.hint}
							<p class="mb-3 text-xs text-[var(--text-tertiary)]">{meta.hint}</p>
						{/if}
						<ul class="flex flex-col gap-2">
							{#each items as art}
								<li class="flex items-center justify-between gap-2 text-xs">
									<div class="min-w-0 flex-1">
										<div class="font-mono text-[var(--text-secondary)]">{art.scanner}</div>
										<div class="text-[var(--text-tertiary)]">{formatSize(art.size)}</div>
									</div>
									<a
										class="btn btn-ghost btn-xs"
										href={`/api/image-scans/${run.id}/artifacts/${art.id}/download`}
										title="Download raw artifact"
									>
										<Download size={14} />
									</a>
								</li>
							{/each}
						</ul>
					</div>
				{/each}
			</div>
		{/if}

		{#if run.sbom_id}
			<div class="mt-4 rounded-xl border border-[var(--accent)]/30 bg-[var(--accent)]/5 p-4 text-sm">
				<div class="flex items-center justify-between gap-4">
					<div>
						<div class="font-semibold text-[var(--text-bright)]">SBOM linked to this image</div>
						<div class="text-xs text-[var(--text-tertiary)]">Components from this SBOM are queryable in /app/components.</div>
					</div>
					<a class="btn btn-secondary btn-sm" href={`/api/sboms/${run.sbom_id}/download`} target="_blank" rel="noopener">
						Download SBOM
					</a>
				</div>
			</div>
		{/if}
	</div>
</div>
