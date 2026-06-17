<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { ShieldCheck, ShieldAlert, Play, Clock, Trash2 } from 'lucide-svelte';
	import { isJobActive, jobStatusLabel, jobStatusClass } from './jobStatus';

	type OSVScanStatus = {
		job_id?: string;
		status?: string;
		created_at?: string;
		finished_at?: string;
		error?: string;
		result?: {
			total_purls: number;
			scanned: number;
			vulns_found: number;
			components_with_vulns: number;
			errors: number;
			phase?: string;
			enrich_total?: number;
			enrich_done?: number;
		};
	};

	let osvStatus: OSVScanStatus = $state({});
	let osvTriggering = $state(false);
	let osvError = $state('');
	let cacheClearing = $state(false);
	let cacheMessage = $state('');
	let osvPollTimer: ReturnType<typeof setTimeout> | null = null;

	const loadOSVStatus = async () => {
		try {
			const response = await fetch('/api/admin/osv/scan/status', { credentials: 'include' });
			if (response.ok) osvStatus = await response.json();
		} catch { /* ignore */ }
	};

	const pollOSVStatus = () => {
		if (osvPollTimer) clearTimeout(osvPollTimer);
		osvPollTimer = setTimeout(async () => {
			await loadOSVStatus();
			if (isJobActive(osvStatus.status)) pollOSVStatus();
		}, 3000);
	};

	const triggerOSVScan = async () => {
		osvTriggering = true;
		osvError = '';
		try {
			const response = await fetch('/api/admin/osv/scan', {
				method: 'POST',
				credentials: 'include'
			});
			if (response.status === 409) {
				osvError = 'A scan is already queued or running.';
				return;
			}
			if (!response.ok) {
				osvError = 'Failed to start scan.';
				return;
			}
			osvStatus = await response.json();
			pollOSVStatus();
		} catch {
			osvError = 'Failed to start scan.';
		} finally {
			osvTriggering = false;
		}
	};

	const clearCache = async () => {
		cacheClearing = true;
		cacheMessage = '';
		try {
			const response = await fetch('/api/admin/cache/clear', {
				method: 'POST',
				credentials: 'include'
			});
			if (!response.ok) {
				cacheMessage = 'Failed to clear application cache.';
				return;
			}
			cacheMessage = 'Application cache cleared. Cached views will repopulate on the next request or refresh job.';
		} catch {
			cacheMessage = 'Failed to clear application cache.';
		} finally {
			cacheClearing = false;
		}
	};

	onMount(() => {
		if (!browser) return;
		loadOSVStatus().then(() => {
			if (isJobActive(osvStatus.status)) pollOSVStatus();
		});
		return () => {
			if (osvPollTimer) clearTimeout(osvPollTimer);
		};
	});
</script>

<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
	<header class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">Vulnerability Scanning</h2>
			<p class="text-sm text-[var(--text-tertiary)]">
				Checks all SBOM components against the OSV database. Results are cached per component for 24 h.
			</p>
		</div>
		<div class="flex flex-wrap items-center gap-2">
			<button
				type="button"
				class="inline-flex items-center gap-2 rounded-full border border-[var(--border-color)] px-4 py-2 text-sm font-semibold text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
				onclick={clearCache}
				disabled={cacheClearing}
			>
				<Trash2 size={14} />
				{cacheClearing ? 'Clearing…' : 'Clear Cache'}
			</button>
			<button
				type="button"
				class="btn btn-primary inline-flex items-center gap-2"
				onclick={triggerOSVScan}
				disabled={osvTriggering || isJobActive(osvStatus.status)}
			>
				<Play size={14} />
				{osvTriggering ? 'Starting…' : 'Run OSV Scan'}
			</button>
		</div>
	</header>

	{#if osvError}
		<div class="rounded-2xl border border-[var(--error)]/30 bg-[var(--error)]/5 p-4 text-sm text-[var(--error)]">
			{osvError}
		</div>
	{/if}
	{#if cacheMessage}
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--text-secondary)]">
			{cacheMessage}
		</div>
	{/if}

	<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
		<!-- Status -->
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<ShieldAlert size={16} />
				<span>Status</span>
			</div>
			<p class="mt-2 text-sm font-semibold">
				<span class="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs {jobStatusClass(osvStatus.status)}">
					{jobStatusLabel(osvStatus.status)}
				</span>
			</p>
			{#if osvStatus.created_at}
				<p class="mt-1 flex items-center gap-1 text-[11px] text-[var(--text-muted)]">
					<Clock size={10} /> Started {new Date(osvStatus.created_at).toLocaleString()}
				</p>
			{/if}
			{#if osvStatus.finished_at}
				<p class="mt-0.5 text-[11px] text-[var(--text-muted)]">
					Finished {new Date(osvStatus.finished_at).toLocaleString()}
				</p>
			{/if}
		</div>

		<!-- Scanned -->
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<ShieldCheck size={16} />
				<span>Components scanned</span>
			</div>
			<p class="mt-2 text-2xl font-semibold text-[var(--text-bright)]">
				{osvStatus.result?.scanned ?? '—'}
				{#if osvStatus.result?.total_purls}
					<span class="text-sm font-normal text-[var(--text-muted)]">/ {osvStatus.result.total_purls}</span>
				{/if}
			</p>
			{#if osvStatus.status === 'RUNNING' && osvStatus.result?.total_purls}
				{@const phase = osvStatus.result.phase}
				{@const pct = phase === 'enriching'
					? (osvStatus.result.enrich_total ? Math.round((osvStatus.result.enrich_done ?? 0) / osvStatus.result.enrich_total * 100) : 0)
					: Math.round((osvStatus.result.scanned / osvStatus.result.total_purls) * 100)}
				<div class="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-[var(--border-color)]">
					<div class="h-full rounded-full bg-amber-400 transition-all duration-500" style="width: {pct}%"></div>
				</div>
				<p class="mt-1 text-[11px] text-[var(--text-muted)]">
					{#if phase === 'enriching'}
						Enriching details — {osvStatus.result.enrich_done ?? 0}/{osvStatus.result.enrich_total} ({pct}%)
					{:else}
						{pct}% scanned
					{/if}
				</p>
			{/if}
		</div>

		<!-- Vulnerabilities -->
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<ShieldAlert size={16} />
				<span>Vulnerabilities found</span>
			</div>
			<p class="mt-2 text-2xl font-semibold {(osvStatus.result?.vulns_found ?? 0) > 0 ? 'text-red-400' : 'text-[var(--text-bright)]'}">
				{osvStatus.result?.vulns_found ?? '—'}
			</p>
			{#if osvStatus.result?.components_with_vulns != null}
				<p class="mt-1 text-[11px] text-[var(--text-muted)]">
					across {osvStatus.result.components_with_vulns} components
				</p>
			{/if}
		</div>

		<!-- Errors -->
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<span>Batch errors</span>
			</div>
			<p class="mt-2 text-2xl font-semibold {(osvStatus.result?.errors ?? 0) > 0 ? 'text-[var(--error)]' : 'text-[var(--text-bright)]'}">
				{osvStatus.result?.errors ?? '—'}
			</p>
			<p class="mt-1 text-[11px] text-[var(--text-muted)]">Failed OSV batches</p>
		</div>
	</div>

	{#if osvStatus.error}
		<div class="rounded-2xl border border-[var(--error)]/30 bg-[var(--error)]/5 p-4">
			<p class="text-xs font-semibold uppercase tracking-wider text-[var(--error)]">Job error</p>
			<p class="mt-1 text-sm text-[var(--text-secondary)]">{osvStatus.error}</p>
		</div>
	{/if}
</section>
