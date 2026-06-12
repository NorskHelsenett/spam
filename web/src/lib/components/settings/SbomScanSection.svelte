<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { Play, Clock } from 'lucide-svelte';
	import { isJobActive, jobStatusLabel, jobStatusClass } from './jobStatus';

	type SBOMScanRun = {
		started_at: string;
		finished_at: string;
		sbom_count: number;
		critical_count: number;
		high_count: number;
	};

	type SBOMScanStatus = {
		job_id?: string;
		job_status?: string;
		created_at?: string;
		finished_at?: string;
		error?: string;
		pending_count?: number;
		scanned_count?: number;
		last_scanned_at?: string;
		scan_complete?: boolean;
		recent_runs?: SBOMScanRun[];
	};

	let sbomScanStatus: SBOMScanStatus = $state({});
	let sbomScanTriggering = $state(false);
	let sbomScanError = $state('');
	let sbomScanPollTimer: ReturnType<typeof setTimeout> | null = null;

	const loadSBOMScanStatus = async () => {
		try {
			const response = await fetch('/api/admin/sbom/scan/status', { credentials: 'include' });
			if (response.ok) sbomScanStatus = await response.json();
		} catch { /* ignore */ }
	};

	const scanActive = () => isJobActive(sbomScanStatus.job_status) || !sbomScanStatus.scan_complete;

	const pollSBOMScanStatus = () => {
		if (sbomScanPollTimer) clearTimeout(sbomScanPollTimer);
		sbomScanPollTimer = setTimeout(async () => {
			await loadSBOMScanStatus();
			if (scanActive()) pollSBOMScanStatus();
		}, 3000);
	};

	const triggerSBOMScan = async () => {
		sbomScanTriggering = true;
		sbomScanError = '';
		try {
			const response = await fetch('/api/admin/sbom/scan', {
				method: 'POST',
				credentials: 'include'
			});
			if (response.status === 409) {
				sbomScanError = 'A scan job is already queued or running.';
				return;
			}
			if (response.status === 503) {
				// Should not reach here since button is disabled when not configured.
				return;
			}
			if (!response.ok) {
				sbomScanError = 'Failed to start scan.';
				return;
			}
			await loadSBOMScanStatus();
			pollSBOMScanStatus();
		} catch {
			sbomScanError = 'Failed to start scan.';
		} finally {
			sbomScanTriggering = false;
		}
	};

	onMount(() => {
		if (!browser) return;
		loadSBOMScanStatus().then(() => {
			if (scanActive()) pollSBOMScanStatus();
		});
		return () => {
			if (sbomScanPollTimer) clearTimeout(sbomScanPollTimer);
		};
	});
</script>

<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
	<header class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">SBOM Vulnerability Scanner</h2>
			<p class="text-sm text-[var(--text-tertiary)]">
				Runs as a scheduled K8s CronJob (grype against every stored SBOM). Trigger an ad-hoc scan to pick up new SBOMs immediately.
			</p>
		</div>
		<div class="flex flex-wrap items-center gap-2">
			<button
				type="button"
				class="btn btn-primary inline-flex items-center gap-2"
				onclick={triggerSBOMScan}
				disabled={sbomScanTriggering || isJobActive(sbomScanStatus.job_status)}
			>
				<Play size={14} />
				{sbomScanTriggering ? 'Starting…' : 'Run Scan Now'}
			</button>
		</div>
	</header>

	{#if sbomScanError}
		<div class="rounded-2xl border border-[var(--error)]/30 bg-[var(--error)]/5 p-4 text-sm text-[var(--error)]">
			{sbomScanError}
		</div>
	{/if}

	{#if sbomScanStatus.job_id}
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 space-y-3">
			<div class="flex items-center justify-between">
				<span class="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs {jobStatusClass(sbomScanStatus.job_status)}">
					{sbomScanStatus.scan_complete ? 'Scan complete' : jobStatusLabel(sbomScanStatus.job_status, { succeeded: 'Job created', never: 'Never triggered' })}
				</span>
				<span class="text-xs text-[var(--text-muted)]">
					{sbomScanStatus.scanned_count ?? 0} / {(sbomScanStatus.scanned_count ?? 0) + (sbomScanStatus.pending_count ?? 0)} SBOMs scanned
				</span>
			</div>
			{#if (sbomScanStatus.pending_count ?? 0) > 0}
				{@const total = (sbomScanStatus.scanned_count ?? 0) + (sbomScanStatus.pending_count ?? 0)}
				{@const pct = total > 0 ? Math.round(((sbomScanStatus.scanned_count ?? 0) / total) * 100) : 0}
				<div class="h-1.5 w-full rounded-full bg-[var(--border-color)]/40">
					<div class="h-1.5 rounded-full bg-amber-400 transition-all duration-500" style="width: {pct}%"></div>
				</div>
			{/if}
			<div class="flex flex-wrap gap-x-6 gap-y-1 text-[11px] text-[var(--text-muted)]">
				{#if sbomScanStatus.created_at}
					<span class="flex items-center gap-1"><Clock size={10} /> Triggered {new Date(sbomScanStatus.created_at).toLocaleString()}</span>
				{/if}
				{#if sbomScanStatus.last_scanned_at}
					<span>Last scan {new Date(sbomScanStatus.last_scanned_at).toLocaleString()}</span>
				{/if}
			</div>
		</div>
	{/if}

	{#if sbomScanStatus.error}
		<div class="rounded-2xl border border-[var(--error)]/30 bg-[var(--error)]/5 p-4">
			<p class="text-xs font-semibold uppercase tracking-wider text-[var(--error)]">Job error</p>
			<p class="mt-1 text-sm text-[var(--text-secondary)]">{sbomScanStatus.error}</p>
		</div>
	{/if}

	{#if sbomScanStatus.recent_runs && sbomScanStatus.recent_runs.length > 0}
		<div class="space-y-1">
			<p class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Recent runs</p>
			<div class="divide-y divide-[var(--border-color)]/40 rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
				{#each sbomScanStatus.recent_runs as run}
					<div class="flex items-center justify-between px-4 py-2.5 text-xs">
						<div class="flex items-center gap-3">
							<span class="text-[var(--text-secondary)]">{new Date(run.started_at).toLocaleDateString()}</span>
							<span class="text-[var(--text-muted)]">{new Date(run.started_at).toLocaleTimeString()} – {new Date(run.finished_at).toLocaleTimeString()}</span>
						</div>
						<div class="flex items-center gap-4">
							<span class="text-[var(--text-muted)]">{run.sbom_count} SBOMs</span>
							{#if run.critical_count > 0}
								<span class="text-red-400">{run.critical_count} critical</span>
							{/if}
							{#if run.high_count > 0}
								<span class="text-orange-400">{run.high_count} high</span>
							{/if}
						</div>
					</div>
				{/each}
			</div>
		</div>
	{/if}
</section>
