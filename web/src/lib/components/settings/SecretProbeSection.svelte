<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { ShieldCheck, ShieldAlert, KeyRound, Eye, Clock } from 'lucide-svelte';
	import { isJobActive, jobStatusLabel, jobStatusClass } from './jobStatus';
	import SecretProbeListDialog from './SecretProbeListDialog.svelte';
	import SecretProbePreviewDialog from './SecretProbePreviewDialog.svelte';

	type ProbeStatus = {
		job?: {
			id: string;
			status: string;
			created_at?: string;
			finished_at?: string;
			error?: string;
			result?: any;
		};
		stats: {
			total: number;
			valid: number;
			invalid: number;
			revoked: number;
			expired: number;
			false_positive: number;
			unknown: number;
			error: number;
		};
		registered_rules: string[];
	};

	let probeStatus: ProbeStatus = $state({ stats: { total: 0, valid: 0, invalid: 0, revoked: 0, expired: 0, false_positive: 0, unknown: 0, error: 0 }, registered_rules: [] });
	let probeTriggering = $state(false);
	let probeError = $state('');
	let probePollTimer: ReturnType<typeof setTimeout> | null = null;

	let listDialog: SecretProbeListDialog;
	let previewDialog: SecretProbePreviewDialog;

	const loadProbeStatus = async () => {
		try {
			const response = await fetch('/api/admin/secrets/probe/status', { credentials: 'include' });
			if (response.ok) probeStatus = await response.json();
		} catch { /* ignore */ }
	};

	const pollProbeStatus = () => {
		if (probePollTimer) clearTimeout(probePollTimer);
		probePollTimer = setTimeout(async () => {
			await loadProbeStatus();
			if (isJobActive(probeStatus.job?.status)) pollProbeStatus();
		}, 3000);
	};

	const probeBusy = $derived(probeTriggering || isJobActive(probeStatus.job?.status));

	// Called by the preview dialog with the user's rule/hash selection.
	const triggerProbe = async (ruleIds: string[], hashes: string[]): Promise<boolean> => {
		probeTriggering = true;
		probeError = '';
		try {
			const body: any = {};
			if (ruleIds.length > 0) body.rule_ids = ruleIds;
			if (hashes.length > 0) body.hashes = hashes;
			const response = await fetch('/api/admin/secrets/probe', {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(body)
			});
			if (response.status === 409) {
				probeError = 'A probe job is already queued or running.';
				return false;
			}
			if (!response.ok) {
				probeError = 'Failed to start probe.';
				return false;
			}
			await loadProbeStatus();
			pollProbeStatus();
			return true;
		} catch {
			probeError = 'Failed to start probe.';
			return false;
		} finally {
			probeTriggering = false;
		}
	};

	onMount(() => {
		if (!browser) return;
		loadProbeStatus().then(() => {
			if (isJobActive(probeStatus.job?.status)) pollProbeStatus();
		});
		return () => {
			if (probePollTimer) clearTimeout(probePollTimer);
		};
	});
</script>

<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
	<header class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">Secret Probe</h2>
			<p class="text-sm text-[var(--text-tertiary)]">Validate discovered secrets to check if they are still live, expired, or revoked.</p>
		</div>
		<button
			type="button"
			class="inline-flex items-center gap-2 rounded-full border border-[var(--border-color)] px-4 py-2 text-sm font-semibold text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
			onclick={() => previewDialog.show()}
			disabled={probeBusy}
		>
			<Eye size={14} />
			Preview Secret Probe
		</button>
	</header>

	{#if probeError}
		<div class="rounded-2xl border border-[var(--error)]/30 bg-[var(--error)]/5 p-4 text-sm text-[var(--error)]">
			{probeError}
		</div>
	{/if}

	{#if probeStatus.job?.error}
		<div class="rounded-2xl border border-[var(--error)]/30 bg-[var(--error)]/5 p-4">
			<p class="text-xs font-semibold uppercase tracking-wider text-[var(--error)]">Error</p>
			<p class="mt-1 text-sm text-[var(--text-secondary)]">{probeStatus.job.error}</p>
		</div>
	{/if}

	<!-- Stats cards -->
	<div class="grid gap-3 grid-cols-5">
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<ShieldCheck size={16} />
				<span>Status</span>
			</div>
			{#if probeStatus.job}
				<p class="mt-2 text-sm font-semibold">
					<span class="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs {jobStatusClass(probeStatus.job.status)}">
						{jobStatusLabel(probeStatus.job.status, { succeeded: 'Complete', never: 'Never triggered' })}
					</span>
				</p>
				{#if probeStatus.job.created_at}
					<p class="mt-1 flex items-center gap-1 text-[11px] text-[var(--text-muted)]">
						<Clock size={10} /> Started {new Date(probeStatus.job.created_at).toLocaleString()}
					</p>
				{/if}
				{#if probeStatus.job.finished_at}
					<p class="mt-0.5 text-[11px] text-[var(--text-muted)]">Finished {new Date(probeStatus.job.finished_at).toLocaleString()}</p>
				{/if}
			{:else}
				<p class="mt-2 text-sm text-[var(--text-muted)]">Never triggered</p>
			{/if}
		</div>
		<button
			type="button"
			class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-left transition hover:border-[var(--accent)]/40 {probeStatus.stats.total === 0 ? 'opacity-50 pointer-events-none' : 'cursor-pointer'}"
			onclick={() => listDialog.show('Secrets probed', ['valid', 'invalid', 'revoked', 'expired', 'unknown', 'error', 'false_positive'])}
		>
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<KeyRound size={16} />
				<span>Secrets probed</span>
			</div>
			<p class="mt-2 text-2xl font-semibold text-[var(--text-bright)]">
				{#if probeStatus.job?.status === 'RUNNING' && probeStatus.job?.result?.probed != null}
					{probeStatus.job.result.probed} <span class="text-sm font-normal text-[var(--text-muted)]">/ {probeStatus.job.result.total}</span>
				{:else}
					{probeStatus.stats.total}
				{/if}
			</p>
			{#if probeStatus.job?.status === 'RUNNING' && probeStatus.job?.result?.total > 0}
				{@const pct = Math.round((probeStatus.job.result.probed / probeStatus.job.result.total) * 100)}
				<div class="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-[var(--border-color)]">
					<div class="h-full rounded-full bg-amber-400 transition-all duration-500" style="width: {pct}%"></div>
				</div>
				<p class="mt-1 text-[11px] text-[var(--text-muted)]">{pct}% probed</p>
			{/if}
		</button>
		<button
			type="button"
			class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-left transition hover:border-red-400/40 {probeStatus.stats.valid === 0 ? 'opacity-50 pointer-events-none' : 'cursor-pointer'}"
			onclick={() => listDialog.show('Live secrets', ['valid'])}
		>
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<ShieldAlert size={16} />
				<span>Live secrets</span>
			</div>
			<p class="mt-2 text-2xl font-semibold text-red-400">{probeStatus.stats.valid}</p>
			{#if probeStatus.stats.valid > 0}
				<p class="mt-1 text-[11px] text-[var(--text-muted)]">Require immediate rotation</p>
			{/if}
		</button>
		<button
			type="button"
			class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-left transition hover:border-green-400/40 {(probeStatus.stats.revoked + probeStatus.stats.expired + probeStatus.stats.invalid) === 0 ? 'opacity-50 pointer-events-none' : 'cursor-pointer'}"
			onclick={() => listDialog.show('Rotated / Safe', ['revoked', 'expired', 'invalid'])}
		>
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<ShieldCheck size={16} />
				<span>Rotated / Safe</span>
			</div>
			<p class="mt-2 text-2xl font-semibold text-green-400">{probeStatus.stats.revoked + probeStatus.stats.expired + probeStatus.stats.invalid}</p>
			{#if probeStatus.stats.unknown > 0}
				<p class="mt-1 text-[11px] text-[var(--text-muted)]">{probeStatus.stats.unknown} unknown</p>
			{/if}
		</button>
		<button
			type="button"
			class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-left transition hover:border-[var(--border-color)] {probeStatus.stats.false_positive === 0 ? 'opacity-50 pointer-events-none' : 'cursor-pointer'}"
			onclick={() => listDialog.show('False positives', ['false_positive'])}
		>
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<span>False positives</span>
			</div>
			<p class="mt-2 text-2xl font-semibold text-[var(--text-muted)]">{probeStatus.stats.false_positive}</p>
			<p class="mt-1 text-[11px] text-[var(--text-muted)]">Placeholder or test values</p>
		</button>
	</div>
</section>

<SecretProbeListDialog bind:this={listDialog} />
<SecretProbePreviewDialog
	bind:this={previewDialog}
	error={probeError}
	triggering={probeTriggering}
	onStart={triggerProbe}
	onStatusRefresh={loadProbeStatus}
/>
