<script lang="ts">
	import Dialog from './Dialog.svelte';
	import { AlertTriangle, ClockAlert, ShieldOff } from 'lucide-svelte';

	// Acknowledgment dialog for a single triage bucket (asset). Lets the
	// operator pick one of three suppressions, write a free-text reason,
	// and (for snooze) set a date. Mirrors the API: POST
	// /api/triage/acknowledge with {asset_type, asset_id, action,
	// reason_text, snooze_until?}.
	//
	// The "Suppress unless infra changes" path captures the current
	// signals fingerprint server-side; the dashboard's next refresh
	// revokes the ack automatically if anything material changes
	// (KEV/critical/exposure/scan freshness/etc).
	type Action = 'snooze' | 'suppress_until_change' | 'accept_risk';

	type HistoryRow = {
		id: string;
		action: string;
		reason_text: string;
		snooze_until?: string | null;
		created_by: string;
		created_at: string;
		revoked_at?: string | null;
		revoked_by?: string | null;
		revoked_reason?: string | null;
	};

	let {
		open = $bindable(false),
		assetType,
		assetSlug,
		assetId,
		headlineReasons = [],
		history = [],
		readOnly = false,
		onAcknowledged = () => {}
	}: {
		open?: boolean;
		assetType: string;
		assetSlug: string;
		assetId: string;
		headlineReasons?: string[];
		history?: HistoryRow[];
		readOnly?: boolean;
		onAcknowledged?: () => void;
	} = $props();

	let action = $state<Action>('snooze');
	let reasonText = $state('');
	// Default snooze: today + 7 days, formatted as YYYY-MM-DD for the
	// native date input.
	const defaultSnoozeISO = () => {
		const d = new Date();
		d.setDate(d.getDate() + 7);
		return d.toISOString().slice(0, 10);
	};
	let snoozeDate = $state(defaultSnoozeISO());
	let submitting = $state(false);
	let error = $state('');

	$effect(() => {
		if (open) {
			action = 'snooze';
			reasonText = '';
			snoozeDate = defaultSnoozeISO();
			submitting = false;
			error = '';
		}
	});

	const fmtAction = (a: string) => {
		switch (a) {
			case 'snooze':
				return 'snoozed';
			case 'suppress_until_change':
				return 'suppressed until change';
			case 'accept_risk':
				return 'accepted risk';
		}
		return a;
	};

	const submit = async () => {
		if (readOnly) return;
		if (!reasonText.trim()) {
			error = 'Reason is required';
			return;
		}
		submitting = true;
		error = '';
		const body: Record<string, unknown> = {
			asset_type: assetType,
			asset_id: assetId,
			action,
			reason_text: reasonText.trim()
		};
		if (action === 'snooze') {
			// Encode as RFC3339 at end-of-day UTC so the snooze covers
			// the chosen calendar day.
			const isoDate = `${snoozeDate}T23:59:59Z`;
			body.snooze_until = isoDate;
		}
		try {
			const res = await fetch('/api/triage/acknowledge', {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(body)
			});
			if (!res.ok) {
				const text = await res.text();
				throw new Error(text || `HTTP ${res.status}`);
			}
			open = false;
			onAcknowledged();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to acknowledge';
		} finally {
			submitting = false;
		}
	};
</script>

<Dialog bind:open maxWidth="max-w-2xl">
	<div class="space-y-5 p-6">
		<header class="space-y-1">
			<div class="flex items-center gap-2 text-xs uppercase tracking-widest text-[var(--text-tertiary)]">
				<span class="badge">{assetType}</span>
				<span>Acknowledge</span>
			</div>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">{assetSlug}</h2>
			{#if headlineReasons.length > 0}
				<div class="rounded-lg border border-[var(--border-color)] bg-[var(--card-bg)] px-3 py-2 text-sm text-[var(--text-secondary)]">
					<div class="text-xs uppercase tracking-widest text-[var(--text-tertiary)]">In the queue because</div>
					<ul class="mt-1 list-disc pl-5">
						{#each headlineReasons as r}
							<li>{r}</li>
						{/each}
					</ul>
				</div>
			{/if}
		</header>

		{#if readOnly}
			<div class="rounded-lg border border-[var(--warning)]/30 bg-[var(--warning)]/10 px-3 py-2 text-sm text-[var(--warning)]">
				Read-only role — you can view the history but not record acknowledgments.
			</div>
		{:else}
			<fieldset class="space-y-3">
				<legend class="text-xs uppercase tracking-widest text-[var(--text-tertiary)]">Action</legend>

				<label class="ack-option" class:active={action === 'snooze'}>
					<input type="radio" bind:group={action} value="snooze" />
					<div class="ack-option-body">
						<div class="ack-option-head"><ClockAlert size={14} /> <span>Snooze until…</span></div>
						<p class="ack-option-desc">Re-surfaces automatically when the date passes.</p>
						{#if action === 'snooze'}
							<input
								type="date"
								class="input mt-2"
								bind:value={snoozeDate}
								min={new Date().toISOString().slice(0, 10)}
							/>
						{/if}
					</div>
				</label>

				<label class="ack-option" class:active={action === 'suppress_until_change'}>
					<input type="radio" bind:group={action} value="suppress_until_change" />
					<div class="ack-option-body">
						<div class="ack-option-head"><AlertTriangle size={14} /> <span>Suppress unless infrastructure changes</span></div>
						<p class="ack-option-desc">
							Captures the current threat & trust signals. The next refresh that detects
							any signal change automatically clears this acknowledgment.
						</p>
					</div>
				</label>

				<label class="ack-option" class:active={action === 'accept_risk'}>
					<input type="radio" bind:group={action} value="accept_risk" />
					<div class="ack-option-body">
						<div class="ack-option-head"><ShieldOff size={14} /> <span>Accept risk (permanent)</span></div>
						<p class="ack-option-desc">Stays suppressed until someone manually revokes it.</p>
					</div>
				</label>
			</fieldset>

			<label class="block space-y-1">
				<span class="text-xs uppercase tracking-widest text-[var(--text-tertiary)]">Reason (required)</span>
				<textarea
					bind:value={reasonText}
					rows="3"
					class="input w-full font-mono"
					placeholder="e.g. mitigated by WAF rule X, pending vendor patch ETA 2026-06-30…"
				></textarea>
			</label>

			{#if error}
				<div class="rounded-lg border border-[var(--error)]/30 bg-[var(--error)]/10 px-3 py-2 text-sm text-[var(--error)]">{error}</div>
			{/if}
		{/if}

		{#if history.length > 0}
			<section class="space-y-2">
				<div class="text-xs uppercase tracking-widest text-[var(--text-tertiary)]">History</div>
				<ul class="space-y-1 text-sm">
					{#each history as h}
						<li class="flex flex-wrap items-center gap-x-2 gap-y-0.5 rounded border border-[var(--border-color)] bg-[var(--card-bg)] px-2 py-1">
							<span class="text-[var(--text-muted)]">{new Date(h.created_at).toISOString().slice(0, 10)}</span>
							<span class="text-[var(--text-bright)]">{h.created_by}</span>
							<span class="text-[var(--text-secondary)]">{fmtAction(h.action)}</span>
							{#if h.revoked_at}
								<span class="text-[var(--text-muted)]">
									→ revoked {new Date(h.revoked_at).toISOString().slice(0, 10)}
									{#if h.revoked_reason}({h.revoked_reason}){/if}
								</span>
							{/if}
							{#if h.reason_text}
								<div class="w-full pl-1 text-xs text-[var(--text-tertiary)]">"{h.reason_text}"</div>
							{/if}
						</li>
					{/each}
				</ul>
			</section>
		{/if}

		<footer class="flex justify-end gap-2 pt-2">
			<button type="button" class="btn btn-ghost" onclick={() => (open = false)} disabled={submitting}>
				Cancel
			</button>
			{#if !readOnly}
				<button type="button" class="btn btn-primary" onclick={submit} disabled={submitting}>
					{submitting ? 'Saving…' : 'Acknowledge'}
				</button>
			{/if}
		</footer>
	</div>
</Dialog>

<style>
	.ack-option {
		display: flex;
		gap: 0.6rem;
		align-items: flex-start;
		padding: 0.6rem 0.7rem;
		border: 1px solid var(--border-color);
		border-radius: 0.6rem;
		cursor: pointer;
		background: var(--card-bg);
		transition: border-color 120ms ease, background 120ms ease;
	}
	.ack-option:hover {
		border-color: color-mix(in srgb, var(--accent) 40%, var(--border-color));
	}
	.ack-option.active {
		border-color: color-mix(in srgb, var(--accent) 60%, var(--border-color));
		background: color-mix(in srgb, var(--accent) 6%, var(--card-bg));
	}
	.ack-option input[type='radio'] {
		margin-top: 0.4rem;
	}
	.ack-option-body {
		flex: 1;
	}
	.ack-option-head {
		display: inline-flex;
		align-items: center;
		gap: 0.4rem;
		font-weight: 600;
		color: var(--text-bright);
		font-size: 0.92rem;
	}
	.ack-option-desc {
		margin: 0.15rem 0 0;
		font-size: 0.8rem;
		color: var(--text-secondary);
		line-height: 1.4;
	}
</style>
