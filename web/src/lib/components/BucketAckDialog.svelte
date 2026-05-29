<script lang="ts">
	import Dialog from './Dialog.svelte';
	import { BellOff, ClockAlert, RefreshCw, X } from 'lucide-svelte';

	// Acknowledgment dialog for a single triage bucket (asset). The
	// scoring engine captures a *snapshot* (signals fingerprint) at ack
	// time, so there are only two coherent choices:
	//   1. Snooze   — postpone this snapshot to a date.
	//   2. Accept   — accept this snapshot's risk; the next refresh that
	//                 detects ANY signal change re-surfaces it, because a
	//                 changed snapshot is no longer the one we accepted.
	// "Accept" maps to the backend's suppress_until_change action (which
	// records the fingerprint and is auto-revoked on drift). There is no
	// permanent-through-changes option — that would accept a snapshot we
	// can no longer see.
	type Action = 'snooze' | 'suppress_until_change';

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

	// Two snapshot choices. "effect" is the at-a-glance consequence tag.
	const options: {
		value: Action;
		icon: typeof ClockAlert;
		title: string;
		desc: string;
		effect: string;
	}[] = [
		{
			value: 'snooze',
			icon: ClockAlert,
			title: 'Snooze until a date',
			desc: 'Postpone this snapshot. Hides it now and brings it back automatically on the date you pick.',
			effect: 'Temporary'
		},
		{
			value: 'suppress_until_change',
			icon: RefreshCw,
			title: 'Accept the risk',
			desc: "Accept this asset's current threat snapshot. If a CVE, exposure, or any scored signal changes, it's a new snapshot — so it comes back on its own.",
			effect: 'Until signals change'
		}
	];

	const fmtAction = (a: string) => {
		switch (a) {
			case 'snooze':
				return 'snoozed';
			case 'suppress_until_change':
				return 'accepted the risk';
			case 'accept_risk':
				return 'accepted the risk (permanent)';
		}
		return a;
	};

	const submit = async () => {
		if (readOnly) return;
		if (!reasonText.trim()) {
			error = 'Add a short reason so the next person knows why this is hidden.';
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

<Dialog bind:open maxWidth="max-w-2xl" showCloseButton={false}>
	<div class="flex max-h-[95vh] flex-col">
		<header class="flex items-start gap-3 border-b border-[var(--border-color)]/60 px-6 py-5 sm:px-8">
			<div class="min-w-0 flex-1">
				<div class="flex items-center gap-2 text-[11px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
					<BellOff size={13} class="text-[var(--accent)]" />
					<span>Acknowledge finding</span>
					<span class="badge">{assetType}</span>
				</div>
				<h2 class="mt-2 truncate text-xl font-semibold text-[var(--text-bright)]">{assetSlug}</h2>
				<p class="mt-1 text-sm text-[var(--text-tertiary)]">
					Acknowledging hides a finding from the active queue — it doesn't fix it. Pick what should happen to it.
				</p>
			</div>
			<button
				type="button"
				class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-transparent text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
				aria-label="Close"
				onclick={() => (open = false)}
			>
				<X size={20} />
			</button>
		</header>

		<div class="space-y-6 overflow-y-auto px-6 py-6 sm:px-8">
			{#if headlineReasons.length > 0}
				<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
					<p class="text-[11px] uppercase tracking-[0.2em] text-[var(--text-muted)]">Why it's in the queue</p>
					<div class="mt-2 flex flex-wrap gap-1.5">
						{#each headlineReasons as r}
							<span class="pill pill-warning">{r}</span>
						{/each}
					</div>
				</div>
			{/if}

			{#if readOnly}
				<div class="rounded-2xl border border-[var(--warning)]/30 bg-[var(--warning)]/10 px-4 py-3 text-sm text-[var(--warning)]">
					Your role is read-only — you can review the history below, but not hide findings.
				</div>
			{:else}
				<fieldset class="space-y-3">
					<legend class="text-[11px] uppercase tracking-[0.2em] text-[var(--text-muted)]">What should happen?</legend>

					{#each options as opt}
						{@const Icon = opt.icon}
						<label class="ack-option" class:active={action === opt.value}>
							<input type="radio" bind:group={action} value={opt.value} />
							<div class="min-w-0 flex-1">
								<div class="flex items-center gap-2">
									<Icon size={15} class="shrink-0 text-[var(--accent)]" />
									<span class="font-semibold text-[var(--text-bright)]">{opt.title}</span>
									<span class="ack-effect">{opt.effect}</span>
								</div>
								<p class="mt-1 text-sm text-[var(--text-secondary)]">{opt.desc}</p>
								{#if opt.value === 'snooze' && action === 'snooze'}
									<div class="mt-3 flex items-center gap-2">
										<span class="text-xs text-[var(--text-tertiary)]">Bring back on</span>
										<input
											type="date"
											class="input ack-date"
											bind:value={snoozeDate}
											min={new Date().toISOString().slice(0, 10)}
										/>
									</div>
								{/if}
							</div>
						</label>
					{/each}
				</fieldset>

				<div class="space-y-2">
					<label for="ack-reason" class="block text-[11px] uppercase tracking-[0.2em] text-[var(--text-muted)]">
						Reason <span class="text-[var(--accent)]">(required)</span>
					</label>
					<textarea
						id="ack-reason"
						bind:value={reasonText}
						rows="3"
						class="input"
						placeholder="e.g. mitigated by WAF rule X — vendor patch expected 2026-06-30"
					></textarea>
				</div>

				{#if error}
					<div class="rounded-2xl border border-[var(--error)]/30 bg-[var(--error)]/10 px-4 py-3 text-sm text-[var(--error)]">{error}</div>
				{/if}
			{/if}

			{#if history.length > 0}
				<section class="space-y-2">
					<p class="text-[11px] uppercase tracking-[0.2em] text-[var(--text-muted)]">Previously acknowledged</p>
					<ul class="space-y-1.5">
						{#each history as h}
							<li class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-3 py-2 text-sm">
								<div class="flex flex-wrap items-center gap-x-2 gap-y-0.5">
									<span class="text-[var(--text-muted)]">{new Date(h.created_at).toISOString().slice(0, 10)}</span>
									<span class="font-medium text-[var(--text-bright)]">{h.created_by}</span>
									<span class="text-[var(--text-secondary)]">{fmtAction(h.action)}</span>
									{#if h.revoked_at}
										<span class="pill pill-neutral">
											revoked {new Date(h.revoked_at).toISOString().slice(0, 10)}{#if h.revoked_reason} · {h.revoked_reason}{/if}
										</span>
									{/if}
								</div>
								{#if h.reason_text}
									<p class="mt-1 text-xs italic text-[var(--text-tertiary)]">"{h.reason_text}"</p>
								{/if}
							</li>
						{/each}
					</ul>
				</section>
			{/if}
		</div>

		<footer class="flex justify-end gap-2 border-t border-[var(--border-color)]/60 px-6 py-4 sm:px-8">
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
	/* Action cards: flat bordered surface, accent ring when picked —
	   matches the playground card language (no drop shadows). */
	.ack-option {
		display: flex;
		gap: 0.7rem;
		align-items: flex-start;
		padding: 0.8rem 0.9rem;
		border: 1px solid color-mix(in srgb, var(--border-color) 60%, transparent);
		border-radius: 1rem;
		cursor: pointer;
		background: color-mix(in srgb, var(--card-bg) 40%, transparent);
		transition: border-color 120ms ease, background 120ms ease;
	}
	.ack-option:hover {
		border-color: color-mix(in srgb, var(--accent) 40%, var(--border-color));
	}
	.ack-option.active {
		border-color: var(--accent);
		background: color-mix(in srgb, var(--accent) 8%, transparent);
	}

	.ack-effect {
		margin-left: auto;
		flex-shrink: 0;
		font-size: 0.65rem;
		font-weight: 600;
		letter-spacing: 0.08em;
		text-transform: uppercase;
		color: var(--text-muted);
	}

	.ack-date {
		width: auto;
		padding: 0.4rem 0.75rem;
		font-size: 0.85rem;
		border-radius: 0.75rem;
	}

	/* Radio dot lifted from the shared Radio component so the dialog
	   matches the playground's animated accent dot rather than the raw
	   browser control. */
	.ack-option input[type='radio'] {
		appearance: none;
		margin-top: 0.15rem;
		width: 18px;
		height: 18px;
		border-radius: 999px;
		border: 1px solid var(--border-color);
		background: var(--card-bg);
		display: inline-grid;
		place-items: center;
		cursor: pointer;
		flex-shrink: 0;
		transition: border-color 150ms ease, background 150ms ease, box-shadow 150ms ease;
	}
	.ack-option input[type='radio']::after {
		content: '';
		width: 8px;
		height: 8px;
		border-radius: 999px;
		background: var(--accent);
		transform: scale(0);
		transition: transform 120ms ease;
	}
	.ack-option input[type='radio']:checked {
		background: color-mix(in srgb, var(--accent) 18%, transparent);
		border-color: var(--accent);
	}
	.ack-option input[type='radio']:checked::after {
		transform: scale(1);
		animation: radio-pop 180ms ease-out;
	}
	.ack-option input[type='radio']:focus-visible {
		outline: none;
		box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 35%, transparent);
	}

	@keyframes radio-pop {
		0% {
			transform: scale(0.3);
		}
		70% {
			transform: scale(1.2);
		}
		100% {
			transform: scale(1);
		}
	}
</style>
