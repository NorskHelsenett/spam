<script lang="ts">
	import type { Snippet } from 'svelte';
	import { GitBranch, Container, ChevronDown, ArrowUpRight, BellOff, Wrench } from 'lucide-svelte';
	import KubernetesIcon from '$lib/components/icons/KubernetesIcon.svelte';

	// One triage finding row. Presentational + reusable: the live page
	// feeds it real data and an expandable `detail` snippet; the
	// playground feeds it mock data so the design can be previewed in
	// isolation. No severity is encoded as a coloured edge — urgency
	// reads from the coloured reason pills and the tier the row sits in.
	type Reason = { label: string; cls: string };

	let {
		assetType,
		assetSlug,
		trustGrade,
		href,
		primaryAction,
		reasons = [],
		open = false,
		readOnly = false,
		onToggle = () => {},
		onAcknowledge = () => {},
		detail
	}: {
		assetType: string;
		assetSlug: string;
		trustGrade: string;
		href: string;
		primaryAction: string;
		reasons?: Reason[];
		open?: boolean;
		readOnly?: boolean;
		onToggle?: () => void;
		onAcknowledge?: () => void;
		detail?: Snippet;
	} = $props();

	const Icon = $derived(
		assetType === 'repo' ? GitBranch : assetType === 'image' ? Container : KubernetesIcon
	);

	const trustColor = (grade: string): string => {
		if (grade.startsWith('A')) return 'var(--success)';
		if (grade.startsWith('B')) return 'var(--accent)';
		if (grade === 'C') return 'var(--warning)';
		return 'var(--error)';
	};

	const shown = $derived(reasons.slice(0, 3));
	const moreCount = $derived(Math.max(0, reasons.length - 3));
</script>

<div class="finding" class:open>
	<div
		role="button"
		tabindex="0"
		class="finding-main"
		aria-expanded={open}
		onclick={onToggle}
		onkeydown={(e) => {
			if (e.key === 'Enter' || e.key === ' ') {
				e.preventDefault();
				onToggle();
			}
		}}
	>
		<div class="finding-body">
			<div class="finding-top">
				<Icon size={15} class="shrink-0 text-[var(--text-muted)]" />
				<span class="finding-slug">{assetSlug}</span>
				<span class="badge">{assetType}</span>
				<span class="finding-trust" style="color: {trustColor(trustGrade)}" title="Trust grade">Trust {trustGrade}</span>
			</div>
			<p class="finding-action">
				<Wrench size={13} class="shrink-0" />
				<span>{primaryAction}</span>
			</p>
			{#if shown.length > 0}
				<div class="finding-pills">
					{#each shown as r}
						<span class={r.cls}>{r.label}</span>
					{/each}
					{#if moreCount > 0}
						<span class="pill pill-neutral">+{moreCount} more</span>
					{/if}
				</div>
			{/if}
		</div>
		<div class="finding-actions">
			<button
				type="button"
				class="finding-btn"
				disabled={readOnly}
				title={readOnly ? 'Read-only role' : 'Acknowledge this finding'}
				onclick={(e) => {
					e.stopPropagation();
					if (!readOnly) onAcknowledge();
				}}
			>
				<BellOff size={12} /> Acknowledge
			</button>
			<a
				class="finding-btn finding-btn-open"
				{href}
				title="Open {assetType} detail"
				onclick={(e) => e.stopPropagation()}
			>
				Open <ArrowUpRight size={12} />
			</a>
			<ChevronDown size={16} class="finding-chevron {open ? 'open' : ''}" />
		</div>
	</div>

	{#if open && detail}
		<div class="finding-detail">
			{@render detail()}
		</div>
	{/if}
</div>

<style>
	/* Flat bordered card — playground card language, no drop shadows and
	   no coloured edge. Accent border only on hover/open (interaction,
	   not severity). */
	.finding {
		border: 1px solid color-mix(in srgb, var(--border-color) 60%, transparent);
		border-radius: 1rem;
		background: color-mix(in srgb, var(--card-bg) 40%, transparent);
		overflow: hidden;
		transition: border-color 120ms ease, background 120ms ease;
	}
	.finding:hover,
	.finding.open {
		border-color: color-mix(in srgb, var(--accent) 45%, var(--border-color));
		background: var(--card-bg);
	}

	.finding-main {
		display: flex;
		align-items: flex-start;
		gap: 1rem;
		width: 100%;
		padding: 0.85rem 1rem;
		border: 0;
		background: transparent;
		color: inherit;
		text-align: left;
		font: inherit;
		cursor: pointer;
	}

	.finding-body {
		flex: 1;
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 0.4rem;
	}
	.finding-top {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		flex-wrap: wrap;
	}
	.finding-slug {
		font-weight: 600;
		color: var(--text-bright);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		max-width: 60vw;
	}
	.finding-trust {
		margin-left: auto;
		font-size: 0.72rem;
		font-weight: 600;
		white-space: nowrap;
	}

	/* The at-a-glance "do this" line — the whole point of the row. */
	.finding-action {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		margin: 0;
		font-size: 0.92rem;
		font-weight: 600;
		color: var(--text-bright);
	}
	.finding-action :global(svg) {
		color: var(--accent);
	}

	.finding-pills {
		display: flex;
		flex-wrap: wrap;
		gap: 0.35rem;
	}

	.finding-actions {
		display: flex;
		align-items: center;
		gap: 0.4rem;
		flex-shrink: 0;
		color: var(--text-muted);
	}
	.finding-btn {
		display: inline-flex;
		align-items: center;
		gap: 0.3rem;
		padding: 0.35rem 0.65rem;
		border: 1px solid var(--border-color);
		border-radius: 0.6rem;
		font-size: 0.72rem;
		font-weight: 600;
		color: var(--text-secondary);
		background: var(--card-bg);
		cursor: pointer;
		text-decoration: none;
		white-space: nowrap;
		transition: color 120ms ease, border-color 120ms ease, background 120ms ease;
	}
	.finding-btn:hover {
		color: var(--text-bright);
		border-color: color-mix(in srgb, var(--accent) 55%, transparent);
		background: color-mix(in srgb, var(--accent) 8%, var(--card-bg));
	}
	.finding-btn:disabled {
		opacity: 0.4;
		cursor: not-allowed;
	}
	.finding-btn-open:hover {
		color: var(--accent);
	}
	.finding-chevron {
		transition: transform 120ms ease, color 120ms ease;
	}
	:global(.finding-chevron.open) {
		transform: rotate(180deg);
		color: var(--accent);
	}

	.finding-detail {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		padding: 0.5rem 1rem 1rem;
		border-top: 1px solid color-mix(in srgb, var(--border-color) 50%, transparent);
	}
</style>
