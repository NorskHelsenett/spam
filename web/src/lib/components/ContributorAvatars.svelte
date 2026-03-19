<script lang="ts">
	import { browser } from '$app/environment';
	import Copy from 'lucide-svelte/icons/copy';

	export type Contributor = {
		login?: string;
		name?: string;
		email?: string;
		avatar_url?: string;
		profile_url?: string;
		contributions?: number;
	};

	interface Props {
		contributors: Contributor[];
		max?: number;
	}

	let { contributors = [], max = 8 }: Props = $props();

	let hovered: Contributor | null = $state(null);
	let tipPos = $state({ x: 0, y: 0 });
	let hideTimer: ReturnType<typeof setTimeout> | null = null;
	let copiedEmail = $state('');
	let copiedTimer: ReturnType<typeof setTimeout> | null = null;
	let tipEl: HTMLDivElement | undefined = $state();

	const show = (e: MouseEvent, c: Contributor) => {
		if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
		const target = e.currentTarget as HTMLElement;
		const rect = target.getBoundingClientRect();
		tipPos = { x: rect.left + rect.width / 2, y: rect.top - 8 };
		hovered = c;
	};

	const scheduleHide = () => {
		if (hideTimer) clearTimeout(hideTimer);
		hideTimer = setTimeout(() => { hovered = null; }, 120);
	};

	const clearHide = () => {
		if (hideTimer) { clearTimeout(hideTimer); hideTimer = null; }
	};

	const copyEmail = async (c: Contributor) => {
		if (!c.email || !browser) return;
		await navigator.clipboard.writeText(c.email);
		copiedEmail = c.email;
		if (copiedTimer) clearTimeout(copiedTimer);
		copiedTimer = setTimeout(() => { copiedEmail = ''; }, 1400);
	};

	function portal(node: HTMLElement) {
		document.body.appendChild(node);
		return {
			destroy() { node.remove(); }
		};
	}
</script>

<div class="flex items-center gap-2">
	<div class="flex -space-x-1.5">
		{#each contributors.slice(0, max) as c, i (i)}
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div
				class="cursor-pointer"
				onmouseenter={(e) => show(e, c)}
				onmouseleave={scheduleHide}
			>
				{#if c.avatar_url}
					<img
						class="contributor-avatar h-5 w-5 rounded-full ring-1 ring-[var(--bg-soft)]"
						src={c.avatar_url}
						alt={c.login || c.name || ''}
					/>
				{:else}
					<div class="contributor-avatar flex h-5 w-5 items-center justify-center rounded-full bg-[var(--hover-bg)] text-[8px] font-semibold text-[var(--text-muted)] ring-1 ring-[var(--bg-soft)]">
						{(c.login || c.name || '?')[0].toUpperCase()}
					</div>
				{/if}
			</div>
		{/each}
	</div>
	{#if contributors.length <= 3}
		<span class="text-[10px] text-[var(--text-muted)]">{contributors.map(c => c.login || c.name).join(', ')}</span>
	{:else if contributors.length > max}
		<span class="text-[10px] text-[var(--text-muted)]">+{contributors.length - max} more</span>
	{:else}
		<span class="text-[10px] text-[var(--text-muted)]">{contributors[0]?.login || contributors[0]?.name}{contributors.length > 1 ? ` +${contributors.length - 1}` : ''}</span>
	{/if}
</div>

{#if hovered}
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div
		bind:this={tipEl}
		use:portal
		class="contributor-tip-layer"
		style="left: {tipPos.x}px; top: {tipPos.y}px;"
		onmouseenter={clearHide}
		onmouseleave={scheduleHide}
	>
		<button
			type="button"
			class="tip-card"
			onclick={() => copyEmail(hovered!)}
			disabled={!hovered.email}
		>
			{#if hovered.avatar_url}
				<img src={hovered.avatar_url} alt={hovered.login || hovered.name || ''} class="mb-2 h-10 w-10 rounded-full" />
			{:else}
				<div class="mb-2 flex h-10 w-10 items-center justify-center rounded-full bg-[var(--hover-bg)] text-sm font-semibold text-[var(--text-secondary)]">
					{(hovered.login || hovered.name || '?')[0].toUpperCase()}
				</div>
			{/if}
			<p class="text-[11px] font-semibold text-[var(--text-bright)]">{hovered.login || hovered.name || '—'}</p>
			{#if hovered.email}
				<p class="mt-0.5 w-full break-all text-[10px] text-[var(--text-muted)]">{hovered.email}</p>
				<p class="mt-1 text-[9px] text-[var(--text-tertiary)]">{copiedEmail === hovered.email ? 'Copied!' : 'Click to copy email'}</p>
			{:else}
				<p class="mt-1 text-[9px] text-[var(--text-muted)]">No email available</p>
			{/if}
		</button>
	</div>
{/if}

<style>
	:global(.contributor-tip-layer) {
		position: fixed;
		z-index: 1200;
		transform: translate(-50%, calc(-100% + 6px)) scale(0.9) rotate(5deg);
		pointer-events: auto;
		opacity: 0;
		animation: contributor-tip-in 180ms cubic-bezier(0.34, 1.56, 0.64, 1) forwards;
		transform-origin: bottom center;
		will-change: transform, opacity;
	}

	:global(.tip-card) {
		width: 14rem;
		background: var(--bg-soft);
		border: 1px solid var(--border-color);
		border-radius: 0.75rem;
		padding: 0.75rem;
		box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
		text-align: center;
		display: flex;
		flex-direction: column;
		align-items: center;
		cursor: pointer;
	}

	:global(.tip-card:disabled) {
		cursor: default;
		background: var(--bg-soft);
		opacity: 1;
	}

	@keyframes contributor-tip-in {
		from {
			opacity: 0;
			transform: translate(-50%, calc(-100% + 6px)) scale(0.9) rotate(5deg);
		}
		to {
			opacity: 1;
			transform: translate(-50%, -100%) scale(1) rotate(-2deg);
		}
	}
</style>
