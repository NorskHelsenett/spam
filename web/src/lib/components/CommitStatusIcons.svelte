<script lang="ts">
	import ShieldCheck from 'lucide-svelte/icons/shield-check';
	import ShieldAlert from 'lucide-svelte/icons/shield-alert';
	import ShieldOff from 'lucide-svelte/icons/shield-off';
	import Package from 'lucide-svelte/icons/package';
	import Radio from 'lucide-svelte/icons/radio';
	import HoverCard from './HoverCard.svelte';

	interface Props {
		/** git %G? output: G/B/U/X/Y/R/E/N — empty means unknown. */
		signed?: string;
		imageCount?: number;
		livePodCount?: number;
		liveClusterCount?: number;
	}

	let {
		signed = '',
		imageCount = 0,
		livePodCount = 0,
		liveClusterCount = 0
	}: Props = $props();

	const signedState = $derived.by(() => {
		switch (signed) {
			case 'G':
				return { label: 'Good signature', tone: 'good' as const, Icon: ShieldCheck };
			case 'U':
				return { label: 'Signed — signer unknown', tone: 'muted' as const, Icon: ShieldAlert };
			case 'X':
				return { label: 'Signed — signature expired', tone: 'warn' as const, Icon: ShieldAlert };
			case 'Y':
				return { label: 'Signed — key expired', tone: 'warn' as const, Icon: ShieldAlert };
			case 'R':
				return { label: 'Signed — key revoked', tone: 'bad' as const, Icon: ShieldOff };
			case 'B':
				return { label: 'Bad signature', tone: 'bad' as const, Icon: ShieldOff };
			case 'E':
				return { label: 'Signature check failed', tone: 'bad' as const, Icon: ShieldOff };
			case 'N':
				return { label: 'Not signed', tone: 'muted' as const, Icon: ShieldCheck };
			default:
				return { label: 'Signature status unknown', tone: 'muted' as const, Icon: ShieldCheck };
		}
	});

	const hasImage = $derived(imageCount > 0);
	const isLive = $derived(livePodCount > 0);

	// Muted tone shares the same faded look as the unfilled Package/Radio
	// icons below, so the three-icon row reads as one coherent "empty vs
	// filled" pipeline when a commit has no signals yet.
	const toneClass = (tone: 'good' | 'warn' | 'bad' | 'muted') => {
		switch (tone) {
			case 'good':
				return 'text-[var(--success)]';
			case 'warn':
				return 'text-[var(--warning)]';
			case 'bad':
				return 'text-[var(--error)]';
			default:
				return 'text-[var(--text-muted)] opacity-40';
		}
	};
</script>

<HoverCard width={16}>
	<span class="inline-flex items-center gap-1">
		<signedState.Icon class="h-3.5 w-3.5 {toneClass(signedState.tone)}" />
		<Package class="h-3.5 w-3.5 {hasImage ? 'text-[var(--accent)]' : 'text-[var(--text-muted)] opacity-40'}" />
		<Radio class="h-3.5 w-3.5 {isLive ? 'text-[var(--success)]' : 'text-[var(--text-muted)] opacity-40'}" />
	</span>
	{#snippet content()}
		<dl class="space-y-2 text-[11px]">
			<div class="flex items-start gap-2">
				<signedState.Icon class="mt-0.5 h-3.5 w-3.5 flex-shrink-0 {toneClass(signedState.tone)}" />
				<div class="min-w-0 flex-1">
					<dt class="text-[9px] uppercase tracking-wider text-[var(--text-muted)]">Signed</dt>
					<dd class="text-[var(--text-secondary)]">{signedState.label}</dd>
				</div>
			</div>
			<div class="flex items-start gap-2">
				<Package class="mt-0.5 h-3.5 w-3.5 flex-shrink-0 {hasImage ? 'text-[var(--accent)]' : 'text-[var(--text-muted)] opacity-40'}" />
				<div class="min-w-0 flex-1">
					<dt class="text-[9px] uppercase tracking-wider text-[var(--text-muted)]">Built</dt>
					<dd class="text-[var(--text-secondary)]">
						{#if imageCount === 0}
							No image built from this commit
						{:else if imageCount === 1}
							1 image built
						{:else}
							{imageCount} images built
						{/if}
					</dd>
				</div>
			</div>
			<div class="flex items-start gap-2">
				<Radio class="mt-0.5 h-3.5 w-3.5 flex-shrink-0 {isLive ? 'text-[var(--success)]' : 'text-[var(--text-muted)] opacity-40'}" />
				<div class="min-w-0 flex-1">
					<dt class="text-[9px] uppercase tracking-wider text-[var(--text-muted)]">Live</dt>
					<dd class="text-[var(--text-secondary)]">
						{#if livePodCount === 0}
							Not running in any cluster
						{:else}
							{livePodCount} pod{livePodCount === 1 ? '' : 's'} across {liveClusterCount} cluster{liveClusterCount === 1 ? '' : 's'}
						{/if}
					</dd>
				</div>
			</div>
		</dl>
	{/snippet}
</HoverCard>
