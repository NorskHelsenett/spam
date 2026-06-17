<script lang="ts">
	import type { PopoverData } from './chainLayout';

	let { popover, onClose }: { popover: PopoverData; onClose: () => void } = $props();
</script>

<div class="rounded-lg border border-[var(--border-color)]/60 bg-[var(--bg)] px-4 py-3 text-xs shadow-lg">
	<div class="flex items-center justify-between">
		<span class="font-semibold text-[var(--text-bright)]">{popover.title}</span>
		<button class="text-[var(--text-muted)] hover:text-[var(--text-bright)]" onclick={onClose}>&times;</button>
	</div>
	<div class="mt-1.5 space-y-0.5">
		{#each popover.lines as line}
			<div class="whitespace-pre-wrap text-[var(--text-secondary)]">{line}</div>
		{/each}
	</div>
	{#if popover.containers?.length}
		<div class="mt-2 space-y-1.5">
			{#each popover.containers as c}
				{@const fullRef = `${c.registry ? c.registry + '/' : ''}${c.image}${c.digest ? '@' + c.digest : c.tag ? ':' + c.tag : ''}`}
				<div class="relative rounded bg-[var(--bg2)]/40 px-2.5 py-1.5">
					<button
						type="button"
						class="absolute right-2 top-1.5 rounded px-1.5 py-0.5 text-[10px] text-[var(--text-muted)] transition hover:bg-[var(--bg3)] hover:text-[var(--text-bright)]"
						title="Copy: docker pull {fullRef}"
						onclick={() => navigator.clipboard.writeText(`docker pull ${fullRef}`)}
					>
						<svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
					</button>
					<div class="flex items-baseline gap-1">
						<span class="text-[var(--text-muted)]">image</span>
						<code class="text-[var(--text-bright)]">{c.registry ? c.registry + '/' : ''}{c.image}</code>
					</div>
					{#if c.tag}
						<div class="mt-0.5 flex items-baseline gap-1">
							<span class="text-[var(--text-muted)]">tag</span>
							<code class="text-[var(--green)]">{c.tag}</code>
						</div>
					{/if}
					{#if c.digest}
						<div class="mt-0.5 flex items-baseline gap-1">
							<span class="text-[var(--text-muted)]">digest</span>
							<code class="truncate text-[var(--text-tertiary)]">{c.digest}</code>
						</div>
					{/if}
				</div>
			{/each}
		</div>
	{/if}
</div>
