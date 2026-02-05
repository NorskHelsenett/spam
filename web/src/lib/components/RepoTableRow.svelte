<script lang="ts">
	import { GitBranch, Archive, GitFork, Lock, ExternalLink } from 'lucide-svelte';
	import type { RepoData } from '$lib/types/providers';

	interface Props {
		repo: RepoData;
		showPath?: boolean;
		onSelect: () => void;
		formatDate: (date: string) => string;
	}

	let { repo, showPath = false, onSelect, formatDate }: Props = $props();
</script>

<tr
	class="cursor-pointer transition hover:bg-[var(--hover-bg-subtle)]"
	ondblclick={onSelect}
>
	<td class="px-5 py-3">
		<button
			type="button"
			class="flex items-center gap-2 text-left"
			onclick={onSelect}
		>
			<GitBranch class="h-4 w-4 text-[var(--accent)]" />
			<span class="font-semibold text-[var(--text-bright)] hover:text-[var(--accent)] hover:underline">
				{repo.name}
			</span>
		</button>
		{#if repo.description}
			<p class="mt-0.5 line-clamp-1 text-xs text-[var(--text-muted)]" title={repo.description}>
				{repo.description}
			</p>
		{/if}
		{#if repo.topics && repo.topics.length > 0}
			<div class="mt-1 flex flex-wrap gap-1">
				{#each repo.topics.slice(0, 3) as topic}
					<span class="rounded-full bg-[var(--accent)]/10 px-2 py-0.5 text-[10px] text-[var(--accent)]">
						{topic}
					</span>
				{/each}
				{#if repo.topics.length > 3}
					<span class="text-[10px] text-[var(--text-muted)]">+{repo.topics.length - 3} more</span>
				{/if}
			</div>
		{/if}
	</td>
	{#if showPath}
		<td class="px-5 py-3">
			<span class="text-xs text-[var(--text-muted)]">{repo.full_path}</span>
		</td>
	{/if}
	<td class="px-5 py-3">
		{#if repo.languages && repo.languages.length > 0}
			<div class="flex flex-wrap gap-1">
				{#each repo.languages.slice(0, 3) as lang}
					<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs">
						{lang}
					</span>
				{/each}
				{#if repo.languages.length > 3}
					<span class="text-[10px] text-[var(--text-muted)]">+{repo.languages.length - 3}</span>
				{/if}
			</div>
		{:else}
			<span class="text-[var(--text-muted)]">—</span>
		{/if}
	</td>
	<td class="px-5 py-3 text-xs">
		{formatDate(repo.pushed_at || repo.updated_at)}
	</td>
	<td class="px-5 py-3 text-center">
		<div class="flex items-center justify-center gap-1">
			{#if repo.is_archived}
				<span title="Archived" class="text-[var(--text-muted)]">
					<Archive class="h-3.5 w-3.5" />
				</span>
			{/if}
			{#if repo.is_fork}
				<span title="Fork" class="text-[var(--text-muted)]">
					<GitFork class="h-3.5 w-3.5" />
				</span>
			{/if}
			{#if repo.is_private}
				<span title="Private" class="text-[var(--text-muted)]">
					<Lock class="h-3.5 w-3.5" />
				</span>
			{/if}
			{#if !repo.is_archived && !repo.is_fork && !repo.is_private}
				<span class="text-[var(--text-muted)]">—</span>
			{/if}
		</div>
	</td>
	<td class="px-5 py-3 text-right">
		<a
			href={repo.html_url}
			target="_blank"
			rel="noopener noreferrer"
			class="inline-flex items-center gap-1 text-xs text-[var(--accent)] hover:underline"
			onclick={(e) => e.stopPropagation()}
		>
			View <ExternalLink class="h-3 w-3" />
		</a>
	</td>
</tr>
