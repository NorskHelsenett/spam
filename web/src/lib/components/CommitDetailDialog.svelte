<script lang="ts">
	import { browser } from '$app/environment';
	import Copy from 'lucide-svelte/icons/copy';
	import Check from 'lucide-svelte/icons/check';
	import ExternalLink from 'lucide-svelte/icons/external-link';
	import ShieldCheck from 'lucide-svelte/icons/shield-check';
	import ShieldAlert from 'lucide-svelte/icons/shield-alert';
	import ShieldOff from 'lucide-svelte/icons/shield-off';
	import Package from 'lucide-svelte/icons/package';
	import Radio from 'lucide-svelte/icons/radio';
	import GitCommit from 'lucide-svelte/icons/git-commit';
	import X from 'lucide-svelte/icons/x';

	export type CommitImage = {
		registry: string;
		repository: string;
		digest: string;
	};

	export type CommitDetail = {
		sha: string;
		message: string;
		author_name: string;
		author_email: string;
		author_date: string;
		author_login?: string;
		author_avatar?: string;
		commit_url?: string;
		signed?: string;
		image_count?: number;
		live_pod_count?: number;
		live_cluster_count?: number;
		images?: CommitImage[];
	};

	interface Props {
		open: boolean;
		commit: CommitDetail | null;
		onClose?: () => void;
	}

	let { open = $bindable(false), commit, onClose = () => {} }: Props = $props();

	const signedState = $derived.by(() => {
		const s = commit?.signed ?? '';
		switch (s) {
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

	const formatFullDate = (iso: string) => {
		if (!iso) return '';
		const d = new Date(iso);
		if (isNaN(d.getTime())) return iso;
		return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
	};

	let copiedSha = $state(false);
	let copiedEmail = $state(false);
	let copiedImageIdx = $state<number | null>(null);
	let copyTimer: ReturnType<typeof setTimeout> | null = null;

	const copy = async (value: string, kind: 'sha' | 'email' | 'image', idx = -1) => {
		if (!browser) return;
		await navigator.clipboard.writeText(value);
		if (kind === 'sha') copiedSha = true;
		else if (kind === 'email') copiedEmail = true;
		else copiedImageIdx = idx;
		if (copyTimer) clearTimeout(copyTimer);
		copyTimer = setTimeout(() => {
			copiedSha = false;
			copiedEmail = false;
			copiedImageIdx = null;
		}, 1400);
	};

	const imageRef = (img: CommitImage) =>
		`${img.registry}/${img.repository}@${img.digest}`;

	const close = () => {
		open = false;
		onClose();
	};

	$effect(() => {
		if (!browser) return;
		if (open) {
			const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') close(); };
			document.addEventListener('keydown', onKey);
			return () => document.removeEventListener('keydown', onKey);
		}
	});
</script>

{#if open && commit}
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<!-- svelte-ignore a11y_click_events_have_key_events -->
	<div
		class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 pt-16 backdrop-blur-sm"
		role="presentation"
		onclick={(e) => { if (e.target === e.currentTarget) close(); }}
	>
		<div class="w-full max-w-2xl" role="dialog" aria-modal="true">
			<section class="overflow-hidden rounded-2xl border border-[var(--border-color)] bg-[var(--bg)] shadow-2xl">
				<!-- Header -->
				<header class="flex items-start justify-between gap-3 border-b border-[var(--border-color)]/60 px-6 py-4">
					<div class="flex min-w-0 items-center gap-3">
						<GitCommit class="h-5 w-5 flex-shrink-0 text-[var(--accent)]" />
						<div class="min-w-0">
							<h2 class="truncate text-base font-semibold text-[var(--text-bright)]">Commit</h2>
							<p class="text-[11px] text-[var(--text-muted)]">{formatFullDate(commit.author_date)}</p>
						</div>
					</div>
					<button
						type="button"
						class="rounded-lg p-1.5 text-[var(--text-muted)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-secondary)]"
						onclick={close}
						aria-label="Close"
					>
						<X class="h-4 w-4" />
					</button>
				</header>

				<!-- Body -->
				<div class="space-y-5 px-6 py-5">
					<!-- Author -->
					<div class="flex items-start gap-3">
						{#if commit.author_avatar}
							<img src={commit.author_avatar} alt={commit.author_login || commit.author_name} class="h-10 w-10 flex-shrink-0 rounded-full" />
						{:else}
							<div class="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-full bg-[var(--accent)]/20 text-sm font-medium text-[var(--accent)]">
								{commit.author_name.charAt(0).toUpperCase()}
							</div>
						{/if}
						<div class="min-w-0 flex-1">
							<p class="truncate text-sm font-medium text-[var(--text-bright)]">
								{commit.author_name}
								{#if commit.author_login && commit.author_login !== commit.author_name}
									<span class="ml-1 text-xs font-normal text-[var(--text-muted)]">@{commit.author_login}</span>
								{/if}
							</p>
							{#if commit.author_email}
								<button
									type="button"
									class="mt-0.5 inline-flex items-center gap-1.5 text-xs text-[var(--text-secondary)] hover:text-[var(--accent)]"
									onclick={() => copy(commit.author_email, 'email')}
									title="Copy email"
								>
									<span class="truncate">{commit.author_email}</span>
									{#if copiedEmail}
										<Check class="h-3 w-3 text-[var(--success)]" />
									{:else}
										<Copy class="h-3 w-3 text-[var(--text-muted)]" />
									{/if}
								</button>
							{/if}
						</div>
					</div>

					<!-- Message -->
					<div>
						<p class="mb-1.5 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">Message</p>
						<pre class="whitespace-pre-wrap break-words rounded-lg border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40 p-3 font-mono text-[11px] leading-relaxed text-[var(--text-secondary)]">{commit.message}</pre>
					</div>

					<!-- Status tiles -->
					<div>
						<p class="mb-1.5 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">Status</p>
						<dl class="grid gap-3 sm:grid-cols-3">
							<div class="flex items-start gap-2 rounded-lg border border-[var(--border-color)]/30 bg-[var(--card-bg)]/20 px-3 py-2">
								<signedState.Icon class="mt-0.5 h-4 w-4 flex-shrink-0 {toneClass(signedState.tone)}" />
								<div class="min-w-0 flex-1">
									<dt class="text-[9px] uppercase tracking-wider text-[var(--text-muted)]">Signed</dt>
									<dd class="text-xs text-[var(--text-secondary)]">{signedState.label}</dd>
								</div>
							</div>

							<div class="flex items-start gap-2 rounded-lg border border-[var(--border-color)]/30 bg-[var(--card-bg)]/20 px-3 py-2">
								<Package class="mt-0.5 h-4 w-4 flex-shrink-0 {(commit.image_count ?? 0) > 0 ? 'text-[var(--accent)]' : 'text-[var(--text-muted)] opacity-40'}" />
								<div class="min-w-0 flex-1">
									<dt class="text-[9px] uppercase tracking-wider text-[var(--text-muted)]">Built</dt>
									<dd class="text-xs text-[var(--text-secondary)]">
										{#if (commit.image_count ?? 0) === 0}
											No image
										{:else if commit.image_count === 1}
											1 image
										{:else}
											{commit.image_count} images
										{/if}
									</dd>
								</div>
							</div>

							<div class="flex items-start gap-2 rounded-lg border border-[var(--border-color)]/30 bg-[var(--card-bg)]/20 px-3 py-2">
								<Radio class="mt-0.5 h-4 w-4 flex-shrink-0 {(commit.live_pod_count ?? 0) > 0 ? 'text-[var(--success)]' : 'text-[var(--text-muted)] opacity-40'}" />
								<div class="min-w-0 flex-1">
									<dt class="text-[9px] uppercase tracking-wider text-[var(--text-muted)]">Live</dt>
									<dd class="text-xs text-[var(--text-secondary)]">
										{#if (commit.live_pod_count ?? 0) === 0}
											Not running
										{:else}
											{commit.live_pod_count} pod{commit.live_pod_count === 1 ? '' : 's'} / {commit.live_cluster_count ?? 0} cluster{commit.live_cluster_count === 1 ? '' : 's'}
										{/if}
									</dd>
								</div>
							</div>
						</dl>
					</div>

					{#if commit.images && commit.images.length > 0}
						<div>
							<p class="mb-1.5 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">Images built</p>
							<ul class="space-y-1.5">
								{#each commit.images as img, i (img.registry + img.repository + img.digest)}
									<li class="flex items-center gap-2 rounded-lg border border-[var(--border-color)]/30 bg-[var(--card-bg)]/30 px-3 py-2">
										<Package class="h-3.5 w-3.5 flex-shrink-0 text-[var(--accent)]" />
										<span class="min-w-0 flex-1 truncate font-mono text-[11px] text-[var(--text-secondary)]" title={imageRef(img)}>{imageRef(img)}</span>
										<button
											type="button"
											class="inline-flex items-center gap-1 rounded-md border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40 px-2 py-1 text-[10px] text-[var(--text-muted)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
											onclick={() => copy(imageRef(img), 'image', i)}
											title="Copy docker pull reference"
										>
											{#if copiedImageIdx === i}
												<Check class="h-3 w-3 text-[var(--success)]" />
												<span>Copied</span>
											{:else}
												<Copy class="h-3 w-3" />
												<span>Copy</span>
											{/if}
										</button>
									</li>
								{/each}
							</ul>
						</div>
					{/if}
				</div>

				<!-- Footer -->
				<footer class="flex items-center justify-between gap-3 border-t border-[var(--border-color)]/60 bg-[var(--card-bg)]/30 px-6 py-3">
					<button
						type="button"
						class="inline-flex items-center gap-2 rounded-lg border border-[var(--border-color)]/40 bg-[var(--card-bg)]/40 px-2.5 py-1.5 font-mono text-[11px] text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
						onclick={() => copy(commit.sha, 'sha')}
						title="Copy SHA"
					>
						<span class="truncate">{commit.sha}</span>
						{#if copiedSha}
							<Check class="h-3 w-3 flex-shrink-0 text-[var(--success)]" />
						{:else}
							<Copy class="h-3 w-3 flex-shrink-0 text-[var(--text-muted)]" />
						{/if}
					</button>
					{#if commit.commit_url}
						<a
							href={commit.commit_url}
							target="_blank"
							rel="noopener noreferrer"
							class="inline-flex items-center gap-1.5 text-xs text-[var(--accent)] hover:underline"
						>
							View on provider
							<ExternalLink class="h-3 w-3" />
						</a>
					{/if}
				</footer>
			</section>
		</div>
	</div>
{/if}
