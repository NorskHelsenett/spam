<script lang="ts">
	import { FileWarning, X, KeyRound } from 'lucide-svelte';

	type Finding = {
		rule_id: string;
		description: string;
		file: string;
		start_line: number;
		match: string;
	};

	const cleanMatch = (s: string) =>
		s.endsWith('"') && !s.slice(0, -1).includes('"') ? s.slice(0, -1) : s;

	const tryDecodeBase64 = (s: string): string | null => {
		const decode = (candidate: string): string | null => {
			const norm = candidate.replace(/-/g, '+').replace(/_/g, '/');
			const padded = norm + '=='.slice(0, (4 - (norm.length % 4)) % 4);
			if (padded.length < 8 || !/^[A-Za-z0-9+/]+=*$/.test(padded)) return null;
			try {
				const decoded = atob(padded);
				if (/[\x00-\x08\x0e-\x1f\x7f]/.test(decoded)) return null;
				try { return JSON.stringify(JSON.parse(decoded), null, 2); } catch { /* not json */ }
				return decoded;
			} catch {
				return null;
			}
		};

		const b64chars = '[A-Za-z0-9+/\\-_]';
		const candidates: (string | null | undefined)[] = [
			// key := "value" or key = "value" (assignment with quoted string)
			s.match(new RegExp(`:=?\\s*["'](${b64chars}+=*)["']$`))?.[1],
			// Key: value  (header-style, e.g. "Token: cashuAeyJ...")
			s.match(new RegExp(`:\\s*(${b64chars}+=*)$`))?.[1],
			// Bare assignment: key=value (no quotes, = not part of base64 padding)
			s.match(new RegExp(`[^=]=["']?(${b64chars}+=*)["']?$`))?.[1],
			// First eyJ... substring (base64-encoded JSON — very common for JWTs / tokens)
			s.match(new RegExp(`eyJ${b64chars}+=*`))?.[0],
			// Whole string
			s,
		];

		for (const c of candidates) {
			if (!c) continue;
			const result = decode(c);
			if (result) return result;
		}
		return null;
	};


	let {
		repoId,
		repoName,
		onClose = () => {}
	}: {
		repoId: string;
		repoName: string;
		onClose?: () => void;
	} = $props();

	let findings: Finding[] = $state([]);
	let loading = $state(false);
	let activeFilter: string | null = $state(null);

	const grouped = $derived.by(() => {
		const map = new Map<string, Finding[]>();
		for (const f of findings) {
			const key = f.rule_id || 'unknown';
			if (!map.has(key)) map.set(key, []);
			map.get(key)!.push(f);
		}
		return Array.from(map.entries());
	});

	const visibleGroups = $derived(
		activeFilter ? grouped.filter(([ruleId]) => ruleId === activeFilter) : grouped
	);

	$effect(() => {
		if (repoId) { activeFilter = null; load(); }
	});

	const load = async () => {
		loading = true;
		findings = [];
		try {
			const params = new URLSearchParams({ repo_id: repoId });
			const res = await fetch(`/api/secrets/findings?${params}`, { credentials: 'include' });
			if (res.ok) findings = await res.json();
		} catch {
			// ignore
		} finally {
			loading = false;
		}
	};
</script>

<div class="flex h-full flex-col overflow-hidden rounded-l-[10px] bg-[var(--bg-soft)]">
	<!-- Header -->
	<div class="shrink-0 p-7">
		<div class="flex items-start gap-3">
			<KeyRound class="mt-0.5 h-5 w-5 shrink-0 text-[var(--accent)]" />
			<div class="min-w-0 flex-1">
				<div class="flex items-center gap-2">
					<a
						href="/app/providers/repo/{repoId}"
						class="truncate text-base font-semibold text-[var(--text-bright)] hover:text-[var(--accent)] hover:underline"
					>
						{repoName}
					</a>
				</div>
				{#if !loading && findings.length > 0}
					<p class="mt-0.5 text-[11px] text-[var(--text-muted)]">
						{findings.length} finding{findings.length !== 1 ? 's' : ''}
					</p>
					<div class="mt-2 flex flex-wrap gap-1.5">
						{#each grouped as [ruleId, group]}
							<button
								type="button"
								onclick={() => activeFilter = activeFilter === ruleId ? null : ruleId}
								class="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium transition {activeFilter === ruleId ? 'border-red-500/70 bg-red-500/20 text-red-300' : activeFilter ? 'border-red-500/20 bg-red-500/5 text-red-400/40' : 'border-red-500/40 bg-red-500/10 text-red-400 hover:border-red-500/60 hover:bg-red-500/15'}"
							>
								<FileWarning class="h-3 w-3 shrink-0" />
								{ruleId}
								<span class="ml-0.5 font-semibold">{group.length}</span>
							</button>
						{/each}
					</div>
				{/if}
			</div>
			<button
				type="button"
				class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition hover:bg-[var(--hover-bg)]"
				onclick={onClose}
				aria-label="Close"
			>
				<X size={18} stroke-width={2} />
			</button>
		</div>
	</div>

	<!-- Body -->
	{#if loading}
		<div class="flex flex-1 items-center justify-center p-8">
			<div class="h-6 w-6 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
		</div>
	{:else if findings.length === 0}
		<div class="flex flex-1 items-center justify-center p-8 text-center">
			<p class="text-sm text-[var(--text-muted)]">No findings for this repo.</p>
		</div>
	{:else}
		<div class="flex-1 overflow-y-auto bg-[var(--bg-soft)]">
			{#each visibleGroups as [ruleId, group]}
				<div>
					<!-- Group header -->
					<div class="flex items-center justify-center gap-3 px-7 py-4">
						<div class="h-px w-28 bg-[var(--border-color)]/60"></div>
						<div class="flex flex-col items-center gap-0.5">
							<span class="text-sm font-semibold text-[var(--text-secondary)]">{ruleId}</span>
							<span class="text-[11px] text-[var(--text-muted)]">{group.length} finding{group.length !== 1 ? 's' : ''}</span>
						</div>
						<div class="h-px w-28 bg-[var(--border-color)]/60"></div>
					</div>
					<!-- Findings -->
					<div class="space-y-1 px-4 py-2 bg-[var(--bg-soft)]">
						{#each group as f}
							<article class="rounded-xl px-5 py-4 transition-colors hover:bg-[var(--hover-bg-subtle)]">
								<div class="flex items-start gap-4">
									<div class="w-40 shrink-0 pt-0.5">
										<span class="inline-flex items-center gap-1 rounded-full border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-xs font-semibold text-red-400">
											<FileWarning class="h-3 w-3 shrink-0" />
											<span class="truncate">{f.rule_id}</span>
										</span>
									</div>
									<div class="min-w-0 flex-1 space-y-1.5">
										{#if f.description}
											<p class="text-sm text-[var(--text-secondary)]">{f.description}</p>
										{/if}
										{#if f.file}
											<p class="font-mono text-xs text-[var(--text-muted)]">{f.file}{f.start_line ? `:${f.start_line}` : ''}</p>
										{/if}
										{#if f.match}
											{@const raw = cleanMatch(f.match)}
											{@const decoded = tryDecodeBase64(raw)}
											<div class="inline-block max-w-full break-all rounded bg-[var(--card-bg)] px-2 py-1.5 font-mono text-xs text-[var(--text-muted)]">{raw}</div>
											{#if decoded}
												<div class="block whitespace-pre-wrap break-all rounded bg-[var(--card-bg)] px-2 py-1.5 font-mono text-xs text-[var(--text-muted)] opacity-70">{decoded}</div>
											{/if}
										{/if}
									</div>
								</div>
							</article>
						{/each}
					</div>
				</div>
			{/each}
		</div>
	{/if}
</div>
