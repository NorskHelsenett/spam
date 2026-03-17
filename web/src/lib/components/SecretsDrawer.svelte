<script lang="ts">
	import { FileWarning, X, KeyRound } from 'lucide-svelte';
	import { SvelteMap, SvelteSet } from 'svelte/reactivity';

	type Finding = {
		rule_id: string;
		description: string;
		file: string;
		start_line: number;
		match: string;
	};

	type FindingsPage = {
		items: Finding[];
		total: number;
	};

	const PAGE_SIZE = 100;

	const cleanMatch = (s: string) =>
		s.endsWith('"') && !s.slice(0, -1).includes('"') ? s.slice(0, -1) : s;

	const extractPemKey = (s: string): string | null => {
		const match = s.match(/-----BEGIN [A-Z0-9 ]+ KEY-----[\s\S]+?-----END [A-Z0-9 ]+ KEY-----/);
		return match ? match[0] : null;
	};

	const findAllBase64 = (s: string): Array<{value: string, decoded: string}> => {
		const results: Array<{value: string, decoded: string}> = [];
		const seen = new SvelteSet<string>();

		// First, specifically find JWT tokens (always start with eyJ)
		const jwtPattern = /eyJ[A-Za-z0-9+/\-_]+={0,2}/g;
		let jwtMatch;
		while ((jwtMatch = jwtPattern.exec(s)) !== null) {
			const candidate = jwtMatch[0];
			if (seen.has(candidate)) continue;
			seen.add(candidate);

			const decoded = tryDecodeBase64(candidate);
			if (decoded && decoded !== candidate) {
				results.push({ value: candidate, decoded });
			}
		}

		// Then find other base64 patterns
		const b64Pattern = /(?:^|[:\s=])([A-Za-z0-9+/\-_]{16,}={0,2})(?:[\s"']|$)/g;
		let match;
		while ((match = b64Pattern.exec(s)) !== null) {
			const candidate = match[1];
			if (candidate.length < 16 || seen.has(candidate)) continue;
			seen.add(candidate);

			// Skip URLs and hex-only strings
			if (/^[0-9a-fA-F]+$/.test(candidate)) continue;

			const decoded = tryDecodeBase64(candidate);
			if (decoded && decoded !== candidate) {
				results.push({ value: candidate, decoded });
			}
		}
		return results;
	};

	const tryDecodeBase64 = (s: string): string | null => {
		const decode = (candidate: string): string | null => {
			const norm = candidate.replace(/-/g, '+').replace(/_/g, '/');
			const padded = norm + '=='.slice(0, (4 - (norm.length % 4)) % 4);
			if (padded.length < 8 || !/^[A-Za-z0-9+/]+=*$/.test(padded)) return null;
			try {
				const decoded = atob(padded);
				// Reject strings with control characters
				// eslint-disable-next-line no-control-regex
				if (/[\x00-\x08\x0e-\x1f\x7f]/.test(decoded)) return null;
				// Reject if less than 70% printable ASCII or valid UTF-8
				const printable = decoded.split('').filter(c => {
					const code = c.charCodeAt(0);
					return (code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13 || code >= 128;
				}).length;
				if (printable / decoded.length < 0.7) return null;
				// Reject very short decoded strings unless they look like structured data
				if (decoded.length < 10 && !/[{[\n:]/.test(decoded)) return null;

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
			// YAML-style with trailing text: "key: <base64> kind: Secret" or similar
			s.match(new RegExp(`:\\s+(${b64chars}{32,}=*)\\s+\\w+:`))?.[1],
			// Longest base64 sequence (40+ chars, must have variety to avoid false positives)
			(() => {
				const match = s.match(new RegExp(`${b64chars}{40,}=*`))?.[0];
				// Ensure it has enough entropy (not just repeated chars)
				if (match && new Set(match.slice(0, 20)).size >= 8) return match;
				return null;
			})(),
			// First eyJ... substring (base64-encoded JSON — very common for JWTs / tokens)
			s.match(new RegExp(`eyJ${b64chars}+=*`))?.[0],
			// Whole string (only if it's long enough and looks base64-ish)
			s.length >= 16 && /^[A-Za-z0-9+/\-_]+=*$/.test(s) ? s : null,
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
		initialFilters = [],
		onClose = () => {}
	}: {
		repoId: string;
		repoName: string;
		initialFilters?: string[];
		onClose?: () => void;
	} = $props();

	let findings: Finding[] = $state([]);
	let total = $state(0);
	let loading = $state(false);
	let loadingMore = $state(false);
	let activeFilters = new SvelteSet<string>();
	let sentinelEl: HTMLDivElement | undefined = $state();

	const hasMore = $derived(findings.length < total);

	const toggleFilter = (ruleId: string) => {
		if (activeFilters.has(ruleId)) {
			activeFilters.delete(ruleId);
		} else {
			activeFilters.add(ruleId);
		}
	};

	const grouped = $derived.by(() => {
		const map = new SvelteMap<string, Finding[]>();
		for (const f of findings) {
			const key = f.rule_id || 'unknown';
			if (!map.has(key)) map.set(key, []);
			map.get(key)!.push(f);
		}
		return Array.from(map.entries());
	});

	const visibleGroups = $derived(
		activeFilters.size > 0 ? grouped.filter(([ruleId]) => activeFilters.has(ruleId)) : grouped
	);

	let prevRepoId = '';
	$effect(() => {
		const id = repoId;
		if (id && id !== prevRepoId) {
			prevRepoId = id;
			activeFilters.clear();
			for (const f of initialFilters) activeFilters.add(f);
			load();
		}
	});

	// Intersection observer for infinite scroll
	$effect(() => {
		if (!sentinelEl) return;
		const observer = new IntersectionObserver(
			(entries) => {
				if (entries[0].isIntersecting && hasMore && !loadingMore && !loading) {
					loadMore();
				}
			},
			{ rootMargin: '200px' }
		);
		observer.observe(sentinelEl);
		return () => observer.disconnect();
	});

	const load = async () => {
		loading = true;
		findings = [];
		total = 0;
		try {
			const params = new URLSearchParams({ repo_id: repoId, limit: String(PAGE_SIZE), offset: '0' });
			const res = await fetch(`/api/secrets/findings?${params}`, { credentials: 'include' });
			if (res.ok) {
				const page: FindingsPage = await res.json();
				findings = page.items;
				total = page.total;
			}
		} catch {
			// ignore
		} finally {
			loading = false;
		}
	};

	const loadMore = async () => {
		if (loadingMore || !hasMore) return;
		loadingMore = true;
		try {
			const params = new URLSearchParams({
				repo_id: repoId,
				limit: String(PAGE_SIZE),
				offset: String(findings.length)
			});
			const res = await fetch(`/api/secrets/findings?${params}`, { credentials: 'include' });
			if (res.ok) {
				const page: FindingsPage = await res.json();
				findings = [...findings, ...page.items];
				total = page.total;
			}
		} catch {
			// ignore
		} finally {
			loadingMore = false;
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
				{#if !loading && total > 0}
					<p class="mt-0.5 text-[11px] text-[var(--text-muted)]">
						{total.toLocaleString()} finding{total !== 1 ? 's' : ''}
						{#if findings.length < total}
							<span class="text-[var(--text-muted)]">({findings.length.toLocaleString()} loaded)</span>
						{/if}
					</p>
					<div class="mt-2 flex flex-wrap gap-1.5">
						{#each grouped as [ruleId, group] (ruleId)}
							<button
								type="button"
								onclick={() => toggleFilter(ruleId)}
								class="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium transition {activeFilters.has(ruleId) ? 'border-red-500/70 bg-red-500/20 text-red-300' : activeFilters.size > 0 ? 'border-red-500/20 bg-red-500/5 text-red-400/40' : 'border-red-500/40 bg-red-500/10 text-red-400 hover:border-red-500/60 hover:bg-red-500/15'}"
							>
								<FileWarning class="h-3 w-3 shrink-0" />
								{ruleId}
								<span class="ml-0.5 font-semibold">{group.length}{#if hasMore}+{/if}</span>
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
			{#each visibleGroups as [ruleId, group] (ruleId)}
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
						{#each group as f, idx (`${idx}-${f.file}-${f.start_line}`)}
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
											{@const pemKey = extractPemKey(raw)}
											{@const base64Matches = findAllBase64(raw)}

											<div class="inline-block max-w-full break-all rounded bg-[var(--card-bg)] px-2 py-1.5 font-mono text-xs text-[var(--text-muted)]">{raw}</div>

											{#if pemKey}
												<div class="whitespace-pre-wrap block max-w-full break-all rounded bg-[var(--card-bg)] px-2 py-1.5 font-mono text-xs text-[var(--text-muted)] opacity-70">{pemKey}</div>
											{/if}

											{#each base64Matches as { decoded }, di (di)}
												<div class="whitespace-pre-wrap block max-w-full break-all rounded bg-[var(--card-bg)] px-2 py-1.5 font-mono text-xs text-[var(--text-muted)] opacity-70">{decoded}</div>
											{/each}
										{/if}
									</div>
								</div>
							</article>
						{/each}
					</div>
				</div>
			{/each}

			<!-- Infinite scroll sentinel -->
			{#if hasMore}
				<div bind:this={sentinelEl} class="flex items-center justify-center py-6">
					{#if loadingMore}
						<div class="h-5 w-5 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
					{:else}
						<span class="text-xs text-[var(--text-muted)]">Scroll for more…</span>
					{/if}
				</div>
			{/if}
		</div>
	{/if}
</div>
