<script lang="ts">
	import { FileWarning, X, KeyRound, Globe, Lock, GitCommitHorizontal, GitBranch, Clock, Users, Copy } from 'lucide-svelte';
	import ContributorAvatars from '$lib/components/ContributorAvatars.svelte';
	import { SvelteMap, SvelteSet } from 'svelte/reactivity';

	type Finding = {
		rule_id: string;
		effective_rule_id?: string;
		description: string;
		file: string;
		start_line: number;
		match: string;
		secret?: string;
		entropy?: number;
		sub_type?: string;
		probe_status?: string;
		probe_reason?: string;
		dismissed: boolean;
		secret_hash?: string;
	};

	type FindingsPage = {
		items: Finding[];
		total: number;
	};

	type RepoDetails = {
		description: string;
		is_private: boolean;
		updated_at: string;
		stats: {
			stars: number;
			forks: number;
			watchers: number;
			commits: number;
			branches: number;
			releases: number;
			contributors: number;
		};
	};

	type ContributorInfo = {
		login?: string;
		name?: string;
		email?: string;
		avatar_url?: string;
		profile_url?: string;
		contributions: number;
	};

	const PAGE_SIZE = 100;

	const fmtRelative = (iso: string) => {
		const diff = Date.now() - new Date(iso).getTime();
		const days = Math.floor(diff / 86_400_000);
		if (days === 0) return 'today';
		if (days === 1) return 'yesterday';
		if (days < 30) return `${days}d ago`;
		if (days < 365) return `${Math.floor(days / 30)}mo ago`;
		return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
	};

	const cleanMatch = (s: string) =>
		s.endsWith('"') && !s.slice(0, -1).includes('"') ? s.slice(0, -1) : s;

	const extractPemKey = (s: string): string | null => {
		const match = s.match(/-----BEGIN [A-Z0-9 ]+ KEY-----[\s\S]+?-----END [A-Z0-9 ]+ KEY-----/);
		return match ? match[0] : null;
	};

	type JWTInfo = {
		header: Record<string, unknown>;
		payload: Record<string, unknown>;
		expired: boolean | null;
		expiresAt: string | null;
		issuedAt: string | null;
		issuer: string | null;
		subject: string | null;
	};

	const tryDecodeJWT = (s: string): JWTInfo | null => {
		// Find JWT in the string (eyJ...something.eyJ...something.signature)
		const jwtMatch = s.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
		if (!jwtMatch) return null;
		const token = jwtMatch[0];
		const parts = token.split('.');
		if (parts.length !== 3) return null;

		const decode = (part: string): Record<string, unknown> | null => {
			try {
				const norm = part.replace(/-/g, '+').replace(/_/g, '/');
				const padded = norm + '=='.slice(0, (4 - (norm.length % 4)) % 4);
				return JSON.parse(atob(padded));
			} catch { return null; }
		};

		const header = decode(parts[0]);
		const payload = decode(parts[1]);
		if (!header || !payload) return null;

		const exp = typeof payload.exp === 'number' ? payload.exp : null;
		const iat = typeof payload.iat === 'number' ? payload.iat : null;

		return {
			header,
			payload,
			expired: exp != null ? exp * 1000 < Date.now() : null,
			expiresAt: exp != null ? new Date(exp * 1000).toISOString() : null,
			issuedAt: iat != null ? new Date(iat * 1000).toISOString() : null,
			issuer: typeof payload.iss === 'string' ? payload.iss : null,
			subject: typeof payload.sub === 'string' ? payload.sub : null,
		};
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
	let repoDetails: RepoDetails | null = $state(null);
	let contributors: ContributorInfo[] = $state([]);
	let detailsError: string | null = $state(null);
	let showInactive = $state(false);

	const isInactive = (f: Finding) =>
		f.dismissed || f.probe_status === 'expired' || f.probe_status === 'invalid' || f.probe_status === 'false_positive';

	const activeFindings = $derived(
		showInactive ? findings : findings.filter((f) => !isInactive(f))
	);

	const inactiveCount = $derived(findings.filter(isInactive).length);

	const hasMore = $derived(findings.length < total);


	const handleFilter = (ruleId: string, e: MouseEvent) => {
		if (e.metaKey || e.ctrlKey) {
			// Multi-select: toggle this one
			if (activeFilters.has(ruleId)) {
				activeFilters.delete(ruleId);
			} else {
				activeFilters.add(ruleId);
			}
		} else {
			// Single click on active pill: deselect it
			if (activeFilters.has(ruleId)) {
				activeFilters.delete(ruleId);
			} else {
				// Single click on inactive pill: select only this one
				activeFilters.clear();
				activeFilters.add(ruleId);
			}
		}
	};

	const grouped = $derived.by(() => {
		const map = new SvelteMap<string, Finding[]>();
		for (const f of activeFindings) {
			const key = f.effective_rule_id || f.rule_id || 'unknown';
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
		repoDetails = null;
		contributors = [];
		detailsError = null;
		try {
			const params = new URLSearchParams({ repo_id: repoId, limit: String(PAGE_SIZE), offset: '0' });
			const [findingsRes, detailsRes] = await Promise.all([
				fetch(`/api/secrets/findings?${params}`, { credentials: 'include' }),
				fetch(`/api/providers/details?repo_id=${encodeURIComponent(repoId)}`, { credentials: 'include' }).catch(() => null)
			]);
			if (findingsRes.ok) {
				const page: FindingsPage = await findingsRes.json();
				findings = page.items;
				total = page.total;
			}
			if (detailsRes?.ok) {
				const data = await detailsRes.json();
				repoDetails = data.details ?? null;
				contributors = data.contributors ?? [];
			} else {
				if (detailsRes?.status === 403) {
					try {
						const body = await detailsRes.json();
						detailsError = body.error === 'provider_token_required' ? 'no-token' : 'access-denied';
					} catch {
						detailsError = 'access-denied';
					}
				}
				// Fallback to metadata endpoint for basic info
				try {
					const metaRes = await fetch(`/api/repos/metadata?repo_id=${encodeURIComponent(repoId)}`, { credentials: 'include' });
					if (metaRes.ok) {
						const meta = await metaRes.json();
						if (meta.repo) {
							repoDetails = {
								description: '',
								is_private: meta.repo.is_private ?? false,
								updated_at: meta.repo.updated_at ?? '',
								stats: { stars: 0, forks: 0, watchers: 0, commits: 0, branches: 0, releases: 0, contributors: 0 }
							};
						}
					}
				} catch { /* ignore */ }
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

	function portal(node: HTMLElement) {
		document.body.appendChild(node);
		return { destroy() { node.remove(); } };
	}

	// Selection toolbar
	let selToolbar: { top: number; left: number; text: string; range: Range } | null = $state(null);

	let lastMousePos = { x: 0, y: 0 };

	const trackMouse = (e: MouseEvent) => {
		lastMousePos = { x: e.clientX, y: e.clientY };
	};

	const handleDrawerSelect = () => {
		setTimeout(() => {
			const sel = window.getSelection();
			if (!sel || sel.isCollapsed || !sel.toString().trim()) {
				selToolbar = null;
				return;
			}
			const text = sel.toString().trim();
			const range = sel.getRangeAt(0);
			selToolbar = {
				top: lastMousePos.y - 32,
				left: lastMousePos.x,
				text,
				range: range.cloneRange()
			};
		}, 10);
	};

	const tryB64 = (s: string): string | null => {
		try {
			const norm = s.replace(/-/g, '+').replace(/_/g, '/');
			const padded = norm + '=='.slice(0, (4 - (norm.length % 4)) % 4);
			const decoded = atob(padded);
			if (/[\x00-\x08\x0e-\x1f\x7f]/.test(decoded)) return null;
			const printable = [...decoded].filter(c => {
				const code = c.charCodeAt(0);
				return (code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13;
			}).length;
			if (printable / decoded.length < 0.8) return null;
			if (decoded.length < 2 || decoded === s) return null;
			try { return JSON.stringify(JSON.parse(decoded), null, 2); } catch { /* not json */ }
			return decoded;
		} catch { return null; }
	};

	const copyToolbar = () => {
		if (selToolbar) navigator.clipboard.writeText(selToolbar.text);
		selToolbar = null;
	};

	const decodeToolbar = () => {
		if (!selToolbar) return;
		const range = selToolbar.range;
		const text = selToolbar.text;
		const tokens = text.split(/(\s+)/);
		let anyDecoded = false;
		const frag = document.createDocumentFragment();
		for (const token of tokens) {
			if (/^\s+$/.test(token)) { frag.appendChild(document.createTextNode(token)); continue; }
			const stripped = token.replace(/^["'`]+|["'`,:;]+$/g, '');
			const decoded = stripped.length >= 4 ? tryB64(stripped) : null;
			if (decoded) {
				const prefix = token.slice(0, token.indexOf(stripped));
				const suffix = token.slice(token.indexOf(stripped) + stripped.length);
				if (prefix) frag.appendChild(document.createTextNode(prefix));
				const span = document.createElement('span');
				span.textContent = decoded;
				span.style.color = 'var(--accent)';
				span.style.whiteSpace = 'pre-wrap';
				span.title = `Original: ${stripped}`;
				frag.appendChild(span);
				if (suffix) frag.appendChild(document.createTextNode(suffix));
				anyDecoded = true;
			} else {
				frag.appendChild(document.createTextNode(token));
			}
		}
		if (anyDecoded) { range.deleteContents(); range.insertNode(frag); }
		window.getSelection()?.removeAllRanges();
		selToolbar = null;
	};
</script>

<div class="flex h-full flex-col overflow-hidden rounded-l-[10px] bg-[var(--bg-soft)]">
	<!-- Header -->
	<div class="shrink-0 pt-7 pl-7 pr-7 pb-2">
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
					{#if repoDetails}
						{#if repoDetails.is_private}
							<span class="inline-flex items-center gap-1 rounded-full bg-[var(--orange)]/10 px-2 py-0.5 text-[10px] text-[var(--orange)]">
								<Lock class="h-2.5 w-2.5" /> Private
							</span>
						{:else}
							<span class="inline-flex items-center gap-1 rounded-full bg-[var(--success)]/10 px-2 py-0.5 text-[10px] text-[var(--success)]">
								<Globe class="h-2.5 w-2.5" /> Public
							</span>
						{/if}
					{/if}
				</div>
				{#if repoDetails?.description}
					<p class="mt-1 text-xs text-[var(--text-secondary)]">{repoDetails.description}</p>
				{/if}
				{#if !loading && total > 0}
					<p class="mt-1 text-[11px] text-[var(--text-muted)]">
						{total.toLocaleString()} finding{total !== 1 ? 's' : ''}
						{#if findings.length < total}
							<span class="text-[var(--text-muted)]">({findings.length.toLocaleString()} loaded)</span>
						{/if}
					</p>
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

	<!-- Token warning -->
	{#if detailsError && !loading}
		<div class="shrink-0 px-7 pb-3">
			<div class="flex items-center gap-2 px-3 py-2 text-[11px] text-[var(--orange)]">
				<Lock class="h-3 w-3 shrink-0 self-center" />
				<span class="leading-tight">
					{#if detailsError === 'no-token'}
						Provider has no API token configured. Add a token for full repository details.
					{:else}
						Provider token lacks access to this repository.
					{/if}
				</span>
			</div>
		</div>
	{/if}

	<!-- Repo metadata -->
	{#if repoDetails?.stats && (repoDetails.stats.commits > 0 || repoDetails.stats.branches > 0 || contributors.length > 0)}
		<div class="shrink-0 px-7 pb-4">
			<div class="metric-card rounded-xl p-3">
				<h3 class="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Repository</h3>
				<div class="mt-2 grid grid-cols-4 gap-2">
					<div class="flex flex-col justify-end">
						<p class="text-lg font-bold leading-tight text-[var(--text-bright)]">{repoDetails.stats.commits.toLocaleString()}</p>
						<p class="flex items-center gap-1 text-[10px] text-[var(--text-muted)]">
							<GitCommitHorizontal class="h-2.5 w-2.5" /> Commits
						</p>
					</div>
					<div class="flex flex-col justify-end">
						<p class="text-lg font-bold leading-tight text-[var(--text-bright)]">{repoDetails.stats.branches.toLocaleString()}</p>
						<p class="flex items-center gap-1 text-[10px] text-[var(--text-muted)]">
							<GitBranch class="h-2.5 w-2.5" /> Branches
						</p>
					</div>
					<div class="flex flex-col justify-end">
						<p class="text-lg font-bold leading-tight text-[var(--text-bright)]">{repoDetails.updated_at ? fmtRelative(repoDetails.updated_at) : '—'}</p>
						<p class="flex items-center gap-1 text-[10px] text-[var(--text-muted)]">
							<Clock class="h-2.5 w-2.5" /> Last activity
						</p>
					</div>
					<div class="flex flex-col justify-end">
						<p class="text-lg font-bold leading-tight text-[var(--text-bright)]">{Math.max(repoDetails.stats.contributors, contributors.length).toLocaleString()}</p>
						<p class="flex items-center gap-1 text-[10px] text-[var(--text-muted)]">
							<Users class="h-2.5 w-2.5" /> Contributors
						</p>
					</div>
				</div>
				{#if contributors.length > 0}
					<div class="mt-2.5">
						<ContributorAvatars {contributors} />
					</div>
				{/if}
			</div>
		</div>
	{/if}

	<!-- Type filters -->
	{#if !loading && total > 0 && grouped.length > 0}
		<div class="shrink-0 px-7 pb-4">
			{#if inactiveCount > 0}
				<button
					type="button"
					class="mb-2 inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium transition {showInactive ? 'border-[var(--accent)]/40 bg-[var(--accent)]/10 text-[var(--accent)]' : 'border-[var(--border-color)] text-[var(--text-muted)] hover:border-[var(--text-tertiary)] hover:text-[var(--text-secondary)]'}"
					onclick={() => (showInactive = !showInactive)}
				>
					{showInactive ? 'Hiding' : 'Show'} {inactiveCount} expired/dismissed
				</button>
			{/if}
			<div class="flex flex-wrap gap-1.5">
				{#each grouped as [ruleId, group] (ruleId)}
					<button
						type="button"
						onclick={(e: MouseEvent) => handleFilter(ruleId, e)}
						class="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-medium transition {activeFilters.has(ruleId) ? 'border-red-500/70 bg-red-500/20 text-red-300' : activeFilters.size > 0 ? 'border-red-500/20 bg-red-500/5 text-red-400/40' : 'border-red-500/40 bg-red-500/10 text-red-400 hover:border-red-500/60 hover:bg-red-500/15'}"
					>
						<FileWarning class="h-3 w-3 shrink-0" />
						{ruleId}
						<span class="ml-0.5 font-semibold">{group.length}{#if hasMore}+{/if}</span>
					</button>
				{/each}
			</div>
		</div>
	{/if}

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
		<!-- svelte-ignore a11y_no_static_element_interactions -->
		<div class="flex-1 overflow-y-auto bg-[var(--bg-soft)]" onmouseup={handleDrawerSelect} onmousemove={trackMouse}>
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
							<article class="finding rounded-xl px-5 py-4 transition-colors hover:bg-[var(--hover-bg-subtle)] {f.dismissed ? 'opacity-40' : ''}">
								<div class="flex items-start gap-4">
									<div class="w-40 shrink-0 pt-0.5 space-y-1">
										<span class="inline-flex items-center gap-1 rounded-full border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-xs font-semibold text-red-400">
											<FileWarning class="h-3 w-3 shrink-0" />
											<span class="truncate">{f.effective_rule_id || f.rule_id}</span>
										</span>
										{#if f.probe_status && f.probe_status !== 'unknown'}
											<span class="inline-flex rounded-full px-1.5 py-0.5 text-[10px] font-medium {f.probe_status === 'valid' ? 'bg-red-500/10 text-red-400' : f.probe_status === 'expired' ? 'bg-green-500/10 text-green-400' : f.probe_status === 'invalid' || f.probe_status === 'false_positive' ? 'bg-[var(--hover-bg)] text-[var(--text-muted)]' : 'bg-[var(--orange)]/10 text-[var(--orange)]'}">
												{f.probe_status.toUpperCase()}
											</span>
										{/if}
										{#if f.sub_type}
											<p class="text-[10px] text-[var(--text-muted)] truncate" title={f.sub_type}>{f.sub_type}</p>
										{/if}
										{#if f.entropy}
											<p class="text-[10px] {f.entropy > 4 ? 'text-red-400/70' : f.entropy > 3 ? 'text-[var(--orange)]/70' : 'text-[var(--text-muted)]'}" title="Shannon entropy: {f.entropy.toFixed(2)} bits">
												entropy {f.entropy.toFixed(1)}
											</p>
										{/if}
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
											{@const secretVal = f.secret || raw}
											{@const pemKey = extractPemKey(raw)}
											{@const jwt = tryDecodeJWT(secretVal)}
											{@const base64Matches = jwt ? [] : findAllBase64(raw)}

											<div
												class="inline-block max-w-full break-all rounded bg-[var(--card-bg)] px-2 py-1.5 font-mono text-xs text-[var(--text-muted)] cursor-text"
												onclick={(e) => {
													const sel = window.getSelection();
													if (sel && sel.toString().length > 0) return;
													const range = document.createRange();
													range.selectNodeContents(e.currentTarget as Node);
													sel?.removeAllRanges();
													sel?.addRange(range);
												}}
											>{raw}</div>

											{#if jwt}
												<div class="mt-1 rounded border border-[var(--border-color)]/40 bg-[var(--card-bg)] px-3 py-2 text-xs space-y-1.5">
													<div class="flex items-center gap-2">
														<span class="font-semibold text-[var(--text-secondary)]">JWT</span>
														{#if jwt.expired === true}
															<span class="rounded-full bg-green-500/10 px-1.5 py-0.5 text-[10px] font-medium text-green-400">EXPIRED</span>
														{:else if jwt.expired === false}
															<span class="rounded-full bg-red-500/10 px-1.5 py-0.5 text-[10px] font-medium text-red-400">ACTIVE</span>
														{:else}
															<span class="rounded-full bg-[var(--hover-bg)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--text-muted)]">NO EXPIRY</span>
														{/if}
														{#if jwt.header.alg}
															<span class="text-[10px] text-[var(--text-muted)]">{jwt.header.alg}</span>
														{/if}
													</div>
													<div class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-[11px]">
														{#if jwt.issuer}
															<span class="text-[var(--text-muted)]">iss</span>
															<span class="text-[var(--text-secondary)] break-all">{jwt.issuer}</span>
														{/if}
														{#if jwt.subject}
															<span class="text-[var(--text-muted)]">sub</span>
															<span class="text-[var(--text-secondary)] break-all">{jwt.subject}</span>
														{/if}
														{#if jwt.expiresAt}
															<span class="text-[var(--text-muted)]">exp</span>
															<span class="text-[var(--text-secondary)]">{new Date(jwt.expiresAt).toLocaleString('fr-FR')}</span>
														{/if}
														{#if jwt.issuedAt}
															<span class="text-[var(--text-muted)]">iat</span>
															<span class="text-[var(--text-secondary)]">{new Date(jwt.issuedAt).toLocaleString('fr-FR')}</span>
														{/if}
													</div>
													<details class="group">
														<summary class="cursor-pointer text-[10px] text-[var(--text-muted)] hover:text-[var(--text-secondary)]">payload</summary>
														<pre class="mt-1 whitespace-pre-wrap break-all font-mono text-[10px] text-[var(--text-muted)]">{JSON.stringify(jwt.payload, null, 2)}</pre>
													</details>
												</div>
											{/if}

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

{#if selToolbar}
	<div
		use:portal
		class="fixed z-[300] flex items-center gap-0.5 rounded-lg border border-[var(--border-color)] bg-[var(--card-bg)] px-1 py-0.5 shadow-xl"
		style="top: {selToolbar.top}px; left: {selToolbar.left}px; transform: translateX(-50%);"
	>
		<button
			type="button"
			class="inline-flex items-center gap-1 rounded px-2 py-1 text-[11px] text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
			onclick={copyToolbar}
		>
			<Copy size={11} /> Copy
		</button>
		<div class="h-4 w-px bg-[var(--border-color)]"></div>
		<button
			type="button"
			class="inline-flex items-center gap-1 rounded px-2 py-1 text-[11px] text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--accent)]"
			onclick={decodeToolbar}
		>
			B64
		</button>
	</div>
{/if}
