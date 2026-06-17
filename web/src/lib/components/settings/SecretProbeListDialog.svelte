<script lang="ts">
	import { ShieldCheck, FileWarning, Copy, Download } from 'lucide-svelte';
	import X from 'lucide-svelte/icons/x';
	import Dialog from '$lib/components/Dialog.svelte';
	import Loading from '$lib/components/Loading.svelte';

	let open = $state(false);
	let title = $state('');
	let statuses: string[] = $state([]);
	let items: any[] = $state([]);
	let loading = $state(false);

	// Opened imperatively from the probe stats cards via bind:this.
	export const show = async (nextTitle: string, nextStatuses: string[]) => {
		title = nextTitle;
		statuses = nextStatuses;
		open = true;
		loading = true;
		items = [];
		try {
			const params = statuses.map((s) => `status=${s}`).join('&');
			const res = await fetch(`/api/admin/secrets/probe/list?${params}`, { credentials: 'include' });
			if (res.ok) {
				const data = await res.json();
				items = Array.isArray(data) ? data : [];
			}
		} catch { /* ignore */ }
		finally { loading = false; }
	};

	const exportCSV = () => {
		const params = statuses.map((s) => `status=${s}`).join('&');
		window.open(`/api/admin/secrets/probe/export?${params}`, '_blank');
	};

	const tryDecodeJWT = (s: string): { header: Record<string, unknown>; payload: Record<string, unknown>; expired: boolean | null; expiresAt: string | null; issuedAt: string | null; issuer: string | null; subject: string | null } | null => {
		const jwtMatch = s.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
		if (!jwtMatch) return null;
		const parts = jwtMatch[0].split('.');
		if (parts.length !== 3) return null;
		const decode = (part: string) => {
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
			header, payload,
			expired: exp != null ? exp * 1000 < Date.now() : null,
			expiresAt: exp != null ? new Date(exp * 1000).toISOString() : null,
			issuedAt: iat != null ? new Date(iat * 1000).toISOString() : null,
			issuer: typeof payload.iss === 'string' ? payload.iss : null,
			subject: typeof payload.sub === 'string' ? payload.sub : null,
		};
	};

	// Floating Copy / B64-decode toolbar over a text selection in the table.
	let selectionToolbar: { top: number; left: number; text: string; range: Range } | null = $state(null);

	$effect(() => {
		if (!open) selectionToolbar = null;
	});

	const handleSecretSelect = () => {
		// Small delay to let click-to-select-all finish first
		setTimeout(() => {
			const sel = window.getSelection();
			if (!sel || sel.isCollapsed || !sel.toString().trim()) {
				selectionToolbar = null;
				return;
			}
			const text = sel.toString().trim();
			const range = sel.getRangeAt(0);
			const rect = range.getBoundingClientRect();
			selectionToolbar = {
				top: Math.max(4, rect.top - 36),
				left: Math.min(Math.max(80, rect.left + rect.width / 2), window.innerWidth - 80),
				text,
				range: range.cloneRange()
			};
		}, 10);
	};

	const tryBase64Decode = (s: string): string | null => {
		try {
			const norm = s.replace(/-/g, '+').replace(/_/g, '/');
			const padded = norm + '=='.slice(0, (4 - (norm.length % 4)) % 4);
			const decoded = atob(padded);
			// Reject control characters
			if (/[\x00-\x08\x0e-\x1f\x7f]/.test(decoded)) return null;
			// Reject if less than 80% printable ASCII / common UTF-8
			const printable = [...decoded].filter(c => {
				const code = c.charCodeAt(0);
				return (code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13;
			}).length;
			if (printable / decoded.length < 0.8) return null;
			// Reject very short or same as input
			if (decoded.length < 2 || decoded === s) return null;
			try { return JSON.stringify(JSON.parse(decoded), null, 2); } catch { /* not json */ }
			return decoded;
		} catch {
			return null;
		}
	};

	const copySelection = () => {
		if (!selectionToolbar) return;
		navigator.clipboard.writeText(selectionToolbar.text);
		selectionToolbar = null;
	};

	const decodeSelection = () => {
		if (!selectionToolbar) return;
		const range = selectionToolbar.range;
		const text = selectionToolbar.text;

		// Try each whitespace-separated token for base64
		const tokens = text.split(/(\s+)/);
		let anyDecoded = false;
		const frag = document.createDocumentFragment();

		for (const token of tokens) {
			if (/^\s+$/.test(token)) {
				frag.appendChild(document.createTextNode(token));
				continue;
			}
			// Strip common wrappers: quotes, trailing punctuation
			const stripped = token.replace(/^["'`]+|["'`,:;]+$/g, '');
			const decoded = stripped.length >= 4 ? tryBase64Decode(stripped) : null;
			if (decoded) {
				// Keep prefix/suffix that was stripped
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

		if (anyDecoded) {
			range.deleteContents();
			range.insertNode(frag);
		}

		window.getSelection()?.removeAllRanges();
		selectionToolbar = null;
	};
</script>

<Dialog bind:open showCloseButton={false} maxWidth="max-w-6xl">
	<div class="p-6 sm:p-8 space-y-5">
		<div class="flex items-start justify-between">
			<div>
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">{title}</h2>
				<p class="mt-1 text-sm text-[var(--text-tertiary)]">{items.length} secret{items.length !== 1 ? 's' : ''}</p>
			</div>
			<div class="flex items-center gap-2">
				<button
					type="button"
					class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-[var(--text-muted)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
					onclick={() => (open = false)}
					aria-label="Close"
				>
					<X size={18} />
				</button>
			</div>
		</div>

		{#if loading}
			<Loading message="Loading secrets" variant="bar" size="sm" />
		{:else if items.length === 0}
			<div class="flex flex-col items-center gap-3 py-10 text-center">
				<ShieldCheck class="h-12 w-12 text-[var(--accent)]" />
				<div>
					<p class="text-lg font-semibold text-[var(--text-bright)]">No secrets found</p>
					<p class="mt-1 text-sm text-[var(--text-muted)]">No probed secrets match this filter.</p>
				</div>
			</div>
		{:else}
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div
				class="max-h-[60vh] overflow-y-auto rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40"
				onmouseup={handleSecretSelect}
			>
				<table class="w-full text-sm">
					<thead class="sticky top-0 z-10 bg-[var(--card-bg)] text-[10px] uppercase tracking-wider text-[var(--text-tertiary)]">
						<tr>
							<th class="px-5 py-2.5 text-left w-[100px]">Status</th>
							<th class="px-5 py-2.5 text-left">Secret</th>
							<th class="px-5 py-2.5 text-left w-[28%]">Found in</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-[var(--border-color)]/30">
						{#each items as probe}
							<tr class="align-top transition hover:bg-[var(--hover-bg-subtle)]">
								<!-- Status badge -->
								<td class="px-5 py-3 whitespace-nowrap">
									<span class="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium
										{probe.status === 'valid' ? 'border-red-500/30 bg-red-500/5 text-red-400' :
										 probe.status === 'revoked' || probe.status === 'expired' || probe.status === 'invalid' ? 'border-green-500/30 bg-green-500/5 text-green-400' :
										 probe.status === 'false_positive' ? 'border-[var(--border-color)] bg-[var(--hover-bg)] text-[var(--text-muted)]' :
										 'border-[var(--border-color)] text-[var(--text-tertiary)]'}">
										<span class="h-1.5 w-1.5 rounded-full
											{probe.status === 'valid' ? 'bg-red-400' :
											 probe.status === 'revoked' || probe.status === 'expired' || probe.status === 'invalid' ? 'bg-green-400' :
											 'bg-[var(--text-muted)]'}"></span>
										{probe.status.toUpperCase()}
									</span>
								</td>
								<!-- Secret + rule + reason -->
								<td class="px-5 py-3">
									<div class="flex flex-wrap items-center gap-2">
										<span class="inline-flex items-center gap-1 rounded-full border border-[var(--border-color)] px-1.5 py-0.5 text-xs">
											<FileWarning class="h-3 w-3 shrink-0" />
											{probe.rule_id}
										</span>
										{#if probe.locations?.[0]?.sub_type}
											<span class="text-[10px] text-[var(--text-muted)]">{probe.locations[0].sub_type}</span>
										{/if}
									</div>
									{#if probe.reason}
										<p class="mt-0.5 text-xs text-[var(--text-muted)] leading-snug">{probe.reason}</p>
									{/if}
									{#if probe.locations.length > 0 && probe.locations[0].secret}
										{@const secretVal = probe.locations[0].secret}
										{@const jwt = tryDecodeJWT(secretVal)}
										<pre
											class="mt-1.5 inline-block max-w-full rounded bg-[var(--bg-hard)] px-2 py-1 font-mono text-xs text-[var(--text-muted)] whitespace-pre-wrap break-all cursor-text"
											onclick={(e) => {
												const sel = window.getSelection();
												if (sel && sel.toString().length > 0) return;
												const range = document.createRange();
												range.selectNodeContents(e.currentTarget as Node);
												sel?.removeAllRanges();
												sel?.addRange(range);
											}}
										>{secretVal}</pre>
										{#if jwt}
											<div class="mt-1 rounded border border-[var(--border-color)]/40 bg-[var(--card-bg)] px-2.5 py-1.5 text-xs space-y-1">
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
														<span class="text-[var(--text-secondary)]">{new Date(jwt.expiresAt).toLocaleString()}</span>
													{/if}
												</div>
												<details class="group">
													<summary class="cursor-pointer text-[10px] text-[var(--text-muted)] hover:text-[var(--text-secondary)]">payload</summary>
													<pre class="mt-1 whitespace-pre-wrap break-all font-mono text-[10px] text-[var(--text-muted)]">{JSON.stringify(jwt.payload, null, 2)}</pre>
												</details>
											</div>
										{/if}
									{/if}
									<p class="mt-1 text-[10px] text-[var(--text-muted)]">
										Probed {new Date(probe.probed_at).toLocaleString()}
									</p>
								</td>
								<!-- Locations -->
								<td class="px-5 py-3">
									{#if probe.locations.length > 0}
										<div class="flex flex-col gap-1">
											{#each probe.locations as loc}
												<div>
													<a
														href="/providers/repo/{loc.repo_id}"
														class="text-xs text-[var(--accent)] hover:underline break-all"
													>
														{loc.repo_name}
													</a>
													{#if loc.file}
														<p class="font-mono text-[10px] text-[var(--text-muted)]">{loc.file}{loc.line ? `:${loc.line}` : ''}</p>
													{/if}
												</div>
											{/each}
										</div>
									{:else}
										<span class="text-xs text-[var(--text-muted)]">—</span>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>

			<!-- Footer -->
			<div class="flex justify-end pt-2">
				<button
					type="button"
					class="inline-flex items-center gap-1 text-xs text-[var(--text-muted)] transition hover:text-[var(--accent)]"
					onclick={exportCSV}
				>
					<Download size={11} />
					Export CSV
				</button>
			</div>
		{/if}
	</div>
</Dialog>

<!-- Selection toolbar -->
{#if selectionToolbar}
	<div
		class="fixed z-[300] flex items-center gap-0.5 rounded-lg border border-[var(--border-color)] bg-[var(--card-bg)] px-1 py-0.5 shadow-xl"
		style="top: {selectionToolbar.top}px; left: {selectionToolbar.left}px; transform: translateX(-50%);"
	>
		<button
			type="button"
			class="inline-flex items-center gap-1 rounded px-2 py-1 text-[11px] text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
			onclick={copySelection}
		>
			<Copy size={11} /> Copy
		</button>
		<div class="h-4 w-px bg-[var(--border-color)]"></div>
		<button
			type="button"
			class="inline-flex items-center gap-1 rounded px-2 py-1 text-[11px] text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--accent)]"
			onclick={decodeSelection}
		>
			B64
		</button>
	</div>
{/if}
