<script lang="ts">
	import { fly } from 'svelte/transition';
	import { cubicOut, cubicIn } from 'svelte/easing';
	import { KeyRound, Eye, ShieldCheck, Play, Copy } from 'lucide-svelte';
	import X from 'lucide-svelte/icons/x';
	import Dialog from '$lib/components/Dialog.svelte';
	import Loading from '$lib/components/Loading.svelte';
	import Checkbox from '$lib/components/Checkbox.svelte';
	import Toggle from '$lib/components/Toggle.svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';
	import SecretInspectDrawer from '$lib/components/SecretInspectDrawer.svelte';

	let {
		error = '',
		triggering = false,
		onStart,
		onStatusRefresh
	}: {
		error?: string;
		triggering?: boolean;
		// Returns true when the probe job was accepted; the dialog closes itself.
		onStart: (ruleIds: string[], hashes: string[]) => Promise<boolean>;
		onStatusRefresh: () => Promise<void> | void;
	} = $props();

	let open = $state(false);
	let preview: any[] = $state([]);
	let previewLoading = $state(false);
	let previewRefreshing = $state(false);
	let previewTab = $state('all');
	let selectedRules: string[] = $state([]);
	let force = $state(false);
	let excludedHashes: Set<string> = $state(new Set());
	let inspectItem: { hash: string; secret: string; ruleId: string } | null = $state(null);

	// Dismiss inspect drawer when switching tabs
	$effect(() => {
		previewTab;
		inspectItem = null;
	});

	export const show = () => {
		open = true;
		loadPreview();
	};

	const loadPreview = async ({ preserveRows = false }: { preserveRows?: boolean } = {}) => {
		const hasExistingRows = preview.length > 0;
		previewLoading = !preserveRows || !hasExistingRows;
		previewRefreshing = preserveRows && hasExistingRows;
		if (!preserveRows || !hasExistingRows) {
			preview = [];
			excludedHashes = new Set();
		}
		try {
			const params = force ? '?include_probed=true' : '';
			const res = await fetch(`/api/admin/secrets/probe/preview${params}`, { credentials: 'include' });
			if (res.ok) {
				const data = await res.json();
				preview = Array.isArray(data) ? data : [];
				// Pre-exclude dismissed and inactive (expired/invalid/false_positive) items.
				const excluded = new Set<string>();
				for (const group of preview) {
					for (const item of group.items ?? []) {
						if (item.dismissed || item.probe_status === 'expired' || item.probe_status === 'invalid' || item.probe_status === 'false_positive') {
							excluded.add(item.secret_hash);
						}
					}
				}
				excludedHashes = excluded;
			}
		} catch { /* ignore */ }
		finally {
			previewLoading = false;
			previewRefreshing = false;
		}
	};

	const toggleDismiss = (secretHash: string) => {
		const isDismissed = excludedHashes.has(secretHash);
		const next = new Set(excludedHashes);
		if (isDismissed) { next.delete(secretHash); } else { next.add(secretHash); }
		excludedHashes = next;

		// Update the item's dismissed state in preview so the status column reflects it.
		for (const group of preview) {
			for (const item of group.items ?? []) {
				if (item.secret_hash === secretHash) {
					item.dismissed = !isDismissed;
				}
			}
		}

		// Persist immediately — fire and forget.
		fetch('/api/secrets/dismiss', {
			method: 'POST',
			credentials: 'include',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ secret_hash: secretHash, dismiss: !isDismissed })
		}).catch(() => {});
	};

	const applyProbeRunResult = async (result: { secretHash: string; status: string; reason: string; metadata?: string }) => {
		let matched = false;
		for (const group of preview) {
			for (const item of group.items ?? []) {
				if (item.secret_hash !== result.secretHash) continue;
				item.probe_status = result.status;
				item.previous_status = result.status;
				item.already_probed = true;
				item.reason = result.reason;
				matched = true;
			}
		}

		if (matched) {
			preview = [...preview];
		}

		await onStatusRefresh();
	};

	const buildCurl = (req: any, secret: string) => {
		if (!req) return '';
		// Replace [REDACTED] with actual secret in headers
		const headers = Object.entries(req.headers || {})
			.map(([k, v]: [string, any]) => {
				const val = typeof v === 'string' ? v.replace('[REDACTED]', secret) : v;
				return `-H '${k}: ${val}'`;
			})
			.join(' ');
		const body = req.body ? `-d '${req.body}'` : '';
		return `curl -s ${req.method === 'POST' ? '-X POST ' : ''}${headers} ${body} '${req.url}'`.replace(/\s+/g, ' ').trim();
	};

	const copyToClipboard = (text: string) => {
		navigator.clipboard.writeText(text);
	};

	const startProbe = async () => {
		// Send only the hashes the user has not excluded.
		const hashes: string[] = [];
		for (const group of preview) {
			if (selectedRules.length > 0 && !selectedRules.includes(group.rule_id)) continue;
			for (const item of group.items ?? []) {
				if (!excludedHashes.has(item.secret_hash)) hashes.push(item.secret_hash);
			}
		}
		const started = await onStart(selectedRules, hashes);
		if (started) open = false;
	};
</script>

<Dialog bind:open showCloseButton={false} maxWidth="max-w-6xl">
	<div class="flex h-[80vh] flex-col p-6 sm:p-8 space-y-5">
		<div class="flex items-start justify-between">
			<div class="flex items-center gap-3">
				<KeyRound class="h-6 w-6 flex-shrink-0 text-[var(--accent)]" />
				<div>
					<h2 class="text-xl font-semibold text-[var(--text-bright)]">Secret Probe Preview</h2>
					<p class="mt-1 text-sm text-[var(--text-tertiary)]">
						Review every secret that will be probed, grouped by type.
					</p>
				</div>
			</div>
			<button
				type="button"
				class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-[var(--text-muted)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
				onclick={() => (open = false)}
				aria-label="Close"
			>
				<X size={18} />
			</button>
		</div>

		{#if previewLoading}
			<div class="flex flex-1 items-center justify-center">
				<Loading message="Loading probe preview" variant="bar" size="sm" />
			</div>
		{:else if preview.length === 0}
			<div class="flex flex-1 flex-col items-center justify-center gap-3 py-10 text-center">
				<ShieldCheck class="h-12 w-12 text-[var(--accent)]" />
				<div>
					<p class="text-lg font-semibold text-[var(--text-bright)]">All clear</p>
					<p class="mt-1 text-sm text-[var(--text-muted)]">
						{#if force}
							No secrets found to probe. Run a scan first to discover secrets.
						{:else}
							All discovered secrets have already been probed. Toggle <span class="font-medium text-[var(--text-secondary)]">Show all</span> to see them.
						{/if}
					</p>
				</div>
			</div>
		{:else}
			{@const totalSecrets = preview.reduce((s, g) => s + g.count, 0)}
			{@const filteredPreview = (() => {
				if (previewTab === 'dismissed') {
					// Show only groups that have dismissed items, filtered to those items.
					return preview.map((g: any) => ({
						...g,
						items: (g.items ?? []).filter((i: any) => excludedHashes.has(i.secret_hash)),
						count: (g.items ?? []).filter((i: any) => excludedHashes.has(i.secret_hash)).length
					})).filter((g: any) => g.count > 0);
				}
				const kindFilter = previewTab === 'all' ? null : previewTab;
				return kindFilter ? preview.filter((g: any) => g.kind === kindFilter) : preview;
			})()}
			{@const selectedGroups = selectedRules.length === 0 ? filteredPreview : filteredPreview.filter((g: any) => selectedRules.includes(g.rule_id))}
			{@const selectedCount = selectedGroups.reduce((s: number, g: any) => s + g.count, 0)}

			<!-- Tab selector + summary -->
			<div class="space-y-2">
				<TabSelector
					options={[
						{ value: 'all', label: 'All' },
						{ value: 'network', label: 'External' },
						{ value: 'offline', label: 'Local' },
						{ value: 'dismissed', label: 'Dismissed' }
					]}
					bind:value={previewTab}
				/>
				<p class="text-center text-xs text-[var(--text-muted)]">
					{selectedCount.toLocaleString('en-US').replace(/,/g, ' ')} of {totalSecrets.toLocaleString('en-US').replace(/,/g, ' ')} selected · {selectedGroups.length} type{selectedGroups.length !== 1 ? 's' : ''}
				</p>
			</div>

			<!-- Grouped request table -->
			<div class="relative min-h-0 flex-1 overflow-x-hidden rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
				{#if previewRefreshing}
					<div class="pointer-events-none absolute inset-x-0 top-0 z-30 flex justify-center p-3">
						<div class="rounded-full border border-[var(--border-color)]/60 bg-[var(--card-bg)]/95 px-3 py-1 text-[11px] text-[var(--text-muted)] shadow-lg backdrop-blur">
							Refreshing preview…
						</div>
					</div>
				{/if}
				<div class="h-full overflow-y-auto overflow-x-hidden">
					<table class="w-full table-fixed text-xs">
						<thead class="sticky top-0 z-10 bg-[var(--card-bg)] text-[10px] uppercase tracking-wider text-[var(--text-tertiary)]">
							<tr>
								<th class="w-[3%] px-3 py-2 text-left"></th>
								<th class="w-[25%] px-3 py-2 text-left">Secret</th>
								<th class="w-[7%] px-3 py-2 text-left">Method</th>
								<th class="w-[30%] px-3 py-2 text-left">URL</th>
								<th class="w-[20%] px-3 py-2 text-left">Headers</th>
								<th class="w-[8%] px-3 py-2 text-left">Status</th>
								<th class="w-[3%] px-3 py-2 text-left"></th>
								<th class="px-3 py-2 text-left"></th>
							</tr>
						</thead>
						<tbody class="divide-y divide-[var(--border-color)]/30">
							{#each [...filteredPreview].sort((a, b) => a.rule_id.localeCompare(b.rule_id)) as group}
							{@const isGroupSelected = selectedRules.length === 0 || selectedRules.includes(group.rule_id)}
							<!-- Group header row -->
							<tr class="bg-[var(--hover-bg-subtle)]/50">
								<td class="px-3 py-2 text-center">
									<Checkbox
										checked={isGroupSelected}
										onchange={() => {
											if (selectedRules.length === 0) {
												selectedRules = preview.map(g => g.rule_id).filter(r => r !== group.rule_id);
											} else if (selectedRules.includes(group.rule_id)) {
												selectedRules = selectedRules.filter(r => r !== group.rule_id);
											} else {
												selectedRules = [...selectedRules, group.rule_id];
											}
										}}
									/>
								</td>
								<td class="px-3 py-2 font-semibold text-[var(--text-bright)]" colspan="5">
									{group.rule_id}
									<span class="ml-2 font-normal text-[var(--text-muted)]">{group.count} secret{group.count !== 1 ? 's' : ''}</span>
								</td>
								<td class="px-3 py-2" colspan="2">
									<span class="rounded-full border border-[var(--border-color)] px-2 py-0.5 text-[10px] text-[var(--text-muted)]">{group.kind}</span>
								</td>
							</tr>
							<!-- Item rows -->
							{#if isGroupSelected && group.items}
								{#each group.items as item}
									{@const isItemChecked = !excludedHashes.has(item.secret_hash)}
									{@const isInspected = inspectItem?.hash === item.secret_hash}
									<tr
										class="cursor-pointer transition-opacity {isInspected ? 'bg-[var(--hover-bg)]' : ''} {isItemChecked ? 'text-[var(--text-secondary)]' : 'text-[var(--text-muted)] opacity-40'} hover:bg-[var(--hover-bg-subtle)]"
										onclick={(e) => {
											const target = e.target as HTMLElement;
											if (target.closest('button, a, input') || window.getSelection()?.toString()) return;
											if (inspectItem) {
												inspectItem = { hash: item.secret_hash, secret: item.secret, ruleId: item.effective_rule_id || item.rule_id || '' };
											} else {
												toggleDismiss(item.secret_hash);
											}
										}}
									>
										<td class="px-3 py-1.5">
											<button
												type="button"
												class="mx-auto block h-2 w-2 rounded-full transition {isItemChecked ? 'bg-[var(--accent)]' : 'bg-[var(--border-color)]'}"
												onclick={() => toggleDismiss(item.secret_hash)}
											></button>
										</td>
										<td class="px-3 py-1.5 font-mono overflow-hidden">
											<span
												class="block truncate select-all cursor-text"
												title={item.secret}
												ondblclick={(e) => { const sel = window.getSelection(); const range = document.createRange(); range.selectNodeContents(e.currentTarget); sel?.removeAllRanges(); sel?.addRange(range); }}
											>{item.secret}</span>
											{#if item.is_falsy}
												<span class="text-[9px] italic text-[var(--text-muted)]">({item.falsy_reason})</span>
											{/if}
										</td>
										{#if item.requests && item.requests.length > 0}
											<td class="px-3 py-1.5">
												<span class="rounded bg-[var(--hover-bg)] px-1.5 py-0.5 font-mono text-[10px]">{item.requests[0].method}</span>
											</td>
											<td class="px-3 py-1.5 font-mono truncate">
												<span class="block truncate" title={item.requests[0].url}>{item.requests[0].url}</span>
											</td>
											<td class="px-3 py-1.5 truncate">
												<span class="block truncate" title={Object.entries(item.requests[0].headers || {}).map(([k,v]) => `${k}: ${v}`).join(', ')}>
													{Object.entries(item.requests[0].headers || {}).map(([k,v]) => `${k}: ${v}`).join(', ') || '—'}
												</span>
											</td>
										{:else}
											<td class="px-3 py-1.5 text-[var(--text-muted)]">—</td>
											<td class="px-3 py-1.5 text-[var(--text-muted)]">local check</td>
											<td class="px-3 py-1.5">—</td>
										{/if}
										<td class="px-3 py-1.5">
											{#if item.dismissed}
												<span class="text-[var(--text-muted)]">dismissed</span>
											{:else if item.is_falsy}
												<span class="text-[var(--text-muted)]">skip</span>
											{:else if item.probe_status && item.probe_status !== 'unknown'}
												<span class="{item.probe_status === 'valid' ? 'text-red-400' : item.probe_status === 'expired' || item.probe_status === 'invalid' || item.probe_status === 'false_positive' ? 'text-green-400' : 'text-[var(--text-tertiary)]'}">{item.probe_status}</span>
											{:else if item.already_probed}
												<span class="{item.previous_status === 'valid' ? 'text-red-400' : item.previous_status === 'revoked' || item.previous_status === 'expired' ? 'text-green-400' : 'text-[var(--text-tertiary)]'}">{item.previous_status}</span>
											{:else}
												<span class="text-[var(--text-tertiary)]">pending</span>
											{/if}
										</td>
										<td class="px-3 py-1.5">
											{#if item.requests && item.requests.length > 0}
												<button
													type="button"
													class="p-1 text-[var(--text-muted)] transition hover:text-[var(--accent)]"
													title="Copy as curl"
													onclick={() => copyToClipboard(buildCurl(item.requests[0], item.secret))}
												>
													<Copy size={12} />
												</button>
											{/if}
										</td>
										<td
											class="px-3 py-1.5 cursor-pointer text-[var(--text-muted)] transition hover:text-[var(--accent)]"
											title="Inspect secret"
											onclick={() => { inspectItem = { hash: item.secret_hash, secret: item.secret, ruleId: item.effective_rule_id || item.rule_id || '' }; }}
										>
											<Eye size={12} />
										</td>
									</tr>
								{/each}
							{/if}
						{/each}
						</tbody>
					</table>
				</div>

				<!-- Inspect drawer -->
				{#if inspectItem}
					<div
						class="absolute inset-y-0 right-0 z-20 w-[480px] overflow-hidden"
						in:fly={{ x: 480, duration: 240, easing: cubicOut, opacity: 1 }}
						out:fly={{ x: 480, duration: 200, easing: cubicIn, opacity: 1 }}
					>
						<SecretInspectDrawer
							secretHash={inspectItem.hash}
							secret={inspectItem.secret}
							ruleId={inspectItem.ruleId}
							dismissed={excludedHashes.has(inspectItem.hash)}
							onDismiss={(hash) => toggleDismiss(hash)}
							onProbeRun={applyProbeRunResult}
							onClose={() => { inspectItem = null; }}
						/>
					</div>
				{/if}
			</div>
		{/if}

		{#if error}
			<p class="text-sm text-[var(--error)]">{error}</p>
		{/if}

		<!-- Footer -->
		<div class="flex items-center justify-between pt-2">
			<Toggle bind:checked={force} label="Show all" onchange={() => loadPreview({ preserveRows: true })} />
			<div class="flex items-center gap-3">
				<button type="button" class="btn btn-ghost" onclick={() => (open = false)}>
					Cancel
				</button>
				<button
					type="button"
					class="btn btn-primary inline-flex items-center gap-2"
					disabled={triggering || previewLoading}
					onclick={startProbe}
				>
					<Play size={14} />
					{triggering ? 'Starting…' : 'Start Probe'}
				</button>
			</div>
		</div>
	</div>
</Dialog>
