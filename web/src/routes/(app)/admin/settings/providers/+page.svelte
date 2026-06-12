<script lang="ts">
	import { onMount } from 'svelte';
	import { tick } from 'svelte';
	import { slide } from 'svelte/transition';
	import { browser } from '$app/environment';
	import { Eye, EyeOff, Trash2, PlugZap } from 'lucide-svelte';
	import Dialog from '$lib/components/Dialog.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import Select from '$lib/components/Select.svelte';
	import AddProviderForm from '$lib/components/settings/AddProviderForm.svelte';
	import { mapProvider, providerTag } from '$lib/components/settings/providers';
	import type { ApiProvider, ProviderRow } from '$lib/components/settings/providers';
	import { providerSyncStates, initSyncStates, updateSyncState } from '$lib/stores/providerSync';

	let providers: ProviderRow[] = $state([]);
	let formError = $state('');
	let error = $state('');
	let loading = $state(true);
	let saving = $state(false);
	let rotatePat = $state('');
	let rotateDialogOpen = $state(false);
	let rotatingProvider = $state<ProviderRow | null>(null);
	let showRotatePat = $state(false);
	let showAddProvider = $state(false);
	let rotateError = $state('');
	let removeDialogOpen = $state(false);
	let removingProvider = $state<ProviderRow | null>(null);
	const syncStates = providerSyncStates;
	let healthTooltip = $state<{
		entryId: string;
		message: string;
		top: number;
		left: number;
	} | null>(null);
	let healthTooltipEl: HTMLDivElement | null = $state(null);

	const statusLabel = (entry: ProviderRow) => {
		const health = (entry.healthStatus || '').toUpperCase();
		if (entry.enabled && (health === 'FAILED' || health === 'DEGRADED')) return 'Unhealhty';
		return entry.enabled ? 'Enabled' : 'Disabled';
	};

	const statusClass = (entry: ProviderRow) => {
		const health = (entry.healthStatus || '').toUpperCase();
		if (entry.enabled && (health === 'FAILED' || health === 'DEGRADED')) {
			return 'border-[var(--error)]/40 text-[var(--error)]';
		}
		if (entry.enabled) {
			return 'border-[var(--success)]/40 text-[var(--success)]';
		}
		return 'border-[var(--border-color)] text-[var(--text-tertiary)]';
	};

	const healthDetails = (entry: ProviderRow) => {
		const health = (entry.healthStatus || '').toUpperCase();
		if (!entry.enabled || (health !== 'FAILED' && health !== 'DEGRADED')) {
			return '';
		}
		return (entry.healthMessage || '').trim();
	};

	const hasHealthDetails = (entry: ProviderRow) => Boolean(healthDetails(entry));

	const TOOLTIP_OFFSET = 10;
	const TOOLTIP_EDGE_GAP = 12;

	const hideHealthTooltip = (entryId?: string) => {
		if (!entryId || healthTooltip?.entryId === entryId) {
			healthTooltip = null;
		}
	};

	const showHealthTooltip = async (event: MouseEvent | FocusEvent, entry: ProviderRow) => {
		const message = healthDetails(entry);
		if (!message || !browser) {
			return;
		}

		const anchor = event.currentTarget as HTMLElement | null;
		if (!anchor) {
			return;
		}

		const rect = anchor.getBoundingClientRect();
		healthTooltip = {
			entryId: entry.id,
			message,
			top: rect.bottom + TOOLTIP_OFFSET,
			left: rect.left + rect.width / 2
		};

		await tick();

		if (!healthTooltip || healthTooltip.entryId !== entry.id || !healthTooltipEl) {
			return;
		}

		const tipRect = healthTooltipEl.getBoundingClientRect();
		const maxLeft = window.innerWidth - tipRect.width - TOOLTIP_EDGE_GAP;
		const centeredLeft = rect.left + rect.width / 2 - tipRect.width / 2;
		const left = Math.max(TOOLTIP_EDGE_GAP, Math.min(maxLeft, centeredLeft));

		let top = rect.bottom + TOOLTIP_OFFSET;
		if (top + tipRect.height > window.innerHeight - TOOLTIP_EDGE_GAP) {
			top = rect.top - tipRect.height - TOOLTIP_OFFSET;
		}
		top = Math.max(TOOLTIP_EDGE_GAP, top);

		healthTooltip = {
			...healthTooltip,
			top,
			left
		};
	};

	const loadProviders = async () => {
		loading = true;
		error = '';
		try {
			const response = await fetch('/api/admin/providers', {
				credentials: 'include'
			});
			if (!response.ok) {
				error = response.status === 403 ? 'Admin access required.' : 'Failed to load providers.';
				providers = [];
				return;
			}
			const data: ApiProvider[] = await response.json();
			providers = data.map(mapProvider);
		} catch {
			error = 'Failed to load providers.';
		} finally {
			loading = false;
		}
	};

	const toggleEnabled = async (entry: ProviderRow) => {
		saving = true;
		formError = '';
		try {
			const response = await fetch(`/api/admin/providers/${entry.id}`, {
				method: 'PATCH',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ enabled: !entry.enabled })
			});

			if (!response.ok) {
				formError = 'Failed to update provider.';
				return;
			}

			const updated: ApiProvider = await response.json();
			providers = providers.map((provider) => (provider.id === updated.id ? mapProvider(updated) : provider));
		} catch {
			formError = 'Failed to update provider.';
		} finally {
			saving = false;
		}
	};

	const openRotateDialog = (entry: ProviderRow) => {
		rotatingProvider = entry;
		rotatePat = '';
		showRotatePat = false;
		rotateError = '';
		rotateDialogOpen = true;
	};

	const closeRotateDialog = () => {
		rotateDialogOpen = false;
		rotatingProvider = null;
		rotatePat = '';
		showRotatePat = false;
		rotateError = '';
	};

	const rotateToken = async (pat: string, failMessage: string) => {
		if (!rotatingProvider) return;
		saving = true;
		rotateError = '';
		try {
			const response = await fetch(`/api/admin/providers/${rotatingProvider.id}/rotate`, {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ pat })
			});

			if (!response.ok) {
				rotateError = failMessage;
				return;
			}

			const updated: ApiProvider = await response.json();
			providers = providers.map((provider) => (provider.id === updated.id ? mapProvider(updated) : provider));
			closeRotateDialog();
		} catch {
			rotateError = failMessage;
		} finally {
			saving = false;
		}
	};

	const submitRotateToken = async () => {
		if (!rotatePat.trim()) {
			rotateError = 'PAT is required.';
			return;
		}
		await rotateToken(rotatePat, 'Failed to rotate token.');
	};

	const submitMakePublic = async () => {
		await rotateToken('', 'Failed to revoke token.');
	};

	const openRemoveDialog = (entry: ProviderRow) => {
		removingProvider = entry;
		removeDialogOpen = true;
	};

	const confirmRemoveProvider = async () => {
		if (!removingProvider) return;
		saving = true;
		formError = '';
		removeDialogOpen = false;
		try {
			const response = await fetch(`/api/admin/providers/${removingProvider.id}`, {
				method: 'DELETE',
				credentials: 'include'
			});
			if (!response.ok) {
				formError = 'Failed to delete provider.';
				return;
			}
			providers = providers.filter((provider) => provider.id !== removingProvider!.id);
		} catch {
			formError = 'Failed to delete provider.';
		} finally {
			saving = false;
			removingProvider = null;
		}
	};

	const isSyncing = (id: string) => $syncStates[id]?.status === 'running';

	const refreshSyncStatuses = async () => {
		try {
			const response = await fetch('/api/admin/providers/sync/status', { credentials: 'include' });
			if (!response.ok) return;
			const data = await response.json();
			initSyncStates(data);
		} catch {
			// Ignore transient sync status refresh errors.
		}
	};

	const syncProviderNow = async (entry: ProviderRow) => {
		if (isSyncing(entry.id)) return;
		formError = '';
		try {
			const response = await fetch(`/api/admin/providers/${entry.id}/sync`, {
				method: 'POST',
				credentials: 'include'
			});
			// 202 = started, 409 = already running — both include current state.
			if (response.ok || response.status === 409) {
				const state = await response.json();
				updateSyncState(state);
				return;
			}
			if (!response.ok) {
				formError = 'Failed to sync provider.';
			}
		} catch {
			formError = 'Failed to sync provider.';
		}
	};

	const providerSummary = (entry: ProviderRow) => {
		if (entry.ownerPath) return `${entry.baseUrl}/${entry.ownerPath}`;
		return entry.baseUrl;
	};

	const pollIntervalOptions = [
		{ value: '0', label: 'Off' },
		{ value: '900', label: '15 min' },
		{ value: '3600', label: '1 hour' },
		{ value: '21600', label: '6 hours' },
		{ value: '86400', label: '24 hours' }
	];

	const updatePollInterval = async (entry: ProviderRow, value: string) => {
		const numValue = parseInt(value) || 0;
		saving = true;
		formError = '';
		try {
			const response = await fetch(`/api/admin/providers/${entry.id}`, {
				method: 'PATCH',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ poll_interval: numValue || null })
			});

			if (!response.ok) {
				formError = 'Failed to update polling interval.';
				return;
			}

			const updated: ApiProvider = await response.json();
			providers = providers.map((provider) =>
				provider.id === updated.id ? mapProvider(updated) : provider
			);
		} catch {
			formError = 'Failed to update polling interval.';
		} finally {
			saving = false;
		}
	};

	onMount(() => {
		if (!browser) return;

		loadProviders();
		// Restore sync states for any in-progress syncs (e.g. after navigating away and back).
		refreshSyncStatuses();

		const closeTooltip = () => {
			healthTooltip = null;
		};
		window.addEventListener('scroll', closeTooltip, true);
		window.addEventListener('resize', closeTooltip);

		return () => {
			window.removeEventListener('scroll', closeTooltip, true);
			window.removeEventListener('resize', closeTooltip);
		};
	});
</script>

<svelte:head>
	<title>Providers · Settings — Spam Monitor</title>
</svelte:head>

<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
	<header class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">Configured Providers</h2>
			<p class="text-sm text-[var(--text-tertiary)]">Stored in the database and encrypted at rest.</p>
		</div>
		<button
			type="button"
			class={`btn ${showAddProvider ? 'btn-ghost' : 'btn-primary'} inline-flex items-center gap-2`}
			onclick={() => (showAddProvider = !showAddProvider)}
		>
			{showAddProvider ? 'Close' : 'Add Provider'}
		</button>
	</header>

	{#if showAddProvider}
		<div in:slide={{ duration: 180 }} out:slide={{ duration: 160 }}>
			<AddProviderForm
				oncreated={(created) => {
					providers = [created, ...providers];
					showAddProvider = false;
				}}
			/>
		</div>
	{/if}

	{#if error}
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">{error}</div>
	{/if}
	{#if formError}
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">{formError}</div>
	{/if}

	{#if loading}
		<p class="text-sm text-[var(--text-secondary)]">Loading providers...</p>
	{:else if providers.length === 0}
		<div class="flex flex-col items-center justify-center gap-4 py-12 text-center">
			<div class="rounded-full border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-[var(--text-tertiary)]">
				<PlugZap size={32} />
			</div>
			<div class="space-y-1">
				<h3 class="text-lg font-semibold text-[var(--text-bright)]">No providers configured</h3>
				<p class="max-w-md text-sm text-[var(--text-tertiary)]">
					Connect a GitHub, GitLab, Gitea, or Forgejo instance to start ingesting repositories.
				</p>
			</div>
			{#if !showAddProvider}
				<button
					type="button"
					class="btn btn-primary inline-flex items-center gap-2"
					onclick={() => (showAddProvider = true)}
				>
					Add Provider
				</button>
			{/if}
		</div>
	{:else}
		<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
			<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
				<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
					<tr>
						<th class="px-5 py-3 text-left">Provider</th>
						<th class="px-5 py-3 text-left">Type</th>
						<th class="px-5 py-3 text-left">Owner/Group</th>
						<th class="px-5 py-3 text-left">Token</th>
						<th class="px-5 py-3 text-left">Polling</th>
						<th class="px-5 py-3 text-left">Status</th>
						<th class="px-5 py-3 text-left">Actions</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
					{#each providers as entry}
						<tr class="transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]">
							<td class="px-5 py-3">
								<div class="font-semibold text-[var(--text-bright)]">{entry.displayName}</div>
								<div class="text-xs text-[var(--text-tertiary)]">{providerSummary(entry)}</div>
							</td>
							<td class="px-5 py-3">
								<span class="inline-flex items-center rounded-full border border-[var(--border-color)] px-2 py-1 text-xs">
									{providerTag(entry.type)}
								</span>
							</td>
							<td class="px-5 py-3 text-xs">
								{entry.ownerPath || 'All'}
							</td>
							<td class="px-5 py-3 text-xs">
								{entry.tokenFingerprint ? `${entry.tokenFingerprint}` : 'Public'}
								{#if entry.lastRotatedAt}
									<div class="text-[10px] uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
										Rotated {entry.lastRotatedAt}
									</div>
								{/if}
							</td>
							<td class="px-5 py-3">
								<Select
									options={pollIntervalOptions}
									value={String(entry.pollInterval || 3600)}
									disabled={saving}
									size="sm"
									onchange={(v) => updatePollInterval(entry, v)}
								/>
							</td>
							<td class="px-5 py-3">
								<div class="relative inline-flex">
									<span
										class={`inline-flex items-center rounded-full border px-2 py-1 text-xs ${statusClass(entry)}`}
									>
										<button
											type="button"
											class="inline-flex items-center border-0 bg-transparent p-0 text-inherit"
											tabindex={hasHealthDetails(entry) ? 0 : -1}
											onmouseenter={(event) => showHealthTooltip(event, entry)}
											onmouseleave={() => hideHealthTooltip(entry.id)}
											onfocus={(event) => showHealthTooltip(event, entry)}
											onblur={() => hideHealthTooltip(entry.id)}
										>
											{statusLabel(entry)}
										</button>
									</span>
								</div>
							</td>
							<td class="px-5 py-3">
								<div class="flex flex-wrap gap-2">
									<button
										type="button"
										class="sync-now-btn rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
										class:syncing={isSyncing(entry.id)}
										onclick={() => syncProviderNow(entry)}
										disabled={saving || isSyncing(entry.id)}
									>
										{#if isSyncing(entry.id)}
											<span class="sync-label syncing-text" data-text="Syncing...">Syncing...</span>
										{:else}
											<span class="sync-label">Sync Now</span>
										{/if}
									</button>
									<button
										type="button"
										class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
										onclick={() => openRotateDialog(entry)}
										disabled={saving}
									>
										{entry.tokenFingerprint ? 'Rotate' : 'Add Token'}
									</button>
									<button
										type="button"
										class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
										onclick={() => toggleEnabled(entry)}
										disabled={saving}
									>
										{entry.enabled ? 'Disable' : 'Enable'}
									</button>
									<button
										type="button"
										class="rounded-full border border-[var(--error)]/40 px-3 py-1 text-xs text-[var(--error)] transition hover:bg-[var(--error)]/10 disabled:opacity-50"
										onclick={() => openRemoveDialog(entry)}
										disabled={saving}
									>
										Remove
									</button>
								</div>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</section>

{#if healthTooltip}
	<div
		bind:this={healthTooltipEl}
		class="pointer-events-none fixed z-[200] w-80 rounded-xl border border-[var(--border-color)] bg-[var(--surface-bg)] px-3 py-2 text-[11px] leading-relaxed text-[var(--text-secondary)] shadow-xl"
		style={`top: ${healthTooltip.top}px; left: ${healthTooltip.left}px;`}
	>
		{healthTooltip.message}
	</div>
{/if}

<!-- Rotate Token Dialog -->
<Dialog bind:open={rotateDialogOpen} onClose={closeRotateDialog} showCloseButton={false} maxWidth="max-w-xl">
	<div class="p-6 sm:p-8">
		{#if rotatingProvider}
			<div class="space-y-6">
				<div>
					<h2 class="text-xl font-semibold text-[var(--text-bright)]">
						{rotatingProvider.tokenFingerprint ? 'Rotate Token' : 'Add Token'}
					</h2>
					<p class="mt-1 text-sm text-[var(--text-tertiary)]">
						{rotatingProvider.displayName}
					</p>
				</div>

				{#if rotatingProvider.tokenFingerprint}
					<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
						<p class="text-xs text-[var(--text-tertiary)]">
							Current token: <span class="font-mono text-[var(--text-secondary)]">{rotatingProvider.tokenFingerprint}</span>
						</p>
					</div>
				{/if}

				<div class="space-y-2">
					<label class="text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]" for="rotate-pat-input">
						{rotatingProvider.tokenFingerprint ? 'New Personal Access Token' : 'Personal Access Token'}
					</label>
					<div class="relative">
						<input
							id="rotate-pat-input"
							type={showRotatePat ? 'text' : 'password'}
							placeholder="Enter PAT"
							class="w-full rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 pr-12 text-sm text-[var(--text-secondary)] focus:border-[var(--accent)] focus:outline-none disabled:opacity-50"
							bind:value={rotatePat}
							disabled={saving}
						/>
						<button
							type="button"
							class="absolute right-3 top-1/2 -translate-y-1/2 rounded-full p-2 text-[var(--text-muted)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-secondary)]"
							onclick={() => (showRotatePat = !showRotatePat)}
							aria-label={showRotatePat ? 'Hide PAT' : 'Show PAT'}
						>
							{#if showRotatePat}
								<EyeOff size={16} />
							{:else}
								<Eye size={16} />
							{/if}
						</button>
					</div>
				</div>

				{#if rotateError}
					<div class="rounded-xl border border-[var(--error)]/30 bg-[var(--error)]/10 p-3 text-sm text-[var(--error)]">
						{rotateError}
					</div>
				{/if}

				<div class="flex items-center justify-between gap-3 border-t border-[var(--border-color)]/60 pt-6">
					<div class="flex gap-2">
						<button
							type="button"
							class="btn btn-primary"
							onclick={submitRotateToken}
							disabled={saving || !rotatePat.trim()}
						>
							{saving ? 'Saving...' : 'Save'}
						</button>
						<button
							type="button"
							class="rounded-full border border-[var(--border-color)] px-5 py-2.5 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
							onclick={closeRotateDialog}
							disabled={saving}
						>
							Cancel
						</button>
					</div>
					{#if rotatingProvider.tokenFingerprint}
						<button
							type="button"
							class="rounded-full border border-[var(--error)]/40 px-5 py-2.5 text-sm text-[var(--error)] transition hover:bg-[var(--error)]/10 disabled:opacity-50"
							onclick={submitMakePublic}
							disabled={saving}
							title="Revoke the current token and allow unauthenticated access"
						>
							{saving ? 'Revoking...' : 'Make Public'}
						</button>
					{/if}
				</div>
			</div>
		{/if}
	</div>
</Dialog>

<!-- Remove Provider Confirm -->
{#if removingProvider}
	<ConfirmDialog
		bind:open={removeDialogOpen}
		title="Remove {removingProvider.displayName}?"
		description="This will remove the provider configuration and its token. Existing scans and SBOMs are not affected."
		iconVariant="danger"
		buttons={[
			{ label: 'Cancel', variant: 'ghost', onclick: () => { removeDialogOpen = false; removingProvider = null; } },
			{ label: 'Remove', variant: 'danger', onclick: confirmRemoveProvider }
		]}
	>
		{#snippet icon()}<Trash2 size={26} />{/snippet}
	</ConfirmDialog>
{/if}

<style>
	.sync-now-btn {
		position: relative;
		overflow: hidden;
	}

	.sync-label {
		position: relative;
		display: inline-block;
	}

	.sync-now-btn.syncing .syncing-text::after {
		content: attr(data-text);
		position: absolute;
		inset: 0;
		color: transparent;
		background: linear-gradient(
			110deg,
			transparent 0%,
			transparent 35%,
			color-mix(in srgb, var(--text-primary) 55%, transparent) 46%,
			var(--text-primary) 50%,
			color-mix(in srgb, var(--text-primary) 55%, transparent) 54%,
			transparent 65%,
			transparent 100%
		);
		background-size: 220% 100%;
		-webkit-background-clip: text;
		background-clip: text;
		animation: sync-thinking-shimmer 1.25s linear infinite;
	}

	@keyframes sync-thinking-shimmer {
		0% {
			background-position: 200% 0;
		}
		100% {
			background-position: -30% 0;
		}
	}
</style>
