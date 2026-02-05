<script lang="ts">
	import { onMount } from 'svelte';
	import { slide } from 'svelte/transition';
	import { browser } from '$app/environment';
	import { ShieldCheck, KeyRound, RefreshCw, Eye, EyeOff } from 'lucide-svelte';

	type ProviderType = 'github' | 'gitlab' | 'gitea' | 'forgejo';
	type ProviderTypeMode = ProviderType | 'auto';

	type ProviderRow = {
		id: string;
		providerUrl: string;
		baseUrl: string;
		ownerPath: string;
		type: ProviderType;
		displayName: string;
		tokenFingerprint?: string;
		enabled: boolean;
		createdAt: string;
		updatedAt?: string;
		lastRotatedAt?: string;
	};

	type ProviderPreview = {
		type?: ProviderType;
		baseUrl?: string;
		ownerPath?: string;
		errors: string[];
	};

	let providers: ProviderRow[] = $state([]);
	let providerUrl = $state('');
	let providerTypeMode: ProviderTypeMode = $state('auto');
	let displayName = $state('');
	let pat = $state('');
	let preview: ProviderPreview = $state({ errors: [] });
	let formError = $state('');
	let error = $state('');
	let loading = $state(true);
	let saving = $state(false);
	let rotatePat = $state('');
	let rotatingId = $state<string | null>(null);
	let showPat = $state(false);
	let showValidation = $state(false);
	let showAddProvider = $state(false);

	type ApiProvider = {
		id: string;
		provider_url: string;
		base_url: string;
		owner_path: string;
		type: ProviderType;
		display_name: string;
		token_fingerprint?: string;
		enabled: boolean;
		created_at: string;
		updated_at?: string;
		last_rotated_at?: string;
	};

	const detectTypeFromHost = (host: string): ProviderType | undefined => {
		if (host === 'github.com') return 'github';
		if (host.includes('gitlab')) return 'gitlab';
		if (host.includes('forgejo')) return 'forgejo';
		if (host.includes('gitea')) return 'gitea';
		return undefined;
	};

	const ensureScheme = (value: string) => {
		const trimmed = value.trim();
		if (!trimmed) return trimmed;
		if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
			return trimmed;
		}
		return `https://${trimmed}`;
	};

	const parseProviderUrl = (raw: string, mode: ProviderTypeMode): ProviderPreview => {
		const errors: string[] = [];
		if (!raw.trim()) {
			return { errors: ['Provider URL is required.'] };
		}
		let url: URL;
		try {
			url = new URL(ensureScheme(raw));
		} catch {
			return { errors: ['Provider URL must be a valid URL (https://...).'] };
		}
		if (url.protocol !== 'https:') {
			errors.push('Provider URL must start with https://');
		}

		const host = url.host.toLowerCase();
		const path = url.pathname.replace(/^\/+|\/+$/g, '');
		const ownerPath = path;
		const detected = detectTypeFromHost(host);
		const type = mode === 'auto' ? detected : mode;

		if (!type) {
			errors.push('Could not detect provider type. Choose a type manually.');
		}

		if (type === 'github') {
			const parts = ownerPath.split('/').filter(Boolean);
			if (parts.length === 0) {
				errors.push('GitHub providers must include an org or user path.');
			} else if (parts.length > 1) {
				errors.push('GitHub providers must point to an org or user, not a repo.');
			}
		}

		const baseUrl = `${url.protocol}//${url.host}`;

		return {
			type,
			baseUrl,
			ownerPath,
			errors
		};
	};

	const updatePreview = () => {
		preview = parseProviderUrl(providerUrl, providerTypeMode);
		formError = '';
	};

	const resetForm = () => {
		providerUrl = '';
		displayName = '';
		pat = '';
		providerTypeMode = 'auto';
		showPat = false;
		showValidation = false;
		updatePreview();
	};

	const mapProvider = (entry: ApiProvider): ProviderRow => ({
		id: entry.id,
		providerUrl: entry.provider_url,
		baseUrl: entry.base_url,
		ownerPath: entry.owner_path || '',
		type: entry.type,
		displayName: entry.display_name,
		tokenFingerprint: entry.token_fingerprint,
		enabled: entry.enabled,
		createdAt: entry.created_at,
		updatedAt: entry.updated_at,
		lastRotatedAt: entry.last_rotated_at
	});

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

	const addProvider = async () => {
		showValidation = true;
		const nextPreview = parseProviderUrl(providerUrl, providerTypeMode);
		if (nextPreview.errors.length > 0) {
			formError = '';
			return;
		}
		saving = true;
		formError = '';
		try {
			const payload = {
				provider_url: ensureScheme(providerUrl).trim(),
				display_name: displayName.trim() || undefined,
				pat: pat.trim() || undefined,
				type: providerTypeMode === 'auto' ? undefined : providerTypeMode
			};

			const response = await fetch('/api/admin/providers', {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(payload)
			});

			if (!response.ok) {
				const text = await response.text();
				formError = text || 'Failed to create provider.';
				return;
			}

			const created: ApiProvider = await response.json();
			providers = [mapProvider(created), ...providers];
			resetForm();
			showAddProvider = false;
		} catch {
			formError = 'Failed to create provider.';
		} finally {
			saving = false;
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

	const startRotate = (entry: ProviderRow) => {
		rotatingId = entry.id;
		rotatePat = '';
		formError = '';
	};

	const cancelRotate = () => {
		rotatingId = null;
		rotatePat = '';
	};

	const submitRotate = async (entry: ProviderRow) => {
		if (!rotatePat.trim()) {
			formError = 'New PAT is required.';
			return;
		}
		saving = true;
		formError = '';
		try {
			const response = await fetch(`/api/admin/providers/${entry.id}/rotate`, {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ pat: rotatePat })
			});

			if (!response.ok) {
				formError = 'Failed to rotate token.';
				return;
			}

			const updated: ApiProvider = await response.json();
			providers = providers.map((provider) => (provider.id === updated.id ? mapProvider(updated) : provider));
			cancelRotate();
		} catch {
			formError = 'Failed to rotate token.';
		} finally {
			saving = false;
		}
	};

	const removeProvider = async (entry: ProviderRow) => {
		if (!confirm(`Remove ${entry.displayName}?`)) return;
		saving = true;
		formError = '';
		try {
			const response = await fetch(`/api/admin/providers/${entry.id}`, {
				method: 'DELETE',
				credentials: 'include'
			});
			if (!response.ok) {
				formError = 'Failed to delete provider.';
				return;
			}
			providers = providers.filter((provider) => provider.id !== entry.id);
		} catch {
			formError = 'Failed to delete provider.';
		} finally {
			saving = false;
		}
	};

	const toggleAddProvider = () => {
		showAddProvider = !showAddProvider;
		if (!showAddProvider) {
			resetForm();
		}
	};

	const providerTag = (type: ProviderType) => {
		switch (type) {
			case 'github':
				return 'GitHub';
			case 'gitlab':
				return 'GitLab';
			case 'gitea':
				return 'Gitea';
			case 'forgejo':
				return 'Forgejo';
			default:
				return 'Unknown';
		}
	};

	const providerSummary = (entry: ProviderRow) => {
		if (entry.ownerPath) return `${entry.baseUrl}/${entry.ownerPath}`;
		return entry.baseUrl;
	};

	onMount(() => {
		if (browser) {
			loadProviders();
			updatePreview();
		}
	});
</script>

<svelte:head>
	<title>Admin Providers - Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Admin Providers</h1>
				<p class="text-sm text-[var(--text-tertiary)]">
					Configure provider tokens that power the Git providers view.
				</p>
			</div>
			<div class="flex flex-wrap items-center gap-2">
			<button
				type="button"
				class="inline-flex items-center gap-2 rounded-full border border-[var(--border-color)] px-4 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
				onclick={loadProviders}
				disabled={loading}
			>
				<RefreshCw size={16} />
				Refresh
			</button>
			</div>
		</header>

		<div class="grid gap-4 lg:grid-cols-3">
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
					<ShieldCheck size={16} />
					<span>Write-only tokens</span>
				</div>
				<p class="mt-2 text-xs text-[var(--text-tertiary)]">
					PATs are masked immediately after creation and never shown again.
				</p>
			</div>
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
					<KeyRound size={16} />
					<span>Admin-only control</span>
				</div>
				<p class="mt-2 text-xs text-[var(--text-tertiary)]">
					Providers added here are the only ones visible to end users.
				</p>
			</div>
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<p class="text-xs text-[var(--text-tertiary)]">
					{#if providers.length === 0}
						Default GitHub + GitLab tabs would appear for users.
					{:else}
						Only these configured providers would appear for users.
					{/if}
				</p>
			</div>
		</div>
	</section>

	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">Configured Providers</h2>
				<p class="text-sm text-[var(--text-tertiary)]">Stored in the database and encrypted at rest.</p>
			</div>
			<button
				type="button"
				class={`inline-flex items-center gap-2 rounded-full border px-4 py-2 text-sm font-semibold transition ${
					showAddProvider
						? 'border-[var(--border-color)] text-[var(--text-secondary)] hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]'
						: 'border-amber-300 bg-amber-300 text-amber-950 hover:bg-amber-200'
				}`}
				onclick={toggleAddProvider}
			>
				{showAddProvider ? 'Close' : 'Add Provider'}
			</button>
		</header>

		{#if showAddProvider}
			<div class="grid gap-4 lg:grid-cols-3" in:slide={{ duration: 180 }} out:slide={{ duration: 160 }}>
				<div class="lg:col-span-2 space-y-4">
					<div class="grid gap-4 md:grid-cols-2">
						<div class="space-y-2">
							<label class="text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">Provider URL</label>
							<input
								type="url"
								placeholder="https://github.com/NorskHelsenett"
								class="w-full rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 text-sm text-[var(--text-secondary)] focus:border-[var(--accent)] focus:outline-none"
								bind:value={providerUrl}
								oninput={updatePreview}
							/>
						</div>
						<div class="space-y-2">
							<label class="text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">Provider Type</label>
							<select
								class="w-full rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 text-sm text-[var(--text-secondary)] focus:border-[var(--accent)] focus:outline-none"
								bind:value={providerTypeMode}
								onchange={updatePreview}
							>
								<option value="auto">Auto detect</option>
								<option value="github">GitHub</option>
								<option value="gitlab">GitLab</option>
								<option value="gitea">Gitea</option>
								<option value="forgejo">Forgejo</option>
							</select>
						</div>
					</div>

					<div class="grid gap-4 md:grid-cols-2">
						<div class="space-y-2">
							<label class="text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">Display Name</label>
							<input
								type="text"
								placeholder="github.com/NorskHelsenett"
								class="w-full rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 text-sm text-[var(--text-secondary)] focus:border-[var(--accent)] focus:outline-none"
								bind:value={displayName}
							/>
							<p class="text-xs text-[var(--text-tertiary)]">Optional. Defaults to derived URL.</p>
						</div>
						<div class="space-y-2">
							<label class="text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">Personal Access Token</label>
							<div class="relative">
								<input
									type={showPat ? 'text' : 'password'}
									placeholder="Enter PAT"
									class="w-full rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 pr-12 text-sm text-[var(--text-secondary)] focus:border-[var(--accent)] focus:outline-none"
									bind:value={pat}
								/>
								<button
									type="button"
									class="absolute right-3 top-1/2 -translate-y-1/2 rounded-full p-2 text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)]"
									onclick={() => (showPat = !showPat)}
									aria-label={showPat ? 'Hide PAT' : 'Show PAT'}
								>
									{#if showPat}
										<EyeOff size={14} />
									{:else}
										<Eye size={14} />
									{/if}
								</button>
							</div>
							<p class="text-xs text-[var(--text-tertiary)]">Optional. Leave empty to mark as public.</p>
						</div>
					</div>

				{#if showValidation && preview.errors.length > 0}
					<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">
						{preview.errors[0]}
					</div>
				{/if}
				{#if showValidation && formError}
					<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">
						{formError}
					</div>
				{/if}
				</div>

				<div class="space-y-4 rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
					<h3 class="text-sm font-semibold text-[var(--text-bright)]">Derived Preview</h3>
					<div class="text-xs text-[var(--text-tertiary)]">
						<p>Type: {preview.type ? providerTag(preview.type) : 'Unknown'}</p>
						<p>Base URL: {preview.baseUrl ?? '-'}</p>
						<p>Owner/Group: {preview.ownerPath || 'All repositories'}</p>
						<p>Access: {pat.trim() ? 'PAT required' : 'Public'}</p>
					</div>
					<button
						type="button"
						class="w-full rounded-full border border-amber-300 bg-amber-300 px-4 py-2 text-sm font-semibold text-amber-950 transition hover:bg-amber-200"
						onclick={addProvider}
					>
						Add Provider
					</button>
				</div>
			</div>
		{/if}

		{#if error}
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">{error}</div>
		{/if}
		{#if formError && !showAddProvider}
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">{formError}</div>
		{/if}

		{#if loading}
			<p class="text-sm text-[var(--text-secondary)]">Loading providers...</p>
		{:else if providers.length === 0}
			<p class="text-sm text-[var(--text-secondary)]">No providers configured yet.</p>
		{:else}
			<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
				<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
					<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
						<tr>
							<th class="px-5 py-3 text-left">Provider</th>
							<th class="px-5 py-3 text-left">Type</th>
							<th class="px-5 py-3 text-left">Owner/Group</th>
							<th class="px-5 py-3 text-left">Token</th>
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
									<span class={`inline-flex items-center rounded-full border px-2 py-1 text-xs ${entry.enabled ? 'border-[var(--success)]/40 text-[var(--success)]' : 'border-[var(--border-color)] text-[var(--text-tertiary)]'}`}>
										{entry.enabled ? 'Enabled' : 'Disabled'}
									</span>
								</td>
								<td class="px-5 py-3">
									<div class="flex flex-wrap gap-2">
										<button
											type="button"
											class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
											onclick={() => startRotate(entry)}
											disabled={saving}
										>
											Rotate
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
											class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
											onclick={() => removeProvider(entry)}
											disabled={saving}
										>
											Remove
										</button>
									</div>
								</td>
							</tr>
							{#if rotatingId === entry.id}
								<tr class="bg-[var(--hover-bg-subtle)]">
									<td class="px-5 py-3" colspan="6">
										<div class="flex flex-wrap items-center gap-3">
											<input
												type="password"
												placeholder="New PAT"
												class="w-64 rounded-full border border-[var(--border-color)] bg-transparent px-4 py-2 text-xs text-[var(--text-secondary)] focus:border-[var(--accent)] focus:outline-none disabled:opacity-50"
												bind:value={rotatePat}
												disabled={saving}
											/>
											<button
												type="button"
												class="rounded-full border border-[var(--accent)] bg-[var(--accent)]/10 px-4 py-2 text-xs font-medium text-[var(--accent)] transition hover:bg-[var(--accent)]/20 disabled:opacity-50"
												onclick={() => submitRotate(entry)}
												disabled={saving}
											>
												{saving ? 'Saving...' : 'Save'}
											</button>
											<button
												type="button"
												class="rounded-full border border-[var(--border-color)] px-4 py-2 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
												onclick={cancelRotate}
												disabled={saving}
											>
												Cancel
											</button>
										</div>
									</td>
								</tr>
							{/if}
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</section>
</div>
