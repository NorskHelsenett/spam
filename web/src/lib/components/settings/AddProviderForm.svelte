<script lang="ts">
	import { Eye, EyeOff, ChevronDown } from 'lucide-svelte';
	import { mapProvider, providerTag } from './providers';
	import type { ApiProvider, ProviderRow, ProviderType, ProviderTypeMode } from './providers';

	let { oncreated }: { oncreated: (provider: ProviderRow) => void } = $props();

	type ProviderPreview = {
		type?: ProviderType;
		baseUrl?: string;
		ownerPath?: string;
		errors: string[];
	};

	let providerUrl = $state('');
	let providerTypeMode: ProviderTypeMode = $state('auto');
	let displayName = $state('');
	let pat = $state('');
	let preview: ProviderPreview = $state({ errors: [] });
	let formError = $state('');
	let showPat = $state(false);
	let showValidation = $state(false);
	let saving = $state(false);

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

	updatePreview();

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
				if (text && text.toLowerCase().includes('provider health check failed')) {
					formError = 'Could not verify provider access. Check URL and PAT.';
				} else {
					formError = text || 'Failed to create provider.';
				}
				return;
			}

			const created: ApiProvider = await response.json();
			oncreated(mapProvider(created));
		} catch {
			formError = 'Failed to create provider.';
		} finally {
			saving = false;
		}
	};
</script>

<div class="grid gap-4 lg:grid-cols-3">
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
				<div class="relative">
					<select
					class="w-full appearance-none rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 pr-10 text-sm text-[var(--text-secondary)] focus:border-[var(--accent)] focus:outline-none h-[37px]"
						bind:value={providerTypeMode}
						onchange={updatePreview}
					>
						<option value="auto">Auto detect</option>
						<option value="github">GitHub</option>
						<option value="gitlab">GitLab</option>
						<option value="gitea">Gitea</option>
						<option value="forgejo">Forgejo</option>
					</select>
					<div class="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 text-[var(--text-secondary)]">
						<ChevronDown size={16} />
					</div>
				</div>
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
			class="btn btn-primary w-full"
			onclick={addProvider}
			disabled={saving}
		>
			{saving ? 'Adding…' : 'Add Provider'}
		</button>
	</div>
</div>
