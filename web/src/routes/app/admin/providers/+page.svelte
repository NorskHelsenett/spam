<script lang="ts">
	import { onMount } from 'svelte';
	import { tick } from 'svelte';
	import { slide } from 'svelte/transition';
	import { browser } from '$app/environment';
	import { ShieldCheck, KeyRound, Eye, EyeOff, ChevronDown, ShieldAlert, Play, Clock, Trash2 } from 'lucide-svelte';
	import RotateCw from 'lucide-svelte/icons/rotate-cw';
	import RotateCcw from 'lucide-svelte/icons/rotate-ccw';
	import X from 'lucide-svelte/icons/x';
	import Dialog from '$lib/components/Dialog.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import Select from '$lib/components/Select.svelte';
	import Toggle from '$lib/components/Toggle.svelte';
	import { providerSyncStates, initSyncStates, updateSyncState } from '$lib/stores/providerSync';
	import { newUserCount, newUserEvent } from '$lib/stores/newUserCount';

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
		pollInterval?: number | null;
		healthStatus: string;
		healthMessage?: string;
		lastHealthCheck?: string;
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
	let refreshing = $state(false);
	let saving = $state(false);
	let rotatePat = $state('');
	let rotateDialogOpen = $state(false);
	let rotatingProvider = $state<ProviderRow | null>(null);
	let showPat = $state(false);
	let showRotatePat = $state(false);
	let showValidation = $state(false);
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

	type ApiProvider = {
		id: string;
		provider_url: string;
		base_url: string;
		owner_path: string;
		type: ProviderType;
		display_name: string;
		token_fingerprint?: string;
		enabled: boolean;
		poll_interval?: number | null;
		health_status?: string;
		health_message?: string;
		last_health_check?: string;
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
		pollInterval: entry.poll_interval,
		healthStatus: entry.health_status || 'UNKNOWN',
		healthMessage: entry.health_message,
		lastHealthCheck: entry.last_health_check,
		createdAt: entry.created_at,
		updatedAt: entry.updated_at,
		lastRotatedAt: entry.last_rotated_at
	});

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
		refreshing = true;
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
			setTimeout(() => { refreshing = false; }, 1000);
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
				if (text && text.toLowerCase().includes('provider health check failed')) {
					formError = 'Could not verify provider access. Check URL and PAT.';
				} else {
					formError = text || 'Failed to create provider.';
				}
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

	const submitRotateToken = async () => {
		if (!rotatingProvider) return;
		if (!rotatePat.trim()) {
			rotateError = 'PAT is required.';
			return;
		}
		saving = true;
		rotateError = '';
		try {
			const response = await fetch(`/api/admin/providers/${rotatingProvider.id}/rotate`, {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ pat: rotatePat })
			});

			if (!response.ok) {
				rotateError = 'Failed to rotate token.';
				return;
			}

			const updated: ApiProvider = await response.json();
			providers = providers.map((provider) => (provider.id === updated.id ? mapProvider(updated) : provider));
			closeRotateDialog();
		} catch {
			rotateError = 'Failed to rotate token.';
		} finally {
			saving = false;
		}
	};

	const submitMakePublic = async () => {
		if (!rotatingProvider) return;
		saving = true;
		rotateError = '';
		try {
			const response = await fetch(`/api/admin/providers/${rotatingProvider.id}/rotate`, {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ pat: '' })
			});

			if (!response.ok) {
				rotateError = 'Failed to revoke token.';
				return;
			}

			const updated: ApiProvider = await response.json();
			providers = providers.map((provider) => (provider.id === updated.id ? mapProvider(updated) : provider));
			closeRotateDialog();
		} catch {
			rotateError = 'Failed to revoke token.';
		} finally {
			saving = false;
		}
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

	type OSVScanStatus = {
		job_id?: string;
		status?: string;
		created_at?: string;
		finished_at?: string;
		error?: string;
		result?: {
			total_purls: number;
			scanned: number;
			vulns_found: number;
			components_with_vulns: number;
			errors: number;
			phase?: string;
			enrich_total?: number;
			enrich_done?: number;
		};
	};

	let osvStatus: OSVScanStatus = $state({});
	let osvLoading = $state(false);
	let osvTriggering = $state(false);
	let osvError = $state('');
	let cacheClearing = $state(false);
	let cacheMessage = $state('');

	const loadOSVStatus = async () => {
		try {
			const response = await fetch('/api/admin/osv/scan/status', { credentials: 'include' });
			if (response.ok) osvStatus = await response.json();
		} catch { /* ignore */ }
	};

	const triggerOSVScan = async () => {
		osvTriggering = true;
		osvError = '';
		try {
			const response = await fetch('/api/admin/osv/scan', {
				method: 'POST',
				credentials: 'include'
			});
			if (response.status === 409) {
				osvError = 'A scan is already queued or running.';
				return;
			}
			if (!response.ok) {
				osvError = 'Failed to start scan.';
				return;
			}
			osvStatus = await response.json();
			// Poll until done
			pollOSVStatus();
		} catch {
			osvError = 'Failed to start scan.';
		} finally {
			osvTriggering = false;
		}
	};

	const clearCache = async () => {
		cacheClearing = true;
		cacheMessage = '';
		try {
			const response = await fetch('/api/admin/cache/clear', {
				method: 'POST',
				credentials: 'include'
			});
			if (!response.ok) {
				cacheMessage = 'Failed to clear application cache.';
				return;
			}
			cacheMessage = 'Application cache cleared. Cached views will repopulate on the next request or refresh job.';
		} catch {
			cacheMessage = 'Failed to clear application cache.';
		} finally {
			cacheClearing = false;
		}
	};

	let osvPollTimer: ReturnType<typeof setTimeout> | null = null;

	const pollOSVStatus = () => {
		if (osvPollTimer) clearTimeout(osvPollTimer);
		osvPollTimer = setTimeout(async () => {
			await loadOSVStatus();
			const active = osvStatus.status === 'QUEUED' || osvStatus.status === 'RUNNING' || osvStatus.status === 'RETRY';
			if (active) pollOSVStatus();
		}, 3000);
	};

	const osvStatusLabel = (status?: string) => {
		switch (status) {
			case 'QUEUED': return 'Queued';
			case 'RUNNING': return 'Running…';
			case 'RETRY': return 'Retrying';
			case 'SUCCEEDED': return 'Completed';
			case 'FAILED': return 'Failed';
			default: return 'Never run';
		}
	};

	const osvStatusClass = (status?: string) => {
		switch (status) {
			case 'RUNNING':
			case 'QUEUED':
			case 'RETRY': return 'text-amber-400 border-amber-400/40';
			case 'SUCCEEDED': return 'text-green-400 border-green-400/40';
			case 'FAILED': return 'text-[var(--error)] border-[var(--error)]/40';
			default: return 'text-[var(--text-tertiary)] border-[var(--border-color)]';
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

	// ── Users ──────────────────────────────────────────────────────────────
	type UserSummary = {
		id: string;
		subject: string;
		email?: string;
		name?: string;
		approved: boolean;
		hidden: boolean;
		role: string;
		groups: string[];
		last_login_at?: string;
		created_at: string;
	};

	const roleOptions = [
		{ value: 'pending', label: 'Pending' },
		{ value: 'default', label: 'Default' },
		{ value: 'global_reader', label: 'Global reader' },
		{ value: 'admin', label: 'Admin' }
	];

	let users: UserSummary[] = $state([]);
	let usersLoading = $state(true);
	let usersError = $state('');
	let savingUser = $state<string | null>(null);
	let usersRefreshing = $state(false);
	let showHidden = $state(false);

	const visibleUsers = $derived(showHidden ? users : users.filter((u) => !u.hidden));

	const loadUsers = async () => {
		usersLoading = true;
		usersRefreshing = true;
		usersError = '';
		try {
			const response = await fetch('/api/admin/users', { credentials: 'include' });
			if (!response.ok) {
				usersError = response.status === 403 ? 'Admin access required.' : 'Failed to load users.';
				users = [];
				return;
			}
			users = await response.json();
		} catch {
			usersError = 'Failed to load users.';
		} finally {
			usersLoading = false;
			setTimeout(() => { usersRefreshing = false; }, 1000);
		}
	};

	const setHidden = async (user: UserSummary, hidden: boolean) => {
		try {
			const response = await fetch(`/api/admin/users/${user.id}/hidden`, {
				method: 'PATCH',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ hidden })
			});
			if (!response.ok) return;
			const updated = await response.json();
			users = users.map((u) => (u.id === updated.id ? updated : u));
		} catch { /* ignore */ }
	};

	const updateRole = async (user: UserSummary, role: string) => {
		savingUser = user.id;
		try {
			const response = await fetch(`/api/admin/users/${user.id}`, {
				method: 'PATCH',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ role })
			});
			if (!response.ok) { usersError = 'Failed to update role.'; return; }
			const updated = await response.json();
			users = users.map((entry) => (entry.id === updated.id ? updated : entry));
		} catch {
			usersError = 'Failed to update role.';
		} finally {
			savingUser = null;
		}
	};

	$effect(() => {
		const incoming = $newUserEvent;
		if (!incoming) return;
		newUserEvent.set(null);
		newUserCount.update((n) => Math.max(0, n - 1));
		if (!users.some((u) => u.id === incoming.id)) {
			users = [...users, incoming];
		}
	});

	onMount(() => {
		if (browser) {
			loadProviders();
			loadUsers();
			newUserCount.set(0);
			loadOSVStatus().then(() => {
				const active = osvStatus.status === 'QUEUED' || osvStatus.status === 'RUNNING' || osvStatus.status === 'RETRY';
				if (active) pollOSVStatus();
			});
			updatePreview();

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
				if (osvPollTimer) clearTimeout(osvPollTimer);
			};
		}
	});

</script>

<svelte:head>
	<title>Settings - Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Settings</h1>
				<p class="text-sm text-[var(--text-tertiary)]">
					Configure provider tokens that power the Git providers view.
				</p>
			</div>
			<div class="flex flex-wrap items-center gap-2">
			<button
				type="button"
				class="btn btn-ghost"
				onclick={loadProviders}
				disabled={refreshing}
			>
				<span class="inline-flex h-[14px] w-[14px] items-center justify-center {refreshing ? 'animate-spin' : ''}">
					<RotateCw size={14} />
				</span>
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
		<header class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">Users</h2>
				<p class="text-sm text-[var(--text-tertiary)]">Approve new access requests and adjust roles.</p>
			</div>
			<div class="flex items-center gap-4">
				<Toggle bind:checked={showHidden} label="Show hidden" />
				<button type="button" class="btn btn-ghost" onclick={loadUsers} disabled={usersRefreshing}>
					<span class="inline-flex h-[14px] w-[14px] items-center justify-center {usersRefreshing ? 'animate-spin' : ''}">
						<RotateCw size={14} />
					</span>
					Refresh
				</button>
			</div>
		</header>

		{#if usersError}
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">{usersError}</div>
		{/if}

		{#if usersLoading}
			<p class="text-sm text-[var(--text-secondary)]">Loading users…</p>
		{:else if visibleUsers.length === 0}
			<p class="text-sm text-[var(--text-secondary)]">No users found.</p>
		{:else}
			<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
				<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
					<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
						<tr>
							<th class="px-5 py-3 text-left">Name</th>
							<th class="px-5 py-3 text-left">Email</th>
							<th class="px-5 py-3 text-left">Subject</th>
							<th class="px-5 py-3 text-left">Status</th>
							<th class="px-5 py-3 text-left">Role</th>
							<th class="px-5 py-3 text-left">Created</th>
							<th class="px-5 py-3"></th>
						</tr>
					</thead>
					<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
						{#each visibleUsers as user (user.id)}
							<tr transition:slide={{ duration: 200 }} class="transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]">
								<td class="px-5 py-3 font-semibold text-[var(--text-bright)]">{user.name ?? '—'}</td>
								<td class="px-5 py-3">{user.email ?? '—'}</td>
								<td class="px-5 py-3 text-xs">{user.subject}</td>
								<td class="px-5 py-3">
									<span class="badge">{user.approved ? 'Approved' : 'Pending'}</span>
								</td>
								<td class="px-5 py-3">
									<Select
										value={user.role}
										options={roleOptions}
										disabled={savingUser === user.id}
										size="sm"
										onchange={(value) => updateRole(user, value)}
									/>
								</td>
								<td class="px-5 py-3 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
									{user.created_at}
								</td>
								<td class="px-5 py-3">
									{#if user.hidden}
										<button
											type="button"
											class="rounded-full p-1 text-[var(--text-tertiary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-secondary)]"
											onclick={() => setHidden(user, false)}
											aria-label="Restore user"
											title="Restore"
										>
											<RotateCcw size={14} />
										</button>
									{:else}
										<button
											type="button"
											class="rounded-full p-1 text-[var(--text-tertiary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-secondary)]"
											onclick={() => setHidden(user, true)}
											aria-label="Hide user"
											title="Hide"
										>
											<X size={14} />
										</button>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
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
</div>

<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
	<header class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">Vulnerability Scanning</h2>
			<p class="text-sm text-[var(--text-tertiary)]">
				Checks all SBOM components against the OSV database. Results are cached per component for 24 h.
			</p>
		</div>
		<div class="flex flex-wrap items-center gap-2">
			<button
				type="button"
				class="inline-flex items-center gap-2 rounded-full border border-[var(--border-color)] px-4 py-2 text-sm font-semibold text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
				onclick={clearCache}
				disabled={cacheClearing}
			>
				<Trash2 size={14} />
				{cacheClearing ? 'Clearing…' : 'Clear Cache'}
			</button>
			<button
				type="button"
				class="inline-flex items-center gap-2 rounded-full border border-amber-300 bg-amber-300 px-4 py-2 text-sm font-semibold text-amber-950 transition hover:bg-amber-200 disabled:opacity-50"
				onclick={triggerOSVScan}
				disabled={osvTriggering || osvStatus.status === 'QUEUED' || osvStatus.status === 'RUNNING' || osvStatus.status === 'RETRY'}
			>
				<Play size={14} />
				{osvTriggering ? 'Starting…' : 'Run OSV Scan'}
			</button>
		</div>
	</header>

	{#if osvError}
		<div class="rounded-2xl border border-[var(--error)]/30 bg-[var(--error)]/5 p-4 text-sm text-[var(--error)]">
			{osvError}
		</div>
	{/if}
	{#if cacheMessage}
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--text-secondary)]">
			{cacheMessage}
		</div>
	{/if}

	<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
		<!-- Status -->
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<ShieldAlert size={16} />
				<span>Status</span>
			</div>
			<p class="mt-2 text-sm font-semibold">
				<span class="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs {osvStatusClass(osvStatus.status)}">
					{osvStatusLabel(osvStatus.status)}
				</span>
			</p>
			{#if osvStatus.created_at}
				<p class="mt-1 flex items-center gap-1 text-[11px] text-[var(--text-muted)]">
					<Clock size={10} /> Started {new Date(osvStatus.created_at).toLocaleString()}
				</p>
			{/if}
			{#if osvStatus.finished_at}
				<p class="mt-0.5 text-[11px] text-[var(--text-muted)]">
					Finished {new Date(osvStatus.finished_at).toLocaleString()}
				</p>
			{/if}
		</div>

		<!-- Scanned -->
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<ShieldCheck size={16} />
				<span>Components scanned</span>
			</div>
			<p class="mt-2 text-2xl font-semibold text-[var(--text-bright)]">
				{osvStatus.result?.scanned ?? '—'}
				{#if osvStatus.result?.total_purls}
					<span class="text-sm font-normal text-[var(--text-muted)]">/ {osvStatus.result.total_purls}</span>
				{/if}
			</p>
			{#if osvStatus.status === 'RUNNING' && osvStatus.result?.total_purls}
				{@const phase = osvStatus.result.phase}
				{@const pct = phase === 'enriching'
					? (osvStatus.result.enrich_total ? Math.round((osvStatus.result.enrich_done ?? 0) / osvStatus.result.enrich_total * 100) : 0)
					: Math.round((osvStatus.result.scanned / osvStatus.result.total_purls) * 100)}
				<div class="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-[var(--border-color)]">
					<div class="h-full rounded-full bg-amber-400 transition-all duration-500" style="width: {pct}%"></div>
				</div>
				<p class="mt-1 text-[11px] text-[var(--text-muted)]">
					{#if phase === 'enriching'}
						Enriching details — {osvStatus.result.enrich_done ?? 0}/{osvStatus.result.enrich_total} ({pct}%)
					{:else}
						{pct}% scanned
					{/if}
				</p>
			{/if}
		</div>

		<!-- Vulnerabilities -->
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<ShieldAlert size={16} />
				<span>Vulnerabilities found</span>
			</div>
			<p class="mt-2 text-2xl font-semibold {(osvStatus.result?.vulns_found ?? 0) > 0 ? 'text-red-400' : 'text-[var(--text-bright)]'}">
				{osvStatus.result?.vulns_found ?? '—'}
			</p>
			{#if osvStatus.result?.components_with_vulns != null}
				<p class="mt-1 text-[11px] text-[var(--text-muted)]">
					across {osvStatus.result.components_with_vulns} components
				</p>
			{/if}
		</div>

		<!-- Errors -->
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<span>Batch errors</span>
			</div>
			<p class="mt-2 text-2xl font-semibold {(osvStatus.result?.errors ?? 0) > 0 ? 'text-[var(--error)]' : 'text-[var(--text-bright)]'}">
				{osvStatus.result?.errors ?? '—'}
			</p>
			<p class="mt-1 text-[11px] text-[var(--text-muted)]">Failed OSV batches</p>
		</div>
	</div>

	{#if osvStatus.error}
		<div class="rounded-2xl border border-[var(--error)]/30 bg-[var(--error)]/5 p-4">
			<p class="text-xs font-semibold uppercase tracking-wider text-[var(--error)]">Job error</p>
			<p class="mt-1 text-sm text-[var(--text-secondary)]">{osvStatus.error}</p>
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
							class="rounded-full border border-amber-300 bg-amber-300 px-5 py-2.5 text-sm font-semibold text-amber-950 transition hover:bg-amber-200 disabled:opacity-50"
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
