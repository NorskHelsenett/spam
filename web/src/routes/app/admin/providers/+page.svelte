<script lang="ts">
	import { onMount } from 'svelte';
	import { tick } from 'svelte';
	import { slide, fly } from 'svelte/transition';
	import { cubicOut, cubicIn } from 'svelte/easing';
	import { browser } from '$app/environment';
	import { ShieldCheck, KeyRound, Eye, EyeOff, ChevronDown, ShieldAlert, Play, Clock, Trash2, Copy, Download, FileWarning } from 'lucide-svelte';
	import RotateCw from 'lucide-svelte/icons/rotate-cw';
	import RotateCcw from 'lucide-svelte/icons/rotate-ccw';
	import X from 'lucide-svelte/icons/x';
	import Dialog from '$lib/components/Dialog.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import Select from '$lib/components/Select.svelte';
	import Toggle from '$lib/components/Toggle.svelte';
	import Loading from '$lib/components/Loading.svelte';
	import Checkbox from '$lib/components/Checkbox.svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';
	import SecretInspectDrawer from '$lib/components/SecretInspectDrawer.svelte';
	import MultiSelect from '$lib/components/MultiSelect.svelte';
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

	// ── Trivy scanner ──────────────────────────────────────────────────────
	type TrivyRun = {
		started_at: string;
		finished_at: string;
		sbom_count: number;
		critical_count: number;
		high_count: number;
	};

	type TrivyScanStatus = {
		job_id?: string;
		job_status?: string;
		created_at?: string;
		finished_at?: string;
		error?: string;
		pending_count?: number;
		scanned_count?: number;
		last_scanned_at?: string;
		scan_complete?: boolean;
		recent_runs?: TrivyRun[];
	};

	let trivyStatus: TrivyScanStatus = $state({});
	let trivyTriggering = $state(false);
	let trivyError = $state('');
	let trivyPollTimer: ReturnType<typeof setTimeout> | null = null;

	const loadTrivyStatus = async () => {
		try {
			const response = await fetch('/api/admin/trivy/scan/status', { credentials: 'include' });
			if (response.ok) trivyStatus = await response.json();
		} catch { /* ignore */ }
	};

	const triggerTrivyScan = async () => {
		trivyTriggering = true;
		trivyError = '';
		try {
			const response = await fetch('/api/admin/trivy/scan', {
				method: 'POST',
				credentials: 'include'
			});
			if (response.status === 409) {
				trivyError = 'A scan job is already queued or running.';
				return;
			}
			if (response.status === 503) {
				// Should not reach here since button is disabled when not configured.
				return;
			}
			if (!response.ok) {
				trivyError = 'Failed to start scan.';
				return;
			}
			await loadTrivyStatus();
			pollTrivyStatus();
		} catch {
			trivyError = 'Failed to start scan.';
		} finally {
			trivyTriggering = false;
		}
	};

	const pollTrivyStatus = () => {
		if (trivyPollTimer) clearTimeout(trivyPollTimer);
		trivyPollTimer = setTimeout(async () => {
			await loadTrivyStatus();
			const active =
				trivyStatus.job_status === 'QUEUED' ||
				trivyStatus.job_status === 'RUNNING' ||
				trivyStatus.job_status === 'RETRY' ||
				!trivyStatus.scan_complete;
			if (active) pollTrivyStatus();
		}, 3000);
	};

	const trivyJobStatusLabel = (status?: string) => {
		switch (status) {
			case 'QUEUED': return 'Queued';
			case 'RUNNING': return 'Running…';
			case 'RETRY': return 'Retrying';
			case 'SUCCEEDED': return 'Job created';
			case 'FAILED': return 'Failed';
			default: return 'Never triggered';
		}
	};

	const trivyJobStatusClass = (status?: string) => {
		switch (status) {
			case 'RUNNING':
			case 'QUEUED':
			case 'RETRY': return 'text-amber-400 border-amber-400/40';
			case 'SUCCEEDED': return 'text-green-400 border-green-400/40';
			case 'FAILED': return 'text-[var(--error)] border-[var(--error)]/40';
			default: return 'text-[var(--text-tertiary)] border-[var(--border-color)]';
		}
	};

	// ── Secret Probe ────────────────────────────────────────────
	type ProbeStatus = {
		job?: {
			id: string;
			status: string;
			created_at?: string;
			finished_at?: string;
			error?: string;
			result?: any;
		};
		stats: {
			total: number;
			valid: number;
			invalid: number;
			revoked: number;
			expired: number;
			false_positive: number;
			unknown: number;
			error: number;
		};
		registered_rules: string[];
	};

	let probeStatus: ProbeStatus = $state({ stats: { total: 0, valid: 0, invalid: 0, revoked: 0, expired: 0, false_positive: 0, unknown: 0, error: 0 }, registered_rules: [] });
	let probeTriggering = $state(false);
	let probeError = $state('');
	let probeSelectedRules: string[] = $state([]);
	let probeForce = $state(false);
	let probePreviewOpen = $state(false);
	let probePreview: any[] = $state([]);
	let probePreviewLoading = $state(false);
	let probePreviewTab = $state('all');
	let inspectItem: { hash: string; secret: string; ruleId: string } | null = $state(null);

	// Dismiss inspect drawer when tab or loading state changes
	$effect(() => {
		probePreviewTab;
		probePreviewLoading;
		inspectItem = null;
	});

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

	let probeListOpen = $state(false);
	let probeListTitle = $state('');
	let probeListStatuses: string[] = $state([]);
	let probeListItems: any[] = $state([]);
	let probeListLoading = $state(false);

	const openProbeList = async (title: string, statuses: string[]) => {
		probeListTitle = title;
		probeListStatuses = statuses;
		probeListOpen = true;
		probeListLoading = true;
		probeListItems = [];
		try {
			const params = statuses.map(s => `status=${s}`).join('&');
			const res = await fetch(`/api/admin/secrets/probe/list?${params}`, { credentials: 'include' });
			if (res.ok) {
				const data = await res.json();
				probeListItems = Array.isArray(data) ? data : [];
			}
		} catch { /* ignore */ }
		finally { probeListLoading = false; }
	};

	// Selection toolbar for secrets
	let selectionToolbar: { top: number; left: number; text: string; range: Range } | null = $state(null);

	$effect(() => {
		if (!probeListOpen) selectionToolbar = null;
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

	// Auto-decode: find all base64 values in a secret element and replace inline
	const autoDecodeElement = (el: HTMLElement) => {
		const text = el.textContent || '';
		// Match base64 patterns: JWT parts (eyJ...), long base64 strings, key=value base64
		const b64Pattern = /(?:eyJ[A-Za-z0-9+/\-_]{10,}={0,2})|(?:[A-Za-z0-9+/\-_]{20,}={0,2})/g;
		let match;
		const replacements: { start: number; end: number; original: string; decoded: string }[] = [];

		while ((match = b64Pattern.exec(text)) !== null) {
			const candidate = match[0];
			// Skip if it looks like a URL path or hex-only
			if (/^[0-9a-fA-F]+$/.test(candidate)) continue;
			if (candidate.includes('://')) continue;
			const decoded = tryBase64Decode(candidate);
			if (decoded && decoded !== candidate && decoded.length > 3) {
				replacements.push({
					start: match.index,
					end: match.index + candidate.length,
					original: candidate,
					decoded
				});
			}
		}

		if (replacements.length === 0) return;

		// Build new content with decoded spans
		const frag = document.createDocumentFragment();
		let cursor = 0;
		for (const r of replacements) {
			if (r.start > cursor) {
				frag.appendChild(document.createTextNode(text.slice(cursor, r.start)));
			}
			const span = document.createElement('span');
			span.style.color = 'var(--accent)';
			span.style.whiteSpace = 'pre-wrap';
			span.textContent = r.decoded;
			span.title = `Original: ${r.original}`;
			frag.appendChild(span);
			cursor = r.end;
		}
		if (cursor < text.length) {
			frag.appendChild(document.createTextNode(text.slice(cursor)));
		}
		el.textContent = '';
		el.appendChild(frag);
	};

	const exportProbeCSV = () => {
		const params = probeListStatuses.map(s => `status=${s}`).join('&');
		window.open(`/api/admin/secrets/probe/export?${params}`, '_blank');
	};
	let probeExcludedHashes: Set<string> = $state(new Set());
	let probePollTimer: ReturnType<typeof setTimeout> | null = null;

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
		// For webhook URLs, the URL itself is the secret
		const url = req.url === secret ? req.url : req.url;
		return `curl -s ${req.method === 'POST' ? '-X POST ' : ''}${headers} ${body} '${url}'`.replace(/\s+/g, ' ').trim();
	};

	const copyToClipboard = (text: string) => {
		navigator.clipboard.writeText(text);
	};

	const loadProbePreview = async () => {
		probePreviewLoading = true;
		probePreview = [];
		probeExcludedHashes = new Set();
		try {
			const params = probeForce ? '?include_probed=true' : '';
			const res = await fetch(`/api/admin/secrets/probe/preview${params}`, { credentials: 'include' });
			if (res.ok) {
				const data = await res.json();
				probePreview = Array.isArray(data) ? data : [];
				// Pre-exclude dismissed and inactive (expired/invalid/false_positive) items.
				const excluded = new Set<string>();
				for (const group of probePreview) {
					for (const item of group.items ?? []) {
						if (item.dismissed || item.probe_status === 'expired' || item.probe_status === 'invalid' || item.probe_status === 'false_positive') {
							excluded.add(item.secret_hash);
						}
					}
				}
				probeExcludedHashes = excluded;
			}
		} catch { /* ignore */ }
		finally { probePreviewLoading = false; }
	};

	const toggleDismiss = (secretHash: string) => {
		const isDismissed = probeExcludedHashes.has(secretHash);
		const next = new Set(probeExcludedHashes);
		if (isDismissed) { next.delete(secretHash); } else { next.add(secretHash); }
		probeExcludedHashes = next;

		// Update the item's dismissed state in probePreview so the status column reflects it.
		for (const group of probePreview) {
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

	const loadProbeStatus = async () => {
		try {
			const response = await fetch('/api/admin/secrets/probe/status', { credentials: 'include' });
			if (response.ok) probeStatus = await response.json();
		} catch { /* ignore */ }
	};

	const triggerProbe = async () => {
		probeTriggering = true;
		probeError = '';
		try {
			const body: any = {};
			if (probeSelectedRules.length > 0) body.rule_ids = probeSelectedRules;
			if (probeForce) body.force = true;
			const response = await fetch('/api/admin/secrets/probe', {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(body)
			});
			if (response.status === 409) {
				probeError = 'A probe job is already queued or running.';
				return;
			}
			if (!response.ok) {
				probeError = 'Failed to start probe.';
				return;
			}
			await loadProbeStatus();
			pollProbeStatus();
		} catch {
			probeError = 'Failed to start probe.';
		} finally {
			probeTriggering = false;
		}
	};

	const pollProbeStatus = () => {
		if (probePollTimer) clearTimeout(probePollTimer);
		probePollTimer = setTimeout(async () => {
			await loadProbeStatus();
			const active = probeStatus.job?.status === 'QUEUED' || probeStatus.job?.status === 'RUNNING' || probeStatus.job?.status === 'RETRY';
			if (active) pollProbeStatus();
		}, 3000);
	};

	const probeJobLabel = (status?: string) => {
		switch (status) {
			case 'QUEUED': return 'Queued';
			case 'RUNNING': return 'Running…';
			case 'RETRY': return 'Retrying';
			case 'SUCCEEDED': return 'Complete';
			case 'FAILED': return 'Failed';
			default: return 'Never triggered';
		}
	};

	const probeJobClass = (status?: string) => {
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
	const approvedUsers = $derived(users.filter(u => u.approved && !u.hidden));
	const adminCount = $derived(approvedUsers.filter(u => u.role === 'admin').length);
	const readerCount = $derived(approvedUsers.filter(u => u.role === 'global_reader').length);
	const defaultCount = $derived(approvedUsers.filter(u => u.role === 'default').length);
	const pendingUsers = $derived(users.filter(u => !u.approved && !u.hidden));
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
			loadTrivyStatus().then(() => {
				const active =
					trivyStatus.job_status === 'QUEUED' ||
					trivyStatus.job_status === 'RUNNING' ||
					trivyStatus.job_status === 'RETRY' ||
					!trivyStatus.scan_complete;
				if (active) pollTrivyStatus();
			});
			loadProbeStatus().then(() => {
				const active = probeStatus.job?.status === 'QUEUED' || probeStatus.job?.status === 'RUNNING' || probeStatus.job?.status === 'RETRY';
				if (active) pollProbeStatus();
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
				if (trivyPollTimer) clearTimeout(trivyPollTimer);
			};
		}
	});

</script>

<svelte:head>
	<title>Settings - Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex items-baseline gap-3">
			<div>
				<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Settings</h1>
				<p class="mt-1 text-sm text-[var(--text-tertiary)]">Manage providers, users, and scanner configuration.</p>
			</div>
		</header>

		<div class="grid grid-cols-2 gap-3 sm:grid-cols-5">
			<!-- Users with access + role breakdown as subtitles -->
			<div class="metric-card space-y-1 rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Users</h3>
				<p class="text-3xl font-bold text-[var(--text-bright)]">{usersLoading ? '—' : approvedUsers.length}</p>
				<p class="text-xs text-[var(--text-muted)]">
					{usersLoading ? '' : `${adminCount} admin · ${readerCount} reader · ${defaultCount} default`}
				</p>
			</div>
			<!-- Pending users -->
			<div class="metric-card space-y-1 rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Pending</h3>
				<p class="text-3xl font-bold {!usersLoading && pendingUsers.length > 0 ? 'text-amber-400' : 'text-[var(--text-bright)]'}">{usersLoading ? '—' : pendingUsers.length}</p>
				<p class="text-xs text-[var(--text-muted)]">awaiting approval</p>
			</div>
			<!-- Providers -->
			<div class="metric-card space-y-1 rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Providers</h3>
				<p class="text-3xl font-bold text-[var(--text-bright)]">{refreshing ? '—' : providers.length}</p>
				<p class="text-xs text-[var(--text-muted)]">configured sources</p>
			</div>
			<!-- OSV -->
			<div class="metric-card space-y-1 rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">OSV</h3>
				<p class="text-3xl font-bold text-[var(--text-bright)]">{osvStatus.result?.scanned ?? '—'}</p>
				<p class="text-xs text-[var(--text-muted)]">{osvStatus.result?.vulns_found != null ? `${osvStatus.result.vulns_found} vulns found` : 'components scanned'}</p>
			</div>
			<!-- Trivy -->
			<div class="metric-card space-y-1 rounded-2xl p-4">
				<h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Trivy</h3>
				<p class="text-3xl font-bold text-[var(--text-bright)]">{trivyStatus.scanned_count ?? '—'}</p>
				<p class="text-xs text-[var(--text-muted)]">{trivyStatus.pending_count != null ? `${trivyStatus.pending_count} pending` : 'SBOMs scanned'}</p>
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
				class={`btn ${showAddProvider ? 'btn-ghost' : 'btn-primary'} inline-flex items-center gap-2`}
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
						class="btn btn-primary w-full"
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
				class="btn btn-primary inline-flex items-center gap-2"
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

<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
	<header class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">Trivy Scanner</h2>
			<p class="text-sm text-[var(--text-tertiary)]">
				Runs as a scheduled K8s CronJob. Trigger an ad-hoc scan to pick up new SBOMs immediately.
			</p>
		</div>
		<div class="flex flex-wrap items-center gap-2">
			<button
				type="button"
				class="btn btn-primary inline-flex items-center gap-2"
				onclick={triggerTrivyScan}
				disabled={trivyTriggering || trivyStatus.job_status === 'QUEUED' || trivyStatus.job_status === 'RUNNING' || trivyStatus.job_status === 'RETRY'}
			>
				<Play size={14} />
				{trivyTriggering ? 'Starting…' : 'Run Trivy Scan'}
			</button>
		</div>
	</header>

	{#if trivyError}
		<div class="rounded-2xl border border-[var(--error)]/30 bg-[var(--error)]/5 p-4 text-sm text-[var(--error)]">
			{trivyError}
		</div>
	{/if}

	{#if trivyStatus.job_id}
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 space-y-3">
			<div class="flex items-center justify-between">
				<span class="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs {trivyJobStatusClass(trivyStatus.job_status)}">
					{trivyStatus.scan_complete ? 'Scan complete' : trivyJobStatusLabel(trivyStatus.job_status)}
				</span>
				<span class="text-xs text-[var(--text-muted)]">
					{trivyStatus.scanned_count ?? 0} / {(trivyStatus.scanned_count ?? 0) + (trivyStatus.pending_count ?? 0)} SBOMs scanned
				</span>
			</div>
			{#if (trivyStatus.pending_count ?? 0) > 0}
				{@const total = (trivyStatus.scanned_count ?? 0) + (trivyStatus.pending_count ?? 0)}
				{@const pct = total > 0 ? Math.round(((trivyStatus.scanned_count ?? 0) / total) * 100) : 0}
				<div class="h-1.5 w-full rounded-full bg-[var(--border-color)]/40">
					<div class="h-1.5 rounded-full bg-amber-400 transition-all duration-500" style="width: {pct}%"></div>
				</div>
			{/if}
			<div class="flex flex-wrap gap-x-6 gap-y-1 text-[11px] text-[var(--text-muted)]">
				{#if trivyStatus.created_at}
					<span class="flex items-center gap-1"><Clock size={10} /> Triggered {new Date(trivyStatus.created_at).toLocaleString()}</span>
				{/if}
				{#if trivyStatus.last_scanned_at}
					<span>Last scan {new Date(trivyStatus.last_scanned_at).toLocaleString()}</span>
				{/if}
			</div>
		</div>
	{/if}

	{#if trivyStatus.error}
		<div class="rounded-2xl border border-[var(--error)]/30 bg-[var(--error)]/5 p-4">
			<p class="text-xs font-semibold uppercase tracking-wider text-[var(--error)]">Job error</p>
			<p class="mt-1 text-sm text-[var(--text-secondary)]">{trivyStatus.error}</p>
		</div>
	{/if}

	{#if trivyStatus.recent_runs && trivyStatus.recent_runs.length > 0}
		<div class="space-y-1">
			<p class="text-xs font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">Recent runs</p>
			<div class="divide-y divide-[var(--border-color)]/40 rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
				{#each trivyStatus.recent_runs as run}
					<div class="flex items-center justify-between px-4 py-2.5 text-xs">
						<div class="flex items-center gap-3">
							<span class="text-[var(--text-secondary)]">{new Date(run.started_at).toLocaleDateString()}</span>
							<span class="text-[var(--text-muted)]">{new Date(run.started_at).toLocaleTimeString()} – {new Date(run.finished_at).toLocaleTimeString()}</span>
						</div>
						<div class="flex items-center gap-4">
							<span class="text-[var(--text-muted)]">{run.sbom_count} SBOMs</span>
							{#if run.critical_count > 0}
								<span class="text-red-400">{run.critical_count} critical</span>
							{/if}
							{#if run.high_count > 0}
								<span class="text-orange-400">{run.high_count} high</span>
							{/if}
						</div>
					</div>
				{/each}
			</div>
		</div>
	{/if}
</section>

<!-- Secret Probe -->
<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
	<header class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
		<div>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">Secret Probe</h2>
			<p class="text-sm text-[var(--text-tertiary)]">Validate discovered secrets to check if they are still live, expired, or revoked.</p>
		</div>
		<button
			type="button"
			class="inline-flex items-center gap-2 rounded-full border border-[var(--border-color)] px-4 py-2 text-sm font-semibold text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] disabled:opacity-50"
			onclick={() => { probePreviewOpen = true; loadProbePreview(); }}
			disabled={probeTriggering || probeStatus.job?.status === 'QUEUED' || probeStatus.job?.status === 'RUNNING' || probeStatus.job?.status === 'RETRY'}
		>
			<Eye size={14} />
			Preview Secret Probe
		</button>
	</header>

	{#if probeError}
		<div class="rounded-2xl border border-[var(--error)]/30 bg-[var(--error)]/5 p-4 text-sm text-[var(--error)]">
			{probeError}
		</div>
	{/if}

	{#if probeStatus.job?.error}
		<div class="rounded-2xl border border-[var(--error)]/30 bg-[var(--error)]/5 p-4">
			<p class="text-xs font-semibold uppercase tracking-wider text-[var(--error)]">Error</p>
			<p class="mt-1 text-sm text-[var(--text-secondary)]">{probeStatus.job.error}</p>
		</div>
	{/if}

	<!-- Stats cards -->
	<div class="grid gap-3 grid-cols-5">
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<ShieldCheck size={16} />
				<span>Status</span>
			</div>
			{#if probeStatus.job}
				<p class="mt-2 text-sm font-semibold">
					<span class="inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs {probeJobClass(probeStatus.job.status)}">
						{probeJobLabel(probeStatus.job.status)}
					</span>
				</p>
				{#if probeStatus.job.created_at}
					<p class="mt-1 flex items-center gap-1 text-[11px] text-[var(--text-muted)]">
						<Clock size={10} /> Started {new Date(probeStatus.job.created_at).toLocaleString()}
					</p>
				{/if}
				{#if probeStatus.job.finished_at}
					<p class="mt-0.5 text-[11px] text-[var(--text-muted)]">Finished {new Date(probeStatus.job.finished_at).toLocaleString()}</p>
				{/if}
			{:else}
				<p class="mt-2 text-sm text-[var(--text-muted)]">Never triggered</p>
			{/if}
		</div>
		<button
			type="button"
			class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-left transition hover:border-[var(--accent)]/40 {probeStatus.stats.total === 0 ? 'opacity-50 pointer-events-none' : 'cursor-pointer'}"
			onclick={() => openProbeList('Secrets probed', ['valid', 'invalid', 'revoked', 'expired', 'unknown', 'error', 'false_positive'])}
		>
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<KeyRound size={16} />
				<span>Secrets probed</span>
			</div>
			<p class="mt-2 text-2xl font-semibold text-[var(--text-bright)]">
				{#if probeStatus.job?.status === 'RUNNING' && probeStatus.job?.result?.probed != null}
					{probeStatus.job.result.probed} <span class="text-sm font-normal text-[var(--text-muted)]">/ {probeStatus.job.result.total}</span>
				{:else}
					{probeStatus.stats.total}
				{/if}
			</p>
			{#if probeStatus.job?.status === 'RUNNING' && probeStatus.job?.result?.total > 0}
				{@const pct = Math.round((probeStatus.job.result.probed / probeStatus.job.result.total) * 100)}
				<div class="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-[var(--border-color)]">
					<div class="h-full rounded-full bg-amber-400 transition-all duration-500" style="width: {pct}%"></div>
				</div>
				<p class="mt-1 text-[11px] text-[var(--text-muted)]">{pct}% probed</p>
			{/if}
		</button>
		<button
			type="button"
			class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-left transition hover:border-red-400/40 {probeStatus.stats.valid === 0 ? 'opacity-50 pointer-events-none' : 'cursor-pointer'}"
			onclick={() => openProbeList('Live secrets', ['valid'])}
		>
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<ShieldAlert size={16} />
				<span>Live secrets</span>
			</div>
			<p class="mt-2 text-2xl font-semibold text-red-400">{probeStatus.stats.valid}</p>
			{#if probeStatus.stats.valid > 0}
				<p class="mt-1 text-[11px] text-[var(--text-muted)]">Require immediate rotation</p>
			{/if}
		</button>
		<button
			type="button"
			class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-left transition hover:border-green-400/40 {(probeStatus.stats.revoked + probeStatus.stats.expired + probeStatus.stats.invalid) === 0 ? 'opacity-50 pointer-events-none' : 'cursor-pointer'}"
			onclick={() => openProbeList('Rotated / Safe', ['revoked', 'expired', 'invalid'])}
		>
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<ShieldCheck size={16} />
				<span>Rotated / Safe</span>
			</div>
			<p class="mt-2 text-2xl font-semibold text-green-400">{probeStatus.stats.revoked + probeStatus.stats.expired + probeStatus.stats.invalid}</p>
			{#if probeStatus.stats.unknown > 0}
				<p class="mt-1 text-[11px] text-[var(--text-muted)]">{probeStatus.stats.unknown} unknown</p>
			{/if}
		</button>
		<button
			type="button"
			class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-left transition hover:border-[var(--border-color)] {probeStatus.stats.false_positive === 0 ? 'opacity-50 pointer-events-none' : 'cursor-pointer'}"
			onclick={() => openProbeList('False positives', ['false_positive'])}
		>
			<div class="flex items-center gap-2 text-sm text-[var(--text-secondary)]">
				<span>False positives</span>
			</div>
			<p class="mt-2 text-2xl font-semibold text-[var(--text-muted)]">{probeStatus.stats.false_positive}</p>
			<p class="mt-1 text-[11px] text-[var(--text-muted)]">Placeholder or test values</p>
		</button>
	</div>

</section>

<!-- Secret Probe List Dialog -->
<Dialog bind:open={probeListOpen} showCloseButton={false} maxWidth="max-w-6xl">
	<div class="p-6 sm:p-8 space-y-5">
		<div class="flex items-start justify-between">
			<div>
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">{probeListTitle}</h2>
				<p class="mt-1 text-sm text-[var(--text-tertiary)]">{probeListItems.length} secret{probeListItems.length !== 1 ? 's' : ''}</p>
			</div>
			<div class="flex items-center gap-2">
				<button
					type="button"
					class="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-[var(--text-muted)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
					onclick={() => (probeListOpen = false)}
					aria-label="Close"
				>
					<X size={18} />
				</button>
			</div>
		</div>

		{#if probeListLoading}
			<Loading message="Loading secrets" variant="bar" size="sm" />
		{:else if probeListItems.length === 0}
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
						{#each probeListItems as probe}
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
														href="/app/providers/repo/{loc.repo_id}"
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
					onclick={exportProbeCSV}
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

<!-- Secret Probe Preview Dialog -->
<Dialog bind:open={probePreviewOpen} showCloseButton={false} maxWidth="max-w-6xl">
	<div class="flex min-h-[80vh] min-h-0 flex-1 flex-col p-6 sm:p-8 space-y-5">
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
				onclick={() => (probePreviewOpen = false)}
				aria-label="Close"
			>
				<X size={18} />
			</button>
		</div>

		{#if probePreviewLoading}
			<Loading message="Loading probe preview" variant="bar" size="sm" />
		{:else if probePreview.length === 0}
			<div class="flex flex-col items-center gap-3 py-10 text-center">
				<ShieldCheck class="h-12 w-12 text-[var(--accent)]" />
				<div>
					<p class="text-lg font-semibold text-[var(--text-bright)]">All clear</p>
					<p class="mt-1 text-sm text-[var(--text-muted)]">
						{#if probeForce}
							No secrets found to probe. Run a scan first to discover secrets.
						{:else}
							All discovered secrets have already been probed. Toggle <span class="font-medium text-[var(--text-secondary)]">Force re-probe all</span> to re-check them.
						{/if}
					</p>
				</div>
			</div>
		{:else}
			{@const totalSecrets = probePreview.reduce((s, g) => s + g.count, 0)}
			{@const dismissedCount = probePreview.reduce((s, g) => s + (g.items ?? []).filter((i: any) => probeExcludedHashes.has(i.secret_hash)).length, 0)}
			{@const filteredPreview = (() => {
				if (probePreviewTab === 'dismissed') {
					// Show only groups that have dismissed items, filtered to those items.
					return probePreview.map((g: any) => ({
						...g,
						items: (g.items ?? []).filter((i: any) => probeExcludedHashes.has(i.secret_hash)),
						count: (g.items ?? []).filter((i: any) => probeExcludedHashes.has(i.secret_hash)).length
					})).filter((g: any) => g.count > 0);
				}
				const kindFilter = probePreviewTab === 'all' ? null : probePreviewTab;
				return kindFilter ? probePreview.filter((g: any) => g.kind === kindFilter) : probePreview;
			})()}
			{@const selectedGroups = probeSelectedRules.length === 0 ? filteredPreview : filteredPreview.filter((g: any) => probeSelectedRules.includes(g.rule_id))}
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
					bind:value={probePreviewTab}
				/>
				<p class="text-center text-xs text-[var(--text-muted)]">
					{selectedCount.toLocaleString('en-US').replace(/,/g, ' ')} of {totalSecrets.toLocaleString('en-US').replace(/,/g, ' ')} selected · {selectedGroups.length} type{selectedGroups.length !== 1 ? 's' : ''}
				</p>
			</div>

			<!-- Grouped request table -->
			<div class="relative min-h-0 flex-1 overflow-hidden rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
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
							{@const isGroupSelected = probeSelectedRules.length === 0 || probeSelectedRules.includes(group.rule_id)}
							<!-- Group header row -->
							<tr class="bg-[var(--hover-bg-subtle)]/50">
								<td class="px-3 py-2 text-center">
									<Checkbox
										checked={isGroupSelected}
										onchange={() => {
											if (probeSelectedRules.length === 0) {
												probeSelectedRules = probePreview.map(g => g.rule_id).filter(r => r !== group.rule_id);
											} else if (probeSelectedRules.includes(group.rule_id)) {
												probeSelectedRules = probeSelectedRules.filter(r => r !== group.rule_id);
											} else {
												probeSelectedRules = [...probeSelectedRules, group.rule_id];
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
									{@const isItemChecked = !probeExcludedHashes.has(item.secret_hash)}
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
										<td class="px-3 py-1.5">
											<button
												type="button"
												class="p-1 text-[var(--text-muted)] transition hover:text-[var(--accent)]"
												title="Inspect secret"
												onclick={() => { inspectItem = { hash: item.secret_hash, secret: item.secret, ruleId: item.effective_rule_id || item.rule_id || '' }; }}
											>
												<Eye size={12} />
											</button>
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
						class="absolute inset-y-0 right-0 z-20 w-[480px] border-l border-[var(--border-color)] rounded-r-xl"
						in:fly={{ x: 480, duration: 240, easing: cubicOut, opacity: 1 }}
						out:fly={{ x: 480, duration: 200, easing: cubicIn, opacity: 1 }}
					>
						<SecretInspectDrawer
							secretHash={inspectItem.hash}
							secret={inspectItem.secret}
							ruleId={inspectItem.ruleId}
							dismissed={probeExcludedHashes.has(inspectItem.hash)}
							onDismiss={(hash) => toggleDismiss(hash)}
							onClose={() => { inspectItem = null; }}
						/>
					</div>
				{/if}
			</div>
		{/if}

		{#if probeError}
			<p class="text-sm text-[var(--error)]">{probeError}</p>
		{/if}

		<!-- Footer -->
		<div class="flex items-center justify-between pt-2">
			<Toggle bind:checked={probeForce} label="Force re-probe all" onchange={() => loadProbePreview()} />
			<div class="flex items-center gap-3">
				<button type="button" class="btn btn-ghost" onclick={() => (probePreviewOpen = false)}>
					Cancel
				</button>
				<button
					type="button"
					class="btn btn-primary inline-flex items-center gap-2"
					disabled={probeTriggering || probePreviewLoading}
					onclick={async () => {
						await triggerProbe();
						if (!probeError) probePreviewOpen = false;
					}}
				>
					<Play size={14} />
					{probeTriggering ? 'Starting…' : 'Start Probe'}
				</button>
			</div>
		</div>
	</div>
</Dialog>

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
