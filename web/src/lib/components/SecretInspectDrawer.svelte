<script lang="ts">
	import { X, Eye, GitBranch, FileText, Play, Copy, Check } from 'lucide-svelte';

	type Location = {
		repo_id: string;
		repo_name: string;
		repo_url: string;
		file: string;
		line: number;
		secret: string;
		sub_type: string;
	};

	type RequestPreview = {
		method: string;
		url: string;
		headers?: Record<string, string>;
		body?: string;
	};

	type InspectData = {
		secret_hash: string;
		secret: string;
		rule_id: string;
		provider_base_url: string;
		locations: Location[];
		requests: RequestPreview[] | null;
		classification: {
			effective_rule_id: string;
			original_rule_id: string;
			reclassified: boolean;
			probe_output: { status: string; reason: string; metadata?: Record<string, any> };
		} | null;
		probe: { status: string; reason: string; metadata: string; probed_at: string } | null;
	};

	type JWTInfo = {
		header: Record<string, unknown>;
		payload: Record<string, unknown>;
		expired: boolean | null;
		expiresAt: string | null;
		issuedAt: string | null;
	};

	let {
		secretHash,
		secret = '',
		ruleId = '',
		dismissed = false,
		onClose = () => {},
		onDismiss,
		onProbeRun
	}: {
		secretHash: string;
		secret?: string;
		ruleId?: string;
		dismissed?: boolean;
		onClose?: () => void;
		onDismiss?: (secretHash: string) => void;
		onProbeRun?: (result: { secretHash: string; status: string; reason: string; metadata?: string }) => void;
	} = $props();

	let data: InspectData | null = $state(null);
	let loading = $state(true);

	const tryDecodeJWT = (s: string): JWTInfo | null => {
		const jwtMatch = s.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
		if (!jwtMatch) return null;
		const parts = jwtMatch[0].split('.');
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
			header, payload,
			expired: exp != null ? exp * 1000 < Date.now() : null,
			expiresAt: exp != null ? new Date(exp * 1000).toISOString() : null,
			issuedAt: iat != null ? new Date(iat * 1000).toISOString() : null,
		};
	};

	const tryBase64 = (s: string): string | null => {
		if (s.startsWith('eyJ') || s.startsWith('-----') || s.startsWith('http') || s.length < 16) return null;
		try {
			const norm = s.replace(/-/g, '+').replace(/_/g, '/');
			const padded = norm + '=='.slice(0, (4 - (norm.length % 4)) % 4);
			const decoded = atob(padded);
			if (/[\x00-\x08\x0e-\x1f\x7f]/.test(decoded)) return null;
			const printable = [...decoded].filter(c => { const code = c.charCodeAt(0); return (code >= 32 && code <= 126) || code === 9 || code === 10 || code === 13; }).length;
			if (printable / decoded.length < 0.8) return null;
			try { return JSON.stringify(JSON.parse(decoded), null, 2); } catch { /* not json */ }
			return decoded;
		} catch { return null; }
	};

	let prevHash = '';
	$effect(() => {
		if (secretHash && secretHash !== prevHash) {
			prevHash = secretHash;
			load();
		}
	});

	const load = async () => {
		loading = true;
		data = null;
		try {
			const params = new URLSearchParams({ secret_hash: secretHash });
			if (ruleId) params.set('rule_id', ruleId);
			const res = await fetch(`/api/admin/secrets/probe/inspect?${params}`, { credentials: 'include' });
			if (res.ok) data = await res.json();
		} catch { /* ignore */ }
		finally { loading = false; }
	};

	let probing = $state(false);
	let probeResult: { status: string; reason: string; metadata: string } | null = $state(null);
	let copyPressed = $state(false);
	let copyConfirmed = $state(false);
	let copyResetTimer: ReturnType<typeof setTimeout> | null = null;

	const secretValue = $derived(data?.secret || secret);
	const jwt = $derived(secretValue ? tryDecodeJWT(secretValue) : null);
	const decoded = $derived(secretValue && !jwt ? tryBase64(secretValue) : null);
	const effectiveRule = $derived(
		data?.classification?.reclassified
			? data.classification.effective_rule_id
			: (ruleId || data?.rule_id || 'unknown')
	);
	const probeStatus = $derived(probeResult?.status || data?.classification?.probe_output?.status || data?.probe?.status);
	const probeReason = $derived(probeResult?.reason || data?.classification?.probe_output?.reason || data?.probe?.reason);
	const requests = $derived(data?.requests ?? []);
	const isNetwork = $derived(requests.length > 0);

	const runProbe = async () => {
		if (!data || !secretValue) return;
		probing = true;
		probeResult = null;
		try {
			const res = await fetch('/api/admin/secrets/probe/run', {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					secret_hash: secretHash,
					secret: secretValue,
					rule_id: data.rule_id || ruleId,
					provider_base_url: data.provider_base_url || ''
				})
			});
			if (res.ok) {
				probeResult = await res.json();
				if (probeResult) {
					onProbeRun?.({
						secretHash,
						status: probeResult.status,
						reason: probeResult.reason,
						metadata: probeResult.metadata
					});
				}
			}
		} catch { /* ignore */ }
		finally { probing = false; }
	};

	const copySecret = () => {
		if (!secretValue) return;
		navigator.clipboard.writeText(secretValue);
		copyConfirmed = true;
		if (copyResetTimer) clearTimeout(copyResetTimer);
		copyResetTimer = setTimeout(() => {
			copyConfirmed = false;
		}, 900);
	};
</script>

<div class="flex h-full flex-col overflow-hidden bg-[var(--bg-soft)] border-l border-[var(--border-color)]">
	<!-- Header -->
	<div class="shrink-0 px-6 pt-6 pb-4">
		<div class="flex items-start gap-3">
			<Eye class="mt-0.5 h-5 w-5 shrink-0 {dismissed ? 'text-[var(--text-muted)]' : 'text-[var(--accent)]'}" />
			<div class="min-w-0 flex-1">
				<h3 class="text-sm font-semibold {dismissed ? 'text-[var(--text-muted)]' : 'text-[var(--text-bright)]'}">Secret Inspector</h3>
				<div class="mt-1 flex items-center gap-2">
					<span class="rounded-full border border-[var(--border-color)] px-2 py-0.5 text-[10px] {dismissed ? 'text-[var(--text-muted)]' : 'text-[var(--text-secondary)]'}">{effectiveRule}</span>
					{#if probeStatus && probeStatus !== 'unknown'}
						<span class="rounded-full px-1.5 py-0.5 text-[10px] font-medium {probeStatus === 'valid' ? 'bg-red-500/10 text-red-400' : probeStatus === 'expired' ? 'bg-green-500/10 text-green-400' : probeStatus === 'invalid' || probeStatus === 'false_positive' ? 'bg-[var(--hover-bg)] text-[var(--text-muted)]' : 'bg-[var(--orange)]/10 text-[var(--orange)]'}">
							{probeStatus.toUpperCase()}
						</span>
					{/if}
					{#if onDismiss}
						<button
							type="button"
							class="ml-auto rounded-full px-2.5 py-0.5 text-[10px] font-medium transition {dismissed ? 'bg-[var(--hover-bg)] text-[var(--text-muted)] hover:text-[var(--text-secondary)]' : 'bg-[var(--accent)]/10 text-[var(--accent)] hover:bg-[var(--accent)]/20'}"
							onclick={() => onDismiss(secretHash)}
						>
							{dismissed ? 'Excluded' : 'Exclude'}
						</button>
					{/if}
				</div>
				{#if probeReason}
					<p class="mt-1 text-[10px] text-[var(--text-muted)]">{probeReason}</p>
				{/if}
			</div>
			<button
				type="button"
				class="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg transition hover:bg-[var(--hover-bg)]"
				onclick={onClose}
			>
				<X size={16} />
			</button>
		</div>
	</div>

	{#if loading}
		<div class="flex flex-1 items-center justify-center">
			<div class="h-5 w-5 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
		</div>
	{:else}
		<div class="flex-1 overflow-y-auto px-6 py-4 space-y-4">
			<!-- Secret value -->
			<div>
				<h4 class="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-tertiary)] mb-1">Secret</h4>
				<div class="relative rounded bg-[var(--card-bg)] px-3 py-2 font-mono text-xs text-[var(--text-muted)]">
					<button
						type="button"
						class="absolute right-2 top-[0.2rem] rounded p-1 text-[var(--text-muted)] transition-all duration-150 ease-out hover:bg-[var(--hover-bg)] hover:text-[var(--accent)] active:scale-95 {copyPressed ? 'translate-y-px scale-95 bg-[var(--hover-bg)] shadow-inner' : 'scale-100'}"
						title="Copy secret"
						aria-label="Copy secret"
						onmousedown={() => { copyPressed = true; }}
						onmouseup={() => { copyPressed = false; }}
						onmouseleave={() => { copyPressed = false; }}
						onblur={() => { copyPressed = false; }}
						onclick={copySecret}
					>
						<span class="relative block h-3 w-3">
							<span class="absolute inset-0 transition-all duration-200 ease-out {copyConfirmed ? 'scale-75 opacity-0' : 'scale-100 opacity-100'}">
								<Copy size={12} />
							</span>
							<span class="absolute inset-0 transition-all duration-200 ease-out {copyConfirmed ? 'scale-100 opacity-100' : 'scale-75 opacity-0'}">
								<Check size={12} />
							</span>
						</span>
					</button>
					<pre class="max-w-full overflow-x-auto whitespace-pre-wrap break-all pe-8 select-all cursor-text">{secretValue}</pre>
				</div>
			</div>

			<!-- JWT decode -->
			{#if jwt}
				<div>
					<h4 class="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-tertiary)] mb-1">JWT</h4>
					<div class="rounded border border-[var(--border-color)]/40 bg-[var(--card-bg)] px-3 py-2 text-xs space-y-1.5">
						<div class="flex items-center gap-2">
							<span class="font-semibold text-[var(--text-secondary)]">JWT</span>
							{#if jwt.expired === true}
								<span class="rounded-full bg-green-500/10 px-1.5 py-0.5 text-[10px] font-medium text-green-400">EXPIRED</span>
							{:else if jwt.expired === false}
								<span class="rounded-full bg-red-500/10 px-1.5 py-0.5 text-[10px] font-medium text-red-400">ACTIVE</span>
							{/if}
							{#if jwt.header.alg}
								<span class="text-[10px] text-[var(--text-muted)]">{jwt.header.alg}</span>
							{/if}
						</div>
						<div class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-[11px]">
							{#if jwt.payload.iss}
								<span class="text-[var(--text-muted)]">iss</span>
								<span class="text-[var(--text-secondary)] break-all">{jwt.payload.iss}</span>
							{/if}
							{#if jwt.payload.sub}
								<span class="text-[var(--text-muted)]">sub</span>
								<span class="text-[var(--text-secondary)] break-all">{jwt.payload.sub}</span>
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
				</div>
			{/if}

			<!-- Base64 decode -->
			{#if decoded}
				<div>
					<h4 class="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-tertiary)] mb-1">Base64 Decoded</h4>
					<pre class="rounded bg-[var(--card-bg)] px-3 py-2 font-mono text-xs text-[var(--text-muted)] whitespace-pre-wrap break-all">{decoded}</pre>
				</div>
			{/if}

			<!-- HTTP Request Preview -->
			{#if isNetwork}
				<div>
					<div class="flex items-center justify-between mb-1">
						<h4 class="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-tertiary)]">HTTP Request</h4>
						<button
							type="button"
							class="inline-flex items-center gap-1 rounded-full border border-[var(--accent)]/40 bg-[var(--accent)]/10 px-2.5 py-1 text-[10px] font-medium text-[var(--accent)] transition hover:bg-[var(--accent)]/20 disabled:opacity-40"
							disabled={probing}
							onclick={runProbe}
						>
							{#if probing}
								<div class="h-3 w-3 animate-spin rounded-full border border-[var(--accent)] border-t-transparent"></div>
								Probing…
							{:else}
								<Play class="h-3 w-3" />
								Run
							{/if}
						</button>
					</div>
					{#each requests as req}
						<div class="rounded border border-[var(--border-color)]/40 bg-[var(--card-bg)] px-3 py-2 font-mono text-[11px] space-y-1">
							<div>
								<span class="rounded bg-[var(--hover-bg)] px-1.5 py-0.5 text-[10px] font-semibold text-[var(--text-secondary)]">{req.method}</span>
								<span class="ml-1.5 text-[var(--text-secondary)] break-all">{req.url}</span>
							</div>
							{#if req.headers}
								{#each Object.entries(req.headers) as [k, v]}
									<div class="text-[var(--text-muted)]">
										<span class="text-[var(--text-tertiary)]">{k}:</span> <span class="break-all">{v}</span>
									</div>
								{/each}
							{/if}
							{#if req.body}
								<div class="text-[var(--text-muted)] pt-1 border-t border-[var(--border-color)]/20">
									<pre class="whitespace-pre-wrap break-all">{req.body}</pre>
								</div>
							{/if}
						</div>
					{/each}
					{#if probeResult}
						<div class="mt-2 rounded border border-[var(--border-color)]/40 bg-[var(--card-bg)] px-3 py-2 text-xs">
							<span class="font-semibold {probeResult.status === 'valid' ? 'text-red-400' : probeResult.status === 'revoked' || probeResult.status === 'expired' ? 'text-green-400' : 'text-[var(--text-secondary)]'}">
								{probeResult.status.toUpperCase()}
							</span>
							{#if probeResult.reason}
								<span class="ml-2 text-[var(--text-muted)]">{probeResult.reason}</span>
							{/if}
						</div>
					{/if}
				</div>
			{/if}

			<!-- Locations -->
			{#if data?.locations && data.locations.length > 0}
				<div>
					<h4 class="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-tertiary)] mb-1">
						Found in {data.locations.length} location{data.locations.length !== 1 ? 's' : ''}
					</h4>
					<div class="space-y-1">
						{#each data.locations as loc}
							<a
								href="/app/providers/repo/{loc.repo_id}"
								target="_blank"
								rel="noopener"
								class="flex items-start gap-2 rounded-lg px-3 py-2 text-xs transition hover:bg-[var(--hover-bg-subtle)]"
							>
								<GitBranch class="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--accent)]" />
								<div class="min-w-0">
									<span class="font-semibold text-[var(--text-bright)]">{loc.repo_name}</span>
									{#if loc.file}
										<div class="flex items-center gap-1 text-[var(--text-muted)]">
											<FileText class="h-3 w-3 shrink-0" />
											<span class="truncate">{loc.file}{loc.line ? `:${loc.line}` : ''}</span>
										</div>
									{/if}
									{#if loc.sub_type}
										<span class="text-[10px] text-[var(--text-muted)]">{loc.sub_type}</span>
									{/if}
								</div>
							</a>
						{/each}
					</div>
				</div>
			{/if}

			<!-- Hash -->
			<div>
				<h4 class="text-[10px] font-semibold uppercase tracking-wider text-[var(--text-tertiary)] mb-1">Hash</h4>
				<p class="font-mono text-[10px] text-[var(--text-muted)] break-all select-all">{secretHash}</p>
			</div>
		</div>
	{/if}
</div>
