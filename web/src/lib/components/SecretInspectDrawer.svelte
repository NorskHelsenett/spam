<script lang="ts">
	import { X, Eye, GitBranch, FileText } from 'lucide-svelte';

	type Location = {
		repo_id: string;
		repo_name: string;
		repo_url: string;
		file: string;
		line: number;
		secret: string;
		sub_type: string;
	};

	type InspectData = {
		secret_hash: string;
		secret: string;
		rule_id: string;
		locations: Location[];
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
		onClose = () => {}
	}: {
		secretHash: string;
		secret?: string;
		ruleId?: string;
		onClose?: () => void;
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
			const res = await fetch(`/api/admin/secrets/probe/inspect?secret_hash=${encodeURIComponent(secretHash)}`, { credentials: 'include' });
			if (res.ok) data = await res.json();
		} catch { /* ignore */ }
		finally { loading = false; }
	};

	const secretValue = $derived(data?.secret || secret);
	const jwt = $derived(secretValue ? tryDecodeJWT(secretValue) : null);
	const decoded = $derived(secretValue && !jwt ? tryBase64(secretValue) : null);
	const effectiveRule = $derived(data?.classification?.reclassified ? data.classification.effective_rule_id : (data?.rule_id || ruleId));
	const probeStatus = $derived(data?.classification?.probe_output?.status || data?.probe?.status);
	const probeReason = $derived(data?.classification?.probe_output?.reason || data?.probe?.reason);
</script>

<div class="flex h-full flex-col overflow-hidden bg-[var(--bg-soft)] border-l border-[var(--border-color)]">
	<!-- Header -->
	<div class="shrink-0 px-6 pt-6 pb-4 border-b border-[var(--border-color)]/40">
		<div class="flex items-start gap-3">
			<Eye class="mt-0.5 h-5 w-5 shrink-0 text-[var(--accent)]" />
			<div class="min-w-0 flex-1">
				<h3 class="text-sm font-semibold text-[var(--text-bright)]">Secret Inspector</h3>
				<div class="mt-1 flex items-center gap-2">
					<span class="rounded-full border border-[var(--border-color)] px-2 py-0.5 text-[10px] text-[var(--text-secondary)]">{effectiveRule}</span>
					{#if probeStatus && probeStatus !== 'unknown'}
						<span class="rounded-full px-1.5 py-0.5 text-[10px] font-medium {probeStatus === 'valid' ? 'bg-red-500/10 text-red-400' : probeStatus === 'expired' ? 'bg-green-500/10 text-green-400' : probeStatus === 'invalid' || probeStatus === 'false_positive' ? 'bg-[var(--hover-bg)] text-[var(--text-muted)]' : 'bg-[var(--orange)]/10 text-[var(--orange)]'}">
							{probeStatus.toUpperCase()}
						</span>
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
				<div class="rounded bg-[var(--card-bg)] px-3 py-2 font-mono text-xs text-[var(--text-muted)] break-all select-all cursor-text">{secretValue}</div>
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
