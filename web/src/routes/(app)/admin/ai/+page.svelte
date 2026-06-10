<script lang="ts">
	import { browser } from '$app/environment';
	import { Sparkles, Play, Save } from 'lucide-svelte';
	import Loading from '$lib/components/Loading.svelte';
	import Toggle from '$lib/components/Toggle.svelte';
	import Select from '$lib/components/Select.svelte';

	type Settings = {
		use_case: string;
		enabled: boolean;
		base_url: string;
		// api_key is write-only: blank keeps the stored key, a value
		// replaces it; the server returns only the fingerprint.
		api_key?: string;
		api_key_fingerprint?: string;
		clear_api_key?: boolean;
		model: string;
		system_prompt: string;
		temperature: number;
		top_k: number;
		top_p: number;
		max_tokens: number;
		updated_at: string;
		updated_by: string;
	};

	type TestResult = {
		output?: string;
		error?: string;
		latency_ms: number;
		payload: unknown;
		verdict?: { verdict: string; justification: string; confidence: number; missing_data?: string[] };
		verdict_parse_error?: string;
	};

	const useCaseMeta: Record<string, { title: string; blurb: string }> = {
		advisory_summary: {
			title: 'Advisory summary',
			blurb: 'Narrative shown at the top of an expanded triage card. Regenerated when the asset’s tier-relevant signals change.'
		},
		triage_verdict: {
			title: 'Triage verdict (shadow mode)',
			blurb: 'Agent decision keep/suppress with justification + confidence. Recorded and displayed for evaluation only — it never closes or hides anything.'
		}
	};

	let settings = $state<Settings[]>([]);
	let loading = $state(true);
	let error = $state('');
	let saving = $state<Record<string, boolean>>({});
	let savedAt = $state<Record<string, number>>({});

	// Model dropdown: fetched from the endpoint per use case; falls
	// back to (or can be switched to) a free-text input when the list
	// fetch fails or the model isn't listed.
	let modelsByUseCase = $state<Record<string, string[]>>({});
	let modelManual = $state<Record<string, boolean>>({});

	const loadModels = async (s: Settings) => {
		try {
			const params = new URLSearchParams({ use_case: s.use_case, base_url: s.base_url });
			const res = await fetch(`/api/admin/ai/models?${params}`, { credentials: 'include' });
			if (!res.ok) throw new Error(`HTTP ${res.status}`);
			const data = (await res.json()) as { models: string[]; error?: string };
			modelsByUseCase = { ...modelsByUseCase, [s.use_case]: data.models ?? [] };
			if (!data.models?.length) modelManual = { ...modelManual, [s.use_case]: true };
		} catch {
			modelsByUseCase = { ...modelsByUseCase, [s.use_case]: [] };
			modelManual = { ...modelManual, [s.use_case]: true };
		}
	};

	const modelOptions = (s: Settings) => {
		const models = modelsByUseCase[s.use_case] ?? [];
		// Keep an unlisted saved model selectable instead of clobbering it.
		const opts = models.map((m) => ({ value: m, label: m }));
		if (s.model && !models.includes(s.model)) {
			opts.unshift({ value: s.model, label: `${s.model} (saved)` });
		}
		return opts;
	};

	// Backfill state — enqueue ADVISORY_BACKFILL and poll its progress.
	type BackfillStatus = {
		status: string;
		error?: string;
		result?: { status?: string; done?: number; total?: number; generated?: number };
	};
	let backfill = $state<BackfillStatus | null>(null);
	let backfillBusy = $state(false);
	let backfillTimer: ReturnType<typeof setTimeout> | null = null;

	const pollBackfill = async () => {
		try {
			const res = await fetch('/api/admin/ai/backfill/status', { credentials: 'include' });
			if (res.ok) backfill = (await res.json()) as BackfillStatus;
		} catch {
			/* ignore poll errors */
		}
		if (backfill && (backfill.status === 'QUEUED' || backfill.status === 'RUNNING' || backfill.status === 'RETRY')) {
			backfillTimer = setTimeout(pollBackfill, 3000);
		}
	};
	if (browser) void pollBackfill();

	const startBackfill = async () => {
		if (backfillBusy) return;
		backfillBusy = true;
		try {
			const res = await fetch('/api/admin/ai/backfill', { method: 'POST', credentials: 'include' });
			if (res.status === 409) {
				error = 'A backfill is already queued or running.';
			} else if (!res.ok) {
				throw new Error(`HTTP ${res.status}`);
			}
			if (backfillTimer) clearTimeout(backfillTimer);
			void pollBackfill();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to start backfill';
		} finally {
			backfillBusy = false;
		}
	};

	// Test bench state
	let testUseCase = $state('advisory_summary');
	let testAssetType = $state('image');
	let testAssetId = $state('');
	let testRunning = $state(false);
	let testResult = $state<TestResult | null>(null);
	let payloadOpen = $state(false);

	const load = async () => {
		try {
			const res = await fetch('/api/admin/ai/settings', { credentials: 'include' });
			if (!res.ok) throw new Error(`HTTP ${res.status}`);
			settings = ((await res.json()).settings ?? []) as Settings[];
			for (const s of settings) void loadModels(s);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load settings';
		} finally {
			loading = false;
		}
	};
	if (browser) void load();

	const save = async (s: Settings) => {
		saving = { ...saving, [s.use_case]: true };
		try {
			const res = await fetch(`/api/admin/ai/settings/${encodeURIComponent(s.use_case)}`, {
				method: 'PUT',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify(s)
			});
			if (!res.ok) throw new Error(`HTTP ${res.status}`);
			const updated = (await res.json()) as Settings;
			updated.api_key = '';
			settings = settings.map((x) => (x.use_case === updated.use_case ? updated : x));
			savedAt = { ...savedAt, [s.use_case]: Date.now() };
			setTimeout(() => {
				savedAt = { ...savedAt, [s.use_case]: 0 };
			}, 2500);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to save';
		} finally {
			saving = { ...saving, [s.use_case]: false };
		}
	};

	// The bench runs the CURRENT FORM VALUES (saved or not) so a prompt
	// draft can be tried against a real finding before committing it.
	const runTest = async () => {
		const cfg = settings.find((s) => s.use_case === testUseCase);
		if (!cfg || !testAssetId.trim() || testRunning) return;
		testRunning = true;
		testResult = null;
		try {
			const res = await fetch('/api/admin/ai/test', {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					use_case: testUseCase,
					asset_type: testAssetType,
					asset_id: testAssetId.trim(),
					settings: cfg
				})
			});
			if (!res.ok) throw new Error(`${res.status === 404 ? 'asset not found in asset_risk' : `HTTP ${res.status}`}`);
			testResult = (await res.json()) as TestResult;
		} catch (e) {
			testResult = { error: e instanceof Error ? e.message : 'Test failed', latency_ms: 0, payload: null };
		} finally {
			testRunning = false;
		}
	};
</script>

<svelte:head>
	<title>AI Settings • Spam Monitor</title>
</svelte:head>

<div class="space-y-4">
	<article class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex items-center gap-3">
			<Sparkles class="h-10 w-10 flex-shrink-0 text-[var(--accent)]" />
			<div>
				<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">AI advisories</h1>
				<p class="text-sm text-[var(--text-tertiary)]">
					Prompt, model, and sampling per use case. Generation runs in the background against an OpenAI-compatible endpoint; nothing is sent until a use case is enabled.
				</p>
			</div>
		</header>

		{#if loading}
			<div class="flex items-center justify-center py-16">
				<Loading message="Loading settings" size="lg" variant="spinner" />
			</div>
		{:else if error}
			<div class="rounded-2xl bg-[var(--error)]/10 px-4 py-3 text-sm text-[var(--error)]">{error}</div>
		{:else}
			<div class="grid gap-6 xl:grid-cols-2">
				{#each settings as s (s.use_case)}
					{@const meta = useCaseMeta[s.use_case] ?? { title: s.use_case, blurb: '' }}
					<section class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-5 space-y-4">
						<header class="flex items-start justify-between gap-3">
							<div>
								<h2 class="text-base font-semibold text-[var(--text-bright)]">{meta.title}</h2>
								<p class="mt-0.5 text-xs leading-relaxed text-[var(--text-tertiary)]">{meta.blurb}</p>
							</div>
							<Toggle bind:checked={s.enabled} label={s.enabled ? 'Enabled' : 'Disabled'} />
						</header>

						<div class="grid gap-3 sm:grid-cols-2">
							<div>
								<label class="mb-1 block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]" for="{s.use_case}-model">Model</label>
								{#if !modelManual[s.use_case] && (modelsByUseCase[s.use_case]?.length ?? 0) > 0}
									<Select options={modelOptions(s)} bind:value={s.model} class="w-full" />
								{:else}
									<input id="{s.use_case}-model" type="text" class="input" bind:value={s.model} placeholder="nhn-medium" />
								{/if}
								<button
									type="button"
									class="mt-1 text-xs text-[var(--text-muted)] underline decoration-dotted"
									onclick={() => {
										const manual = !modelManual[s.use_case];
										modelManual = { ...modelManual, [s.use_case]: manual };
										if (!manual) void loadModels(s);
									}}
								>
									{modelManual[s.use_case] || !(modelsByUseCase[s.use_case]?.length ?? 0) ? 'Fetch model list from endpoint' : 'Enter model manually'}
								</button>
							</div>
							<div>
								<label class="mb-1 block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]" for="{s.use_case}-url">Endpoint URL</label>
								<input id="{s.use_case}-url" type="text" class="input" bind:value={s.base_url} placeholder="http://…/api/chat/completions" />
							</div>
						</div>

						<div>
							<label class="mb-1 block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]" for="{s.use_case}-key">API key</label>
							<div class="flex items-center gap-2">
								<input
									id="{s.use_case}-key"
									type="password"
									class="input flex-1"
									bind:value={s.api_key}
									autocomplete="off"
									placeholder={s.api_key_fingerprint ? `saved ${s.api_key_fingerprint} — enter a value to replace` : 'none — leave blank if the endpoint needs no auth'}
								/>
								{#if s.api_key_fingerprint}
									<button
										type="button"
										class="btn btn-ghost px-3 py-1.5 text-xs"
										onclick={() => { s.clear_api_key = true; s.api_key = ''; void save(s); s.clear_api_key = false; }}
									>
										Clear key
									</button>
								{/if}
							</div>
							<p class="mt-1 text-xs text-[var(--text-muted)]">Encrypted at rest with the provider secrets key (same as git PATs); only the fingerprint is ever sent back.</p>
						</div>

						<div class="grid gap-3 sm:grid-cols-4">
							<div>
								<label class="mb-1 block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]" for="{s.use_case}-temp">Temp</label>
								<input id="{s.use_case}-temp" type="number" step="0.1" min="0" max="2" class="input" bind:value={s.temperature} />
							</div>
							<div>
								<label class="mb-1 block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]" for="{s.use_case}-topk">Top K</label>
								<input id="{s.use_case}-topk" type="number" step="1" min="0" class="input" bind:value={s.top_k} />
							</div>
							<div>
								<label class="mb-1 block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]" for="{s.use_case}-topp">Top P</label>
								<input id="{s.use_case}-topp" type="number" step="0.05" min="0" max="1" class="input" bind:value={s.top_p} />
							</div>
							<div>
								<label class="mb-1 block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]" for="{s.use_case}-max">Max tokens</label>
								<input id="{s.use_case}-max" type="number" step="100" min="0" class="input" bind:value={s.max_tokens} />
							</div>
						</div>
						<p class="text-xs text-[var(--text-muted)]">
							Max tokens 0 = let the endpoint decide (recommended — the models carry ~256k context). If you do set a cap, remember hidden reasoning tokens count toward it; small caps truncate replies.
						</p>

						<div>
							<label class="mb-1 block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]" for="{s.use_case}-prompt">System prompt</label>
							<textarea id="{s.use_case}-prompt" rows="7" class="input font-mono text-xs leading-relaxed" bind:value={s.system_prompt}></textarea>
						</div>

						<div class="flex items-center justify-between gap-3">
							<p class="text-xs text-[var(--text-muted)]">
								{#if s.updated_by}Last saved by {s.updated_by}{/if}
							</p>
							<div class="flex items-center gap-3">
								{#if savedAt[s.use_case]}
									<span class="text-xs text-[var(--success)]">Saved</span>
								{/if}
								<button type="button" class="btn btn-primary" onclick={() => save(s)} disabled={saving[s.use_case]}>
									<Save class="h-4 w-4" />
									{saving[s.use_case] ? 'Saving…' : 'Save'}
								</button>
							</div>
						</div>
					</section>
				{/each}
			</div>
		{/if}

		{#if !loading}
			<div class="flex flex-wrap items-center gap-3 rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<div class="min-w-0 flex-1">
					<p class="text-sm font-semibold text-[var(--text-bright)]">Backfill fix-now advisories</p>
					<p class="text-xs leading-relaxed text-[var(--text-tertiary)]">
						Generate for every fix-now asset whose advisory is missing or stale, in one job — skips the background worker's {'20'}-per-cycle ramp. Requires at least one enabled use case.
					</p>
				</div>
				<div class="flex items-center gap-3">
					{#if backfill && backfill.status !== 'never_run'}
						<span class="text-xs text-[var(--text-muted)]">
							{#if backfill.status === 'RUNNING' && backfill.result?.done !== undefined}
								generating {backfill.result.done}/{backfill.result.total}…
							{:else if backfill.status === 'SUCCEEDED' && backfill.result}
								last run: {backfill.result.generated}/{backfill.result.total} generated
							{:else if backfill.status === 'FAILED'}
								<span class="text-[var(--error)]">failed: {backfill.error}</span>
							{:else}
								{backfill.status.toLowerCase()}
							{/if}
						</span>
					{/if}
					<button
						type="button"
						class="btn btn-secondary"
						onclick={startBackfill}
						disabled={backfillBusy || backfill?.status === 'QUEUED' || backfill?.status === 'RUNNING'}
					>
						<Play class="h-4 w-4" />
						Backfill now
					</button>
				</div>
			</div>
		{/if}
	</article>

	{#if !loading && !error}
		<article class="panel-surface space-y-5 px-6 py-8 sm:px-10 sm:py-10">
			<header>
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">Test bench</h2>
				<p class="text-sm text-[var(--text-tertiary)]">
					Run the current form values (saved or not) against a real finding. Nothing is persisted — tune the prompt here, then save above.
				</p>
			</header>

			<div class="flex flex-wrap items-end gap-3">
				<div>
					<span class="mb-1 block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Use case</span>
					<Select
						options={settings.map((s) => ({ value: s.use_case, label: useCaseMeta[s.use_case]?.title ?? s.use_case }))}
						bind:value={testUseCase}
					/>
				</div>
				<div>
					<span class="mb-1 block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Asset type</span>
					<Select options={[{ value: 'image', label: 'Image' }, { value: 'repo', label: 'Repo' }]} bind:value={testAssetType} />
				</div>
				<div class="min-w-[280px] flex-1">
					<label class="mb-1 block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]" for="test-asset-id">Asset ID</label>
					<input id="test-asset-id" type="text" class="input" bind:value={testAssetId} placeholder="asset_id from a triage row (image_digests.id / repos.id)" />
				</div>
				<button type="button" class="btn btn-primary" onclick={runTest} disabled={testRunning || !testAssetId.trim()}>
					<Play class="h-4 w-4" />
					{testRunning ? 'Running…' : 'Run test'}
				</button>
			</div>

			{#if testRunning}
				<Loading message="Asking the model" variant="bar" size="sm" />
			{:else if testResult}
				{#if testResult.error}
					<div class="rounded-2xl bg-[var(--error)]/10 px-4 py-3 text-sm text-[var(--error)]">{testResult.error}</div>
				{:else}
					<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-5 space-y-3">
						<div class="flex items-center justify-between">
							<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Output</p>
							<span class="text-xs text-[var(--text-muted)]">{(testResult.latency_ms / 1000).toFixed(1)}s</span>
						</div>
						<p class="whitespace-pre-line text-sm leading-relaxed text-[var(--text-secondary)]">{testResult.output}</p>
						{#if testResult.verdict}
							<div class="flex flex-wrap items-center gap-2 pt-1">
								<span class="pill {testResult.verdict.verdict === 'suppress' ? 'pill-warning' : 'pill-neutral'}">{testResult.verdict.verdict}</span>
								<span class="pill pill-neutral">{Math.round(testResult.verdict.confidence * 100)}% confident</span>
								<span class="text-xs text-[var(--text-tertiary)]">{testResult.verdict.justification}</span>
							</div>
						{/if}
						{#if testResult.verdict_parse_error}
							<p class="text-xs text-[var(--warning)]">Verdict JSON did not parse: {testResult.verdict_parse_error}</p>
						{/if}
						<button type="button" class="text-xs text-[var(--text-muted)] underline decoration-dotted" onclick={() => (payloadOpen = !payloadOpen)}>
							{payloadOpen ? 'Hide' : 'Show'} the exact payload the model saw
						</button>
						{#if payloadOpen}
							<pre class="overflow-x-auto rounded-xl bg-[var(--hover-bg-subtle)] p-3 text-[11px] leading-relaxed text-[var(--text-secondary)]">{JSON.stringify(testResult.payload, null, 2)}</pre>
						{/if}
					</div>
				{/if}
			{/if}
		</article>
	{/if}
</div>
