<script lang="ts">
	import { Check, Copy } from 'lucide-svelte';
	import Dialog from '$lib/components/Dialog.svelte';

	let { open = $bindable(false) }: { open?: boolean } = $props();

	type TabValue = 'helm' | 'argocd';
	let activeTab = $state<TabValue>('helm');

	const helmCommand = `helm install scam oci://ghcr.io/norskhelsenett/scam/helm \\
  --namespace nhn-scam \\
  --create-namespace`;

	const argocdManifest = `apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: scam
  namespace: argocd
spec:
  destination:
    namespace: nhn-scam
    server: https://kubernetes.default.svc
  project: default
  source:
    chart: helm
    repoURL: ghcr.io/norskhelsenett/scam
    targetRevision: '*'
  syncPolicy:
    automated:
      enabled: true
      prune: true
      selfHeal: true
    syncOptions:
    - CreateNamespace=true`;

	let copied = $state(false);
	let copyTimer: ReturnType<typeof setTimeout> | null = null;

	const copyActive = async () => {
		const text = activeTab === 'helm' ? helmCommand : argocdManifest;
		try {
			await navigator.clipboard.writeText(text);
			copied = true;
			if (copyTimer) clearTimeout(copyTimer);
			copyTimer = setTimeout(() => { copied = false; }, 1600);
		} catch {
			/* ignore */
		}
	};
</script>

<Dialog bind:open maxWidth="max-w-3xl">
	<div class="flex w-full flex-col gap-5 p-6 sm:p-8">
		<header class="space-y-1">
			<h2 class="text-lg font-semibold text-[var(--text-bright)]">Deploy a SCAM agent</h2>
			<p class="text-sm text-[var(--text-tertiary)]">
				Pick your install method. Both deploy the agent into the <code class="rounded bg-[var(--card-bg)] px-1.5 py-0.5 text-xs">nhn-scam</code> namespace.
			</p>
		</header>

		<div class="tab-row">
			<button
				type="button"
				class="tab"
				class:is-active={activeTab === 'helm'}
				onclick={() => (activeTab = 'helm')}
			>
				Helm
			</button>
			<button
				type="button"
				class="tab"
				class:is-active={activeTab === 'argocd'}
				onclick={() => (activeTab = 'argocd')}
			>
				ArgoCD
			</button>
		</div>

		<div class="code-block">
			<button type="button" class="copy-btn" onclick={copyActive} aria-label="Copy">
				{#if copied}
					<Check class="h-3.5 w-3.5" />
					<span>Copied</span>
				{:else}
					<Copy class="h-3.5 w-3.5" />
					<span>Copy</span>
				{/if}
			</button>
			<pre><code>{activeTab === 'helm' ? helmCommand : argocdManifest}</code></pre>
		</div>

		{#if activeTab === 'argocd'}
			<p class="text-xs text-[var(--text-muted)]">
				Apply with <code class="rounded bg-[var(--card-bg)] px-1.5 py-0.5">kubectl apply -f</code>, or commit to the repo your ArgoCD ApplicationSet watches.
			</p>
		{:else}
			<p class="text-xs text-[var(--text-muted)]">
				Requires Helm 3.8+ for OCI registry support.
			</p>
		{/if}
	</div>
</Dialog>

<style>
	.tab-row {
		display: inline-flex;
		gap: 4px;
		padding: 4px;
		border: 1px solid var(--border-color);
		border-radius: 999px;
		background: color-mix(in srgb, var(--card-bg) 60%, transparent);
		align-self: flex-start;
	}

	.tab {
		padding: 6px 18px;
		border-radius: 999px;
		border: none;
		background: transparent;
		color: var(--text-secondary);
		font-size: 11px;
		letter-spacing: 0.18em;
		text-transform: uppercase;
		cursor: pointer;
		transition: background 160ms ease, color 160ms ease;
	}

	.tab:hover {
		color: var(--text-bright);
	}

	.tab.is-active {
		background: var(--accent);
		color: var(--main-content-bg);
	}

	.code-block {
		position: relative;
		border: 1px solid var(--border-color);
		border-radius: 12px;
		background: color-mix(in srgb, var(--card-bg) 70%, transparent);
		overflow: hidden;
	}

	.code-block pre {
		margin: 0;
		padding: 16px 18px;
		padding-right: 96px;
		overflow-x: auto;
		font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
		font-size: 12.5px;
		line-height: 1.55;
		color: var(--text-secondary);
		white-space: pre;
	}

	.copy-btn {
		position: absolute;
		top: 10px;
		right: 10px;
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 5px 10px;
		border: 1px solid var(--border-color);
		border-radius: 8px;
		background: var(--card-bg);
		color: var(--text-secondary);
		font-size: 11px;
		cursor: pointer;
		transition: color 160ms ease, border-color 160ms ease, background 160ms ease;
	}

	.copy-btn:hover {
		color: var(--text-bright);
		border-color: color-mix(in srgb, var(--accent) 40%, var(--border-color));
	}
</style>
