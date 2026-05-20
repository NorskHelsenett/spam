<script lang="ts" context="module">
	export type VulnerabilityDialogItem = {
		vuln_id: string;
		severity: string;
		pkg_name: string;
		installed_version: string;
		fixed_version: string;
		title: string;
		description: string;
		sources: string[];
		assets?: Array<{ type: 'repo' | 'image'; id: string; slug: string }>;
		repo_count?: number;
		image_count?: number;
	};
</script>

<script lang="ts">
	import { Shield, ShieldAlert, ShieldX, X } from 'lucide-svelte';
	import Markdown from '$lib/components/Markdown.svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';

	let {
		open = $bindable(false),
		loading = false,
		data = []
	}: {
		open: boolean;
		loading: boolean;
		data: VulnerabilityDialogItem[];
	} = $props();

	let tab = $state('all');

	const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

	const filtered = $derived(
		tab === 'all'
			? data
			: data.filter((v) => v.severity?.toUpperCase() === tab)
	);

	const severityClass = (severity: string) => {
		switch (severity?.toUpperCase()) {
			case 'CRITICAL': return 'text-red-400 border-red-500/40 bg-red-500/10';
			case 'HIGH':     return 'text-orange-400 border-orange-500/40 bg-orange-500/10';
			case 'MEDIUM':   return 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10';
			case 'LOW':      return 'text-blue-400 border-blue-500/40 bg-blue-500/10';
			default:         return 'text-[var(--text-muted)] border-[var(--border-color)] bg-transparent';
		}
	};

	const vulnUrl = (id: string) => `/vuln/${encodeURIComponent(id)}`;
</script>

{#if open}
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div
		class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/60 p-4 pt-16 backdrop-blur-sm"
		onkeydown={(e) => e.key === 'Escape' && (open = false)}
		onclick={(e) => e.target === e.currentTarget && (open = false)}
	>
		<div class="w-full max-w-[60rem]">
			<section class="w-full overflow-hidden rounded-2xl border border-[var(--border-color)] bg-[var(--bg)] shadow-2xl">
				<div class="flex items-center justify-between px-6 py-4">
					<div class="flex items-center gap-3">
						<ShieldX class="h-5 w-5 text-[var(--accent)]" />
						<h2 class="text-base font-semibold text-[var(--text-bright)]">Vulnerabilities</h2>
						{#if !loading && data.length > 0}
							<span class="rounded-full border border-[var(--border-color)] px-2 py-0.5 text-xs text-[var(--text-muted)]">
								{filtered.length}
							</span>
						{/if}
					</div>
					<button
						type="button"
						class="rounded-lg p-1.5 text-[var(--text-muted)] transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-secondary)]"
						onclick={() => (open = false)}
					>
						<X class="h-4 w-4" />
					</button>
				</div>

				{#if !loading && data.length > 0}
					<div class="px-6 pb-2">
						<TabSelector
							options={[
								{ value: 'all', label: 'All' },
								...severityOrder
									.filter((severity) => data.some((v) => v.severity?.toUpperCase() === severity))
									.map((severity) => ({
										value: severity,
										label: severity.charAt(0) + severity.slice(1).toLowerCase()
									}))
							]}
							bind:value={tab}
						/>
					</div>
				{/if}

				<div class="max-h-[70vh] overflow-y-auto">
					{#if loading}
						<div class="flex items-center justify-center py-20">
							<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
						</div>
					{:else if data.length === 0}
						<div class="flex flex-col items-center justify-center py-16 text-center">
							<Shield class="mb-3 h-10 w-10 text-[var(--text-muted)]" />
							<p class="text-sm font-medium text-[var(--text-secondary)]">No vulnerabilities found</p>
							<p class="mt-1 text-xs text-[var(--text-muted)]">No recorded scan results.</p>
						</div>
					{:else}
						<div class="space-y-1 p-2">
							{#each filtered as vuln}
								<article class="rounded-xl px-5 py-4 transition-colors hover:bg-[var(--hover-bg-subtle)]">
									<div class="flex items-start gap-4">
										<div class="w-24 shrink-0 pt-0.5">
											<span class="inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-semibold {severityClass(vuln.severity)}">
												{#if vuln.severity?.toUpperCase() === 'CRITICAL' || vuln.severity?.toUpperCase() === 'HIGH'}
													<ShieldX class="h-3 w-3" />
												{:else}
													<ShieldAlert class="h-3 w-3" />
												{/if}
												{vuln.severity || 'UNKNOWN'}
											</span>
										</div>

										<div class="min-w-0 flex-1 space-y-1.5">
											<div class="flex flex-wrap items-center gap-2">
												<a href={vulnUrl(vuln.vuln_id)} class="font-mono text-sm font-semibold text-[var(--accent)] hover:underline">{vuln.vuln_id}</a>
												{#each vuln.sources ?? [] as source}
													<span class="rounded-full border border-[var(--border-color)] px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-[var(--text-muted)]">{source}</span>
												{/each}
											</div>
											{#if vuln.title}
												<p class="text-sm text-[var(--text-secondary)]">{vuln.title}</p>
											{/if}
											{#if vuln.description}
												<div class="text-xs leading-relaxed text-[var(--text-muted)]">
													<Markdown content={vuln.description} />
												</div>
											{/if}
											<div class="flex flex-wrap items-center gap-3 text-xs text-[var(--text-muted)]">
												<span class="font-mono">{vuln.pkg_name}{vuln.installed_version ? `@${vuln.installed_version}` : ''}</span>
												{#if vuln.fixed_version}
													<span class="bg-green-500/10 px-1.5 py-0.5 font-mono text-green-400">fix: {vuln.fixed_version}</span>
												{:else}
													<span class="opacity-50">no fix available</span>
												{/if}
											</div>
										</div>
									</div>
								</article>
							{/each}
						</div>
					{/if}
				</div>
			</section>
		</div>
	</div>
{/if}
