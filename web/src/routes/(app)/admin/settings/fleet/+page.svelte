<script lang="ts">
	import { onMount } from 'svelte';
	import FleetMap from '$lib/components/FleetMap.svelte';
	import type { FleetAgent } from '$lib/fleet';

	let agents = $state<FleetAgent[]>([]);
	let loading = $state(true);
	let error = $state('');

	async function load() {
		loading = true;
		error = '';
		try {
			const res = await fetch('/api/agents');
			if (!res.ok) throw new Error(`HTTP ${res.status}`);
			agents = await res.json();
		} catch (e) {
			error = e instanceof Error ? e.message : 'failed to load';
		} finally {
			loading = false;
		}
	}

	onMount(load);
</script>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">Fleet</h2>
				<p class="text-sm text-[var(--text-tertiary)]">
					Every SCAM agent at a glance — box size is memory, colour is environment or version,
					and failing agents stand out.
				</p>
			</div>
			<button type="button" class="btn btn-ghost" onclick={load} disabled={loading}>Refresh</button>
		</header>

		{#if error}
			<div class="rounded-xl border border-[var(--border-color)] bg-[var(--card-bg)] p-4 text-sm text-[var(--error)]">
				Failed to load agents: {error}
			</div>
		{:else if loading && agents.length === 0}
			<p class="text-sm text-[var(--text-muted)]">Loading fleet…</p>
		{:else if agents.length === 0}
			<p class="text-sm text-[var(--text-muted)]">No agents have checked in yet.</p>
		{:else}
			<FleetMap {agents} />
		{/if}
	</section>
</div>
