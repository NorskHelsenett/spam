<script lang="ts">
	import FleetMap from '$lib/components/FleetMap.svelte';
	import { generateFleet } from '$lib/fleetMock';

	// TODO: replace with GET /api/agents + the SSE stream once the backend
	// lands (see TODO.md). Mock data for now.
	const agents = generateFleet();
</script>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">Fleet</h2>
				<p class="text-sm text-[var(--text-tertiary)]">
					Every SCAM agent at a glance — box size is memory, colour is environment or version,
					and failing agents stand out. <span class="text-[var(--text-muted)]">(mock data)</span>
				</p>
			</div>
		</header>

		<FleetMap {agents} />
	</section>
</div>
