<script lang="ts">
	import FleetMap from '$lib/components/FleetMap.svelte';
	import { generateFleet } from '$lib/fleetMock';

	let agents = $state(generateFleet());

	// ---- rollout simulation (previews the live SSE transition) ------------
	const TARGET = 'v0.3.0';
	let rolling = $state(false);
	let timer: ReturnType<typeof setInterval> | null = null;

	function nextVersion(v: string): string {
		if (v === 'v0.1.0') return 'v0.2.0';
		if (v === 'v0.2.0' || v === 'feat-agent-healthz') return TARGET;
		return v;
	}

	function toggleRollout() {
		if (rolling) {
			if (timer) clearInterval(timer);
			rolling = false;
			return;
		}
		rolling = true;
		timer = setInterval(() => {
			const laggards = agents.filter((a) => a.version !== TARGET);
			if (laggards.length === 0) {
				if (timer) clearInterval(timer);
				rolling = false;
				return;
			}
			const batch = laggards.slice(0, Math.max(1, Math.floor(laggards.length * 0.12)));
			for (const a of batch) {
				a.version = nextVersion(a.version);
				a.uptimeSeconds = 20 + Math.floor(Math.random() * 90);
				a.commit = Math.random().toString(16).slice(2, 9);
			}
			agents = [...agents];
		}, 650);
	}

	function injectIncident() {
		const live = agents.filter((a) => a.health === 'live');
		for (let i = 0; i < 10 && live.length; i++) {
			const a = live[Math.floor(Math.random() * live.length)];
			a.flapping = true;
			a.cpuPct = 12 + Math.random() * 10;
			a.rssBytes = Math.floor((260 + Math.random() * 160) * (1 << 20));
			a.uptimeSeconds = 15;
		}
		const victims = agents.filter((a) => a.health === 'live');
		for (let i = 0; i < 4 && victims.length; i++) {
			victims[Math.floor(Math.random() * victims.length)].health = 'dead';
		}
		agents = [...agents];
	}

	function reset() {
		if (timer) clearInterval(timer);
		rolling = false;
		agents = generateFleet();
	}

	$effect(() => () => {
		if (timer) clearInterval(timer);
	});
</script>

<div class="space-y-8 p-6 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">Fleet (playground)</h2>
				<p class="text-sm text-[var(--text-tertiary)]">
					Mock data. The buttons preview what the live SSE stream will drive.
				</p>
			</div>
			<div class="flex shrink-0 gap-2">
				<button type="button" class="btn {rolling ? 'btn-warning' : 'btn-primary'}" onclick={toggleRollout}>
					{rolling ? 'Stop rollout' : 'Simulate rollout'}
				</button>
				<button type="button" class="btn btn-ghost" onclick={injectIncident}>Inject incident</button>
				<button type="button" class="btn btn-ghost" onclick={reset}>Reset</button>
			</div>
		</header>

		<FleetMap {agents} />
	</section>
</div>
