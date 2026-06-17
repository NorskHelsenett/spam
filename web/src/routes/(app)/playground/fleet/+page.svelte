<script lang="ts">
	import FleetMap from '$lib/components/FleetMap.svelte';
	import type { FleetAgent, FleetHealth } from '$lib/fleet';

	// ---- mock fleet -------------------------------------------------------
	// Stand-in for GET /api/agents until the backend lands. Shaped exactly
	// like the planned endpoint so FleetMap is wired for real data unchanged.
	// Final home: its own tab right of Database under /admin/settings.
	const ENVS = ['prod', 'prod', 'prod', 'staging', 'test', 'dev'];
	const ZONES: Record<string, string[]> = {
		prod: ['dc-oslo-a', 'dc-oslo-b', 'dc-bergen-a'],
		staging: ['dc-oslo-b', 'dc-trondheim-a'],
		test: ['dc-trondheim-a'],
		dev: ['dc-oslo-a']
	};
	const TARGET = 'v0.3.0';
	const VERSIONS: [string, number][] = [
		['v0.3.0', 0.58],
		['v0.2.0', 0.26],
		['v0.1.0', 0.1],
		['feat-agent-healthz', 0.06]
	];

	function pickWeighted(opts: [string, number][]): string {
		let r = Math.random();
		for (const [v, w] of opts) {
			if ((r -= w) <= 0) return v;
		}
		return opts[0][0];
	}

	function makeAgent(i: number): FleetAgent {
		const env = ENVS[Math.floor(Math.random() * ENVS.length)];
		const zones = ZONES[env];
		const r = Math.random();
		const health: FleetHealth = r > 0.92 ? 'stale' : r > 0.88 ? 'dead' : 'live';
		const outlier = Math.random() > 0.96;
		return {
			clusterId: `c-${env}-${String(i).padStart(3, '0')}`,
			name: `${env.slice(0, 1)}-${zones[0].slice(3, 6)}-${String(i).padStart(3, '0')}`,
			environment: env,
			zone: zones[Math.floor(Math.random() * zones.length)],
			version: pickWeighted(VERSIONS),
			commit: Math.random().toString(16).slice(2, 9),
			health,
			uptimeSeconds: Math.floor(Math.random() * 30 * 86400),
			rssBytes: Math.floor((outlier ? 220 + Math.random() * 180 : 30 + Math.random() * 90) * (1 << 20)),
			cpuPct: outlier ? 8 + Math.random() * 12 : Math.random() * 5,
			goroutines: Math.floor(20 + Math.random() * (outlier ? 400 : 60)),
			flapping: health === 'live' && Math.random() > 0.97
		};
	}

	let agents = $state<FleetAgent[]>(Array.from({ length: 420 }, (_, i) => makeAgent(i)));

	// ---- rollout simulation (previews the live SSE transition) ------------
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
		agents = Array.from({ length: 420 }, (_, i) => makeAgent(i));
	}

	$effect(() => () => {
		if (timer) clearInterval(timer);
	});
</script>

<div class="space-y-8 p-6 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">Fleet</h2>
				<p class="text-sm text-[var(--text-tertiary)]">
					Every agent as a cell — size is memory, color is version or health, and failing agents
					recolor themselves. Mock data; the buttons preview what the live SSE stream will drive.
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
