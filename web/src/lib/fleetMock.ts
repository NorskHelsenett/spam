import type { FleetAgent, FleetHealth } from '$lib/fleet';

// Mock fleet for the playground and the settings page until the backend
// lands. Shaped exactly like the planned GET /api/agents response, so the
// FleetMap component is wired for real data unchanged.

const ENVS = ['prod', 'prod', 'prod', 'staging', 'test', 'dev'];
const ZONES: Record<string, string[]> = {
	prod: ['dc-oslo-a', 'dc-oslo-b', 'dc-bergen-a'],
	staging: ['dc-oslo-b', 'dc-trondheim-a'],
	test: ['dc-trondheim-a'],
	dev: ['dc-oslo-a']
};
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

export function generateFleet(count = 420): FleetAgent[] {
	return Array.from({ length: count }, (_, i) => makeAgent(i));
}
