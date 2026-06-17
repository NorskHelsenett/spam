// Shared types for the fleet view. Kept in a plain module (not a Svelte
// component module-script) so FleetMap.svelte can carry a <style> block —
// the @tailwindcss/vite plugin mis-handles a component that has both a
// `<script module>` and a `<style>`.

export type FleetHealth = 'live' | 'stale' | 'dead';

export interface FleetAgent {
	clusterId: string;
	name: string;
	environment: string;
	zone: string;
	version: string;
	commit: string;
	health: FleetHealth;
	uptimeSeconds: number;
	rssBytes: number;
	cpuPct: number;
	goroutines: number;
	flapping: boolean;
}
