import type { RepoData } from '$lib/types/providers';

const base = new Date('2026-02-05T15:22:00Z');
const ts = (offsetMinutes: number) => new Date(base.getTime() + offsetMinutes * 60000).toISOString();

export const mockDonut = {
	title: 'Dependency Mix',
	total: 120,
	segments: [
		{ label: 'npm', value: 52, color: 'var(--yellow)' },
		{ label: 'pip', value: 28, color: 'var(--aqua)' },
		{ label: 'go', value: 16, color: 'var(--blue)' },
		{ label: 'maven', value: 14, color: 'var(--orange)' }
	]
};

export const mockRepos: RepoData[] = [
	{
		external_id: 'r_001',
		name: 'observability-kit',
		full_path: 'acme/observability-kit',
		description: 'Telemetry pipelines and dashboards.',
		html_url: 'https://example.com/acme/observability-kit',
		default_branch: 'main',
		languages: ['TypeScript', 'Svelte', 'Go'],
		is_private: true,
		is_archived: false,
		is_fork: false,
		topics: ['sse', 'sbom', 'monitoring'],
		created_at: '2024-01-08T12:21:00Z',
		updated_at: '2026-02-02T10:12:00Z',
		pushed_at: '2026-02-03T09:04:00Z'
	},
	{
		external_id: 'r_002',
		name: 'edge-runner',
		full_path: 'acme/edge-runner',
		description: 'Runner that executes SBOM scans in cluster.',
		html_url: 'https://example.com/acme/edge-runner',
		default_branch: 'main',
		languages: ['Go', 'Shell'],
		is_private: false,
		is_archived: false,
		is_fork: true,
		topics: ['kubernetes', 'scanner', 'sbom'],
		created_at: '2023-08-14T08:10:00Z',
		updated_at: '2026-01-27T16:32:00Z',
		pushed_at: '2026-02-01T12:40:00Z'
	},
	{
		external_id: 'r_003',
		name: 'policy-engine',
		full_path: 'acme/policy-engine',
		description: 'Policy checks and artifact rules.',
		html_url: 'https://example.com/acme/policy-engine',
		default_branch: 'main',
		languages: ['Rust', 'Rego'],
		is_private: true,
		is_archived: false,
		is_fork: false,
		topics: ['policy', 'compliance'],
		created_at: '2022-05-10T09:45:00Z',
		updated_at: '2026-02-01T10:01:00Z',
		pushed_at: '2026-01-31T17:26:00Z'
	},
	{
		external_id: 'r_004',
		name: 'artifact-vault',
		full_path: 'acme/artifact-vault',
		description: 'Immutable storage for SBOM artifacts.',
		html_url: 'https://example.com/acme/artifact-vault',
		default_branch: 'main',
		languages: ['Python', 'PostgreSQL'],
		is_private: true,
		is_archived: true,
		is_fork: false,
		topics: ['storage', 'sbom'],
		created_at: '2021-03-12T14:30:00Z',
		updated_at: '2025-12-12T09:10:00Z',
		pushed_at: '2025-12-10T15:00:00Z'
	}
];

export const mockRun = {
	runId: 'run_2026_0205_1042',
	status: 'SUCCEEDED',
	logs: [
		{ line: 'Cloning https://example.com/acme/observability-kit.git...', ts: ts(1) },
		{ line: 'Commit hash: 7f23c9b', ts: ts(2) },
		{ line: 'Running syft...', ts: ts(4) },
		{ line: 'Collecting dependency manifest files', ts: ts(6) },
		{ line: 'Found 3 dependency manifest files', ts: ts(8) },
		{ line: 'Running BetterLeaks...', ts: ts(10) },
		{ line: 'leaks found: 0', ts: ts(12) },
		{ line: 'Uploading SBOM', ts: ts(14) },
		{ line: 'Uploading dependency manifests', ts: ts(15) },
		{ line: 'Run completed successfully', ts: ts(16) }
	],
	events: [
		{
			type: 'Normal',
			reason: 'Scheduled',
			message: 'Successfully assigned spam/runner-5d6c',
			source: 'default-scheduler',
			first_timestamp: ts(0),
			last_timestamp: ts(0),
			count: 1,
			object: 'pod/runner-5d6c'
		},
		{
			type: 'Normal',
			reason: 'Pulling',
			message: 'Pulling image "ghcr.io/acme/runner:1.9.2"',
			source: 'kubelet',
			first_timestamp: ts(1),
			last_timestamp: ts(1),
			count: 1,
			object: 'pod/runner-5d6c'
		},
		{
			type: 'Normal',
			reason: 'Pulled',
			message: 'Successfully pulled image "ghcr.io/acme/runner:1.9.2"',
			source: 'kubelet',
			first_timestamp: ts(2),
			last_timestamp: ts(2),
			count: 1,
			object: 'pod/runner-5d6c'
		},
		{
			type: 'Normal',
			reason: 'Created',
			message: 'Created container runner',
			source: 'kubelet',
			first_timestamp: ts(3),
			last_timestamp: ts(3),
			count: 1,
			object: 'pod/runner-5d6c'
		},
		{
			type: 'Normal',
			reason: 'Started',
			message: 'Started container runner',
			source: 'kubelet',
			first_timestamp: ts(4),
			last_timestamp: ts(4),
			count: 1,
			object: 'pod/runner-5d6c'
		}
	],
	podStatus: {
		phase: 'Running'
	},
	secretCount: 0,
	sbomComponentCount: 1243,
	manifestCount: 3,
	commitHash: '7f23c9b'
};

export const mockMarkdown = [
	'# Markdown sample',
	'',
	'This component renders **rich text** with `inline code`, [links](https://example.com), and highlights.',
	'',
	'## Checklist',
	'- [x] Build UI tokens',
	'- [x] Render components',
	'- [ ] Verify interactions',
	'',
	'## Table',
	'| Token | Value |',
	'| --- | --- |',
	'| Accent | var(--accent) |',
	'| Warning | var(--warning) |',
	'',
	'> Callouts can live here and inherit theme styles.',
	'',
	'```tsx',
	"const status = 'ok';",
	'console.log(status);',
	'```',
	'',
	'---',
	'',
	'Paragraph with ~~del~~ and ==mark== styles.'
].join('\n');

export const mockDependency = {
	name: 'react',
	ecosystem: 'npm',
	sources: ['sbom']
};

export const mockTextSamples = [
	{ label: 'text-xs', className: 'text-xs', sample: 'XS: quick brown fox' },
	{ label: 'text-sm', className: 'text-sm', sample: 'SM: quick brown fox' },
	{ label: 'text-base', className: 'text-base', sample: 'Base: quick brown fox' },
	{ label: 'text-lg', className: 'text-lg', sample: 'LG: quick brown fox' },
	{ label: 'text-xl', className: 'text-xl', sample: 'XL: quick brown fox' },
	{ label: 'text-2xl', className: 'text-2xl', sample: '2XL: quick brown fox' },
	{ label: 'text-3xl', className: 'text-3xl', sample: '3XL: quick brown fox' }
];

export const mockColorSwatches = [
	{ label: 'Background Hard', varName: '--bg-hard' },
	{ label: 'Background', varName: '--bg' },
	{ label: 'Background Soft', varName: '--bg-soft' },
	{ label: 'Border', varName: '--border-color' },
	{ label: 'Text Primary', varName: '--text-primary' },
	{ label: 'Text Secondary', varName: '--text-secondary' },
	{ label: 'Text Muted', varName: '--text-muted' }
];

export const mockSemanticSwatches = [
	{ label: 'Accent', varName: '--accent' },
	{ label: 'Success', varName: '--success' },
	{ label: 'Warning', varName: '--warning' },
	{ label: 'Error', varName: '--error' },
	{ label: 'Info', varName: '--info' },
	{ label: 'CPU', varName: '--cpu-color' },
	{ label: 'Memory', varName: '--memory-color' },
	{ label: 'Disk', varName: '--disk-color' }
];

export const mockPaletteGroups = [
	{ name: 'Red', variants: [{ label: 'Red', varName: '--red' }, { label: 'Red Dim', varName: '--red-dim' }] },
	{ name: 'Green', variants: [{ label: 'Green', varName: '--green' }, { label: 'Green Dim', varName: '--green-dim' }] },
	{ name: 'Yellow', variants: [{ label: 'Yellow', varName: '--yellow' }, { label: 'Yellow Dim', varName: '--yellow-dim' }] },
	{ name: 'Blue', variants: [{ label: 'Blue', varName: '--blue' }, { label: 'Blue Dim', varName: '--blue-dim' }] },
	{ name: 'Purple', variants: [{ label: 'Purple', varName: '--purple' }, { label: 'Purple Dim', varName: '--purple-dim' }] },
	{ name: 'Aqua', variants: [{ label: 'Aqua', varName: '--aqua' }, { label: 'Aqua Dim', varName: '--aqua-dim' }] },
	{ name: 'Orange', variants: [{ label: 'Orange', varName: '--orange' }, { label: 'Orange Dim', varName: '--orange-dim' }] },
	{ name: 'Gray', variants: [{ label: 'Gray', varName: '--gray' }, { label: 'Gray Dim', varName: '--gray-dim' }] }
];

export const mockTabs = [
	{ value: 'overview', label: 'Overview' },
	{ value: 'insights', label: 'Insights' },
	{ value: 'alerts', label: 'Alerts' }
];
