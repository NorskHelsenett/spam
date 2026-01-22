<script lang="ts">
	const segments = [
		{
			name: 'Linux nodes',
			count: 9,
			description: 'Bare-metal and KVM guests joined to the cluster.',
			tag: 'Ubuntu · Debian · Rocky',
			accent: 'var(--accent)'
		},
		{
			name: 'Homelab services',
			count: 5,
			description: 'Applications connected through the agent gateway.',
			tag: 'Docker · Nomad · k3s',
			accent: 'var(--info)'
		},
		{
			name: 'Edge devices',
			count: 3,
			description: 'Remote appliances forwarding metrics and alerts.',
			tag: 'WireGuard',
			accent: 'var(--warning)'
		}
	];

	const tableRows = Array.from({ length: 8 }, (_, index) => ({
		name: `agent-${index + 1}`,
		role: index % 2 === 0 ? 'Collector' : 'Executor',
		dc: index % 3 === 0 ? 'lab' : index % 3 === 1 ? 'edge' : 'cloud',
		status: index % 4 === 0 ? 'Maintenance' : 'Online',
		version: '0.8.12'
	}));
</script>

<svelte:head>
	<title>Agents • Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Agent catalogue</h1>
				<p class="text-sm text-[var(--text-tertiary)]">High-level grouping of managed agents. Data shown here is placeholder content.</p>
			</div>
			<button type="button" class="rounded-full border border-[var(--border-color)] px-4 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]">
				Add agent
			</button>
		</header>
		<div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
			{#each segments as segment}
				<article class="metric-card p-5 sm:p-6">
					<div class="flex items-center justify-between">
						<h2 class="text-lg font-semibold text-[var(--text-bright)]">{segment.name}</h2>
						<span class="text-2xl font-bold" style={`color: ${segment.accent}`}>{segment.count}</span>
					</div>
					<p class="mt-2 text-sm text-[var(--text-secondary)]">{segment.description}</p>
					<span class="mt-4 inline-flex items-center gap-2 rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-tertiary)]">{segment.tag}</span>
				</article>
			{/each}
		</div>
	</section>

	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">Inventory</h2>
			<div class="flex flex-wrap gap-3 text-sm text-[var(--text-secondary)]">
				<span class="rounded-full border border-[var(--border-color)] px-3 py-1">Sort: role</span>
				<span class="rounded-full border border-[var(--border-color)] px-3 py-1">Filter: online</span>
			</div>
		</header>
		<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
			<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
				<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
					<tr>
						<th class="px-5 py-3 text-left">Agent</th>
						<th class="px-5 py-3 text-left">Role</th>
						<th class="px-5 py-3 text-left">Zone</th>
						<th class="px-5 py-3 text-left">Version</th>
						<th class="px-5 py-3 text-left">Status</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
					{#each tableRows as row}
						<tr class="transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]">
							<td class="px-5 py-3 font-semibold text-[var(--text-bright)]">{row.name}</td>
							<td class="px-5 py-3">{row.role}</td>
							<td class="px-5 py-3 uppercase tracking-[0.18em] text-[var(--text-tertiary)]">{row.dc}</td>
							<td class="px-5 py-3">{row.version}</td>
							<td class="px-5 py-3">
								<span class="inline-flex items-center gap-2 rounded-full border border-[var(--border-color)] px-3 py-1 text-xs" style={`color: ${row.status === 'Maintenance' ? 'var(--warning)' : 'var(--success)'}`}>{row.status}</span>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
		<p class="text-xs text-[var(--text-tertiary)]">Data is illustrative; wire this table to your API when backend endpoints are ready.</p>
	</section>
</div>
