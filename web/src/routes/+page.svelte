<script lang="ts">
	const metrics = [
		{
			label: 'Agents',
			value: '17',
			description: 'Across all registered servers',
			accent: 'var(--accent)'
		},
		{
			label: 'Online',
			value: '10',
			description: 'Heartbeat within the last minute',
			accent: 'var(--success)'
		},
		{
			label: 'Compute Load',
			value: '9.0% avg',
			description: 'Total cores: 54',
			accent: 'var(--cpu-color)'
		},
		{
			label: 'Storage',
			value: '47.3 TB used',
			description: '17.6 TB free across pool',
			accent: 'var(--text-bright)'
		},
		{
			label: 'Memory',
			value: '91.1 / 192 GB',
			description: '47% utilisation (online)',
			accent: 'var(--memory-color)'
		}
	];

	const activity = [
		{
			title: 'Fleet sync',
			subtitle: 'Nightly inventory refresh completes in ~4m',
			status: 'Scheduled 02:00 UTC',
			accent: 'var(--info)'
		},
		{
			title: 'Firmware guard',
			subtitle: 'Drift detection monitors 11 nodes',
			status: 'No action required',
			accent: 'var(--success)'
		},
		{
			title: 'Backup window',
			subtitle: 'Incremental archives for media tier',
			status: 'Queued for 03:30 UTC',
			accent: 'var(--warning)'
		}
	];
</script>

<svelte:head>
	<title>Overview • Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:space-y-8 sm:px-10 sm:py-12">
		<div class="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
			<div class="space-y-3">
				<span class="inline-flex w-fit items-center gap-2 rounded-full border border-[var(--accent-dark)]/50 bg-[var(--accent-dark)]/15 px-3 py-1 text-[10px] font-medium uppercase tracking-[0.32em] text-[var(--accent)] sm:text-xs">
					Fleet Control
				</span>
				<div class="space-y-2">
					<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl md:text-4xl">
						Agent Operations Console
					</h1>
					<p class="max-w-xl text-sm text-[var(--text-tertiary)] sm:text-base">
						Monitor workloads across your infrastructure, bootstrap new nodes with single-command routines,
						and drill into individual servers with a widescreen dashboard built for operators.
					</p>
				</div>
			</div>
			<div class="flex flex-col items-start gap-2 text-xs text-[var(--text-muted)] sm:text-sm">
				<span class="inline-flex items-center gap-2 rounded-full border border-[var(--success-dark)] px-3 py-1 text-[var(--success)]">
					<span class="h-2 w-2 rounded-full bg-[var(--success)]"></span>
					Live stream healthy
				</span>
				<span class="rounded-full border border-[var(--border-color)] px-3 py-1">Last refresh 10:27:12</span>
			</div>
		</div>
		<div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
			<article class="metric-card p-4 sm:p-6">
				<h2 class="text-lg font-semibold text-[var(--text-bright)]">Agent health</h2>
				<p class="mt-2 text-sm text-[var(--text-secondary)]">
					Upgrade windows, token rotation cadence, and streaming telemetry summaries surface here.
				</p>
				<ul class="mt-5 space-y-3 text-sm text-[var(--text-tertiary)]">
					<li class="flex items-center justify-between">
						<span>Latest agent version</span>
						<span class="font-semibold text-[var(--text-bright)]">v0.8.12</span>
					</li>
					<li class="flex items-center justify-between">
						<span>Telemetry cadence</span>
						<span class="font-semibold text-[var(--accent)]">15s</span>
					</li>
					<li class="flex items-center justify-between">
						<span>Certificates expiring</span>
						<span class="font-semibold text-[var(--warning)]">2 this week</span>
					</li>
				</ul>
			</article>
			<article class="metric-card p-4 sm:p-6">
				<h2 class="text-lg font-semibold text-[var(--text-bright)]">Upcoming tasks</h2>
				<ul class="mt-4 space-y-4 text-sm text-[var(--text-secondary)]">
					{#each activity as item}
						<li class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-4 py-3">
							<div class="flex items-center justify-between gap-3">
								<span class="font-medium text-[var(--text-bright)]">{item.title}</span>
								<span class="text-xs font-semibold" style={`color: ${item.accent}`}>{item.status}</span>
							</div>
							<p class="mt-2 text-xs text-[var(--text-tertiary)]">{item.subtitle}</p>
						</li>
					{/each}
				</ul>
			</article>
			<article class="metric-card flex flex-col justify-between p-4 sm:p-6">
				<div class="space-y-3">
					<h2 class="text-lg font-semibold text-[var(--text-bright)]">Quick actions</h2>
					<p class="text-sm text-[var(--text-secondary)]">
						Drop in tasks to roll new agents, trigger health probes, or mute noisy alert streams while you iterate.
					</p>
				</div>
				<div class="mt-4 grid gap-2 text-sm">
					<button type="button" class="rounded-lg border border-[var(--border-color)] bg-[var(--hover-bg-subtle)] px-4 py-2 text-left text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]">
						Deploy staging bundle
					</button>
					<button type="button" class="rounded-lg border border-[var(--border-color)] bg-[var(--hover-bg-subtle)] px-4 py-2 text-left text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]">
						Trigger fleet health check
					</button>
					<button type="button" class="rounded-lg border border-[var(--border-color)] bg-[var(--hover-bg-subtle)] px-4 py-2 text-left text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]">
						Mute alerts (15 min)
					</button>
				</div>
			</article>
		</div>
	</section>

	<section class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
		{#each metrics as metric}
			<article class="metric-card p-4 sm:rounded-2xl sm:p-6">
				<p class="text-[10px] uppercase tracking-[0.32em] text-[var(--text-tertiary)] sm:text-xs">{metric.label}</p>
				<p class="mt-2 text-2xl font-semibold" style={`color: ${metric.accent}`}>{metric.value}</p>
				<p class="mt-1 text-xs text-[var(--text-quaternary)] sm:mt-2 sm:text-sm">{metric.description}</p>
			</article>
		{/each}
	</section>

	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
			<div class="space-y-1">
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">Latest telemetry</h2>
				<p class="text-sm text-[var(--text-tertiary)]">
					Placeholder feed showing the most recent events received from connected agents.
				</p>
			</div>
			<button type="button" class="rounded-full border border-[var(--border-color)] px-4 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]">
				View stream
			</button>
		</header>
		<div class="grid gap-3 text-sm text-[var(--text-secondary)] sm:grid-cols-2 lg:grid-cols-3">
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-4 py-4">
				<p class="font-semibold text-[var(--text-bright)]">Node synapse-03</p>
				<p class="mt-2 text-xs text-[var(--text-tertiary)]">CPU spike resolved · load returned to baseline</p>
				<span class="mt-3 inline-flex items-center gap-2 text-[10px] uppercase tracking-[0.26em] text-[var(--success)]">Recovered</span>
			</div>
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-4 py-4">
				<p class="font-semibold text-[var(--text-bright)]">Node archive-02</p>
				<p class="mt-2 text-xs text-[var(--text-tertiary)]">Scrub cycle started for zpool tank</p>
				<span class="mt-3 inline-flex items-center gap-2 text-[10px] uppercase tracking-[0.26em] text-[var(--warning)]">In progress</span>
			</div>
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-4 py-4">
				<p class="font-semibold text-[var(--text-bright)]">Node edge-01</p>
				<p class="mt-2 text-xs text-[var(--text-tertiary)]">Dropped swap usage alert · threshold restored</p>
				<span class="mt-3 inline-flex items-center gap-2 text-[10px] uppercase tracking-[0.26em] text-[var(--accent)]">Resolved</span>
			</div>
		</div>
	</section>
</div>
