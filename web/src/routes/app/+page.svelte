<script lang="ts">
	const summaryMetrics = [
		{
			label: 'Tracked SBOMs',
			value: '42',
			description: 'Across 11 product lines',
			accent: 'var(--accent)'
		},
		{
			label: 'Components indexed',
			value: '18,742',
			description: 'With provenance and hashes',
			status: 'Fix accepted',
			accent: 'var(--text-bright)'
		},
		{
			label: 'Open vulnerabilities',
			value: '176',
			description: '12 critical • 38 high',
			accent: 'var(--error)'
		},
		{
			label: 'License exceptions',
			value: '7',
			description: 'Awaiting legal review',
			accent: 'var(--warning)'
		},
		{
			label: 'Median ingest time',
			value: '11m',
			description: 'From build to inventory',
			accent: 'var(--info)'
		}
	];

	const riskHotspots = [
		{
			service: 'payments-api@8.4.2',
			issue: 'openssl 3.0.1 (CVE-2023-0466)',
			severity: 'Critical',
			severityColor: 'var(--error)',
			recommendedFix: 'Upgrade to 3.0.13',
			exposures: '14 deployments'
		},
		{
			service: 'identity-service@5.9.0',
			issue: 'spring-security 5.8.5 (CVE-2025-12018)',
			severity: 'High',
			severityColor: 'var(--warning)',
			recommendedFix: 'Patch to 5.8.7',
			exposures: '6 deployments'
		},
		{
			service: 'mobile-app@12.3.1',
			issue: 'libwebp 1.2.2 (CVE-2023-4863)',
			severity: 'Critical',
			severityColor: 'var(--error)',
			recommendedFix: 'Upgrade to 1.4.0',
			exposures: 'Android · iOS builds'
		}
	];

	const remediationQueue = [
		{
			id: 'CVE-2025-12018',
			component: 'spring-security 5.8.5',
			owner: 'Platform Security',
			due: 'Due in 2d',
			status: 'Awaiting rollout',
			statusColor: 'var(--warning)'
		},
		{
			id: 'CVE-2024-31032',
			component: 'glibc 2.31',
			owner: 'Runtime Engineering',
			due: 'Due in 5d',

			statusColor: 'var(--success)'
		},
		{
			id: 'CVE-2023-4863',
			component: 'libwebp 1.2.2',
			owner: 'Mobile Platform',
			due: 'Due in 1d',
			status: 'In validation',
			statusColor: 'var(--accent)'
		}
	];

	const recentActivity = [
		{
			sbom: 'frontend-web@5.11.0',
			action: 'Ingested from CI pipeline',
			timestamp: '5 minutes ago',
			delta: '+2 dependencies',
			accent: 'var(--accent)'
		},
		{
			sbom: 'analytics-job@4.2.0',
			action: 'Policy check failed · GPL-3.0 detected',
			timestamp: '18 minutes ago',
			delta: 'Blocked push',
			accent: 'var(--warning)'
		},
		{
			sbom: 'edge-appliance@2.8.1',
			action: 'VEX update suppressed 4 CVEs',
			timestamp: '32 minutes ago',
			delta: '-1 critical',
			accent: 'var(--success)'
		}
	];

	const licenseAlerts = [
		{
			packageName: 'chartjs 4.4.1',
			issue: 'GPL-3.0 introduced via vendor fork',
			action: 'Request dual-license approval',
			status: 'Pending',
			statusColor: 'var(--warning)'
		},
		{
			packageName: 'lodash 4.17.21',
			issue: 'License metadata missing attribution',
			action: 'Update NOTICE file template',
			status: 'In progress',
			statusColor: 'var(--accent)'
		},
		{
			packageName: 'ffmpeg 6.1',
			issue: 'LGPL requirements unmet for static link',
			action: 'Move to dynamic linkage',
			status: 'Escalated',
			statusColor: 'var(--error)'
		}
	];

	const coverageHighlights = [
		{
			label: 'Build pipelines exporting SBOMs',
			value: '34 / 36',
			trend: '+2 this sprint',
			trendColor: 'var(--success)'
		},
		{
			label: 'SBOMs with VEX context',
			value: '19',
			trend: '+6 since last month',
			trendColor: 'var(--accent)'
		},
		{
			label: 'Policies enforced pre-merge',
			value: '92%',
			trend: '+4%',
			trendColor: 'var(--success)'
		}
	];
</script>

<svelte:head>
	<title>SBOM Dashboard • Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:space-y-8 sm:px-10 sm:py-12">
		<div class="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
			<div class="space-y-3">
				<span class="inline-flex w-fit items-center gap-2 rounded-full border border-[var(--accent-dark)]/50 bg-[var(--accent-dark)]/15 px-3 py-1 text-[10px] font-medium uppercase tracking-[0.32em] text-[var(--accent)] sm:text-xs">
					SBOM Control Center
				</span>
				<div class="space-y-2">
					<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl md:text-4xl">
						Software Supply Chain Posture
					</h1>
					<p class="max-w-2xl text-sm text-[var(--text-tertiary)] sm:text-base">
						Track every bill of materials your organisation ships, surface the riskiest components within minutes,
						and steer remediation efforts with policy-backed workflows and instant VEX context.
					</p>
				</div>
			</div>
			<div class="flex flex-col items-start gap-2 text-xs text-[var(--text-muted)] sm:text-sm">
				<span class="inline-flex items-center gap-2 rounded-full border border-[var(--success-dark)] px-3 py-1 text-[var(--success)]">
					<span class="h-2 w-2 rounded-full bg-[var(--success)]"></span>
					All ingest pipelines nominal
				</span>
				<span class="rounded-full border border-[var(--border-color)] px-3 py-1">Last sync 00:04:17 ago</span>
			</div>
		</div>
		<div class="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
			<article class="metric-card p-4 sm:p-6">
				<h2 class="text-lg font-semibold text-[var(--text-bright)]">Risk posture snapshot</h2>
				<ul class="mt-4 space-y-3 text-sm text-[var(--text-secondary)]">
					<li class="flex items-center justify-between">
						<span>Critical CVEs unpatched</span>
						<span class="font-semibold text-[var(--error)]">12</span>
					</li>
					<li class="flex items-center justify-between">
						<span>Components missing provenance</span>
						<span class="font-semibold text-[var(--warning)]">31</span>
					</li>
					<li class="flex items-center justify-between">
						<span>SBOMs with outdated VEX</span>
						<span class="font-semibold text-[var(--accent)]">5</span>
					</li>
				</ul>
			</article>
			<article class="metric-card p-4 sm:p-6">
				<h2 class="text-lg font-semibold text-[var(--text-bright)]">Remediation queue</h2>
				<ul class="mt-4 space-y-4 text-sm text-[var(--text-secondary)]">
					{#each remediationQueue as item}
						<li class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 px-4 py-3">
							<div class="flex items-center justify-between gap-3">
								<span class="font-medium text-[var(--text-bright)]">{item.id}</span>
								<span class="text-xs font-semibold" style={`color: ${item.statusColor}`}>{item.due}</span>
							</div>
							<p class="mt-2 text-xs text-[var(--text-tertiary)]">{item.component}</p>
							<p class="mt-1 text-[10px] uppercase tracking-[0.22em] text-[var(--text-muted)]">{item.owner} · {item.status}</p>
						</li>
					{/each}
				</ul>
			</article>
			<article class="metric-card flex flex-col justify-between p-4 sm:p-6">
				<div class="space-y-3">
					<h2 class="text-lg font-semibold text-[var(--text-bright)]">Quick actions</h2>
					<p class="text-sm text-[var(--text-secondary)]">
						Kick off workflow automation without leaving the console.
					</p>
				</div>
				<div class="mt-4 grid gap-2 text-sm">
					<button type="button" class="rounded-lg border border-[var(--border-color)] bg-[var(--hover-bg-subtle)] px-4 py-2 text-left text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]">
						Upload new SBOM
					</button>
					<button type="button" class="rounded-lg border border-[var(--border-color)] bg-[var(--hover-bg-subtle)] px-4 py-2 text-left text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]">
						Generate compliance report
					</button>
					<button type="button" class="rounded-lg border border-[var(--border-color)] bg-[var(--hover-bg-subtle)] px-4 py-2 text-left text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]">
						Open vulnerability workspace
					</button>
				</div>
			</article>
		</div>
	</section>

	<section class="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
		{#each summaryMetrics as metric}
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
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">Portfolio risk hot spots</h2>
				<p class="text-sm text-[var(--text-tertiary)]">
					Focus remediation on the components exposing the highest blast radius across environments.
				</p>
			</div>
			<button type="button" class="rounded-full border border-[var(--border-color)] px-4 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]">
				Export prioritized list
			</button>
		</header>
		<div class="grid gap-4 lg:grid-cols-2">
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-5">
				<h3 class="text-sm font-semibold uppercase tracking-[0.28em] text-[var(--text-tertiary)]">Risk hot spots</h3>
				<ul class="mt-4 space-y-4 text-sm text-[var(--text-secondary)]">
					{#each riskHotspots as item}
						<li class="rounded-xl border border-[var(--border-color)]/50 bg-[var(--main-content-bg)]/60 px-4 py-3">
							<div class="flex flex-wrap items-center justify-between gap-2">
								<span class="font-medium text-[var(--text-bright)]">{item.service}</span>
								<span class="text-xs font-semibold" style={`color: ${item.severityColor}`}>{item.severity}</span>
							</div>
							<p class="mt-2 text-xs text-[var(--text-tertiary)]">{item.issue}</p>
							<div class="mt-3 flex flex-wrap items-center gap-3 text-[10px] uppercase tracking-[0.22em] text-[var(--text-muted)]">
								<span>{item.exposures}</span>
								<span>Remedy: {item.recommendedFix}</span>
							</div>
						</li>
					{/each}
				</ul>
			</div>
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-5">
				<h3 class="text-sm font-semibold uppercase tracking-[0.28em] text-[var(--text-tertiary)]">Recent SBOM activity</h3>
				<ul class="mt-4 space-y-4 text-sm text-[var(--text-secondary)]">
					{#each recentActivity as change}
						<li class="rounded-xl border border-[var(--border-color)]/50 bg-[var(--main-content-bg)]/60 px-4 py-3">
							<div class="flex flex-wrap items-center justify-between gap-2">
								<span class="font-medium text-[var(--text-bright)]">{change.sbom}</span>
								<span class="text-xs font-semibold" style={`color: ${change.accent}`}>{change.delta}</span>
							</div>
							<p class="mt-2 text-xs text-[var(--text-tertiary)]">{change.action}</p>
							<p class="mt-2 text-[10px] uppercase tracking-[0.26em] text-[var(--text-muted)]">{change.timestamp}</p>
						</li>
					{/each}
				</ul>
			</div>
		</div>
	</section>

	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
			<div class="space-y-1">
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">License & coverage status</h2>
				<p class="text-sm text-[var(--text-tertiary)]">
					Track outstanding license obligations and ensure every product line ships with a complete SBOM.
				</p>
			</div>
			<button type="button" class="rounded-full border border-[var(--border-color)] px-4 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]">
				Open compliance workspace
			</button>
		</header>
		<div class="grid gap-4 lg:grid-cols-2">
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-5">
				<h3 class="text-sm font-semibold uppercase tracking-[0.28em] text-[var(--text-tertiary)]">License alerts</h3>
				<ul class="mt-4 space-y-4 text-sm text-[var(--text-secondary)]">
					{#each licenseAlerts as alert}
						<li class="rounded-xl border border-[var(--border-color)]/50 bg-[var(--main-content-bg)]/60 px-4 py-3">
							<div class="flex flex-wrap items-center justify-between gap-2">
								<span class="font-medium text-[var(--text-bright)]">{alert.packageName}</span>
								<span class="text-xs font-semibold" style={`color: ${alert.statusColor}`}>{alert.status}</span>
							</div>
							<p class="mt-2 text-xs text-[var(--text-tertiary)]">{alert.issue}</p>
							<p class="mt-2 text-[10px] uppercase tracking-[0.24em] text-[var(--text-muted)]">Next step: {alert.action}</p>
						</li>
					{/each}
				</ul>
			</div>
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-5">
				<h3 class="text-sm font-semibold uppercase tracking-[0.28em] text-[var(--text-tertiary)]">Coverage highlights</h3>
				<ul class="mt-4 space-y-4 text-sm text-[var(--text-secondary)]">
					{#each coverageHighlights as highlight}
						<li class="rounded-xl border border-[var(--border-color)]/50 bg-[var(--main-content-bg)]/60 px-4 py-3">
							<div class="flex items-center justify-between gap-3">
								<span class="font-medium text-[var(--text-bright)]">{highlight.label}</span>
								<span class="text-lg font-semibold" style={`color: ${highlight.trendColor}`}>{highlight.value}</span>
							</div>
							<p class="mt-2 text-xs text-[var(--text-tertiary)]">Trend {highlight.trend}</p>
						</li>
					{/each}
				</ul>
			</div>
		</div>
	</section>
</div>
