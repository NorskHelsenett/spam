<script lang="ts">
	const alerts = [
		{
			id: 'alert-5841',
			title: 'Critical CVE detected',
			detail: 'openssl 3.0.1 (CVE-2023-0466) impacting checkout-service@8.4.2.',
			severity: 'Critical',
			tone: 'var(--error)'
		},
		{
			id: 'alert-5837',
			title: 'License policy violation',
			detail: 'GPL-3.0 dependency introduced in analytics-job via chartjs 4.4.1.',
			severity: 'Warning',
			tone: 'var(--warning)'
		},
		{
			id: 'alert-5828',
			title: 'SBOM freshness restored',
			detail: 'billing-worker@4.9.0 SBOM updated — now within 30m SLA.',
			severity: 'Info',
			tone: 'var(--info)'
		}
	];

	const filters = ['All', 'Critical', 'Warning', 'Info'];
</script>

<svelte:head>
	<title>Alerts • Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">Alert center</h1>
				<p class="text-sm text-[var(--text-tertiary)]">
					Supply-chain policy events, vulnerability gates, and compliance notifications surface here.
				</p>
			</div>
			<div class="flex flex-wrap gap-2 text-sm text-[var(--text-secondary)]">
				{#each filters as filter}
					<button type="button" class="rounded-full border border-[var(--border-color)] px-4 py-2 transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]">
						{filter}
					</button>
				{/each}
			</div>
		</header>
		<div class="space-y-3">
			{#each alerts as alert}
				<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/45 px-5 py-4 text-sm text-[var(--text-secondary)]">
					<div class="flex flex-wrap items-center justify-between gap-3">
						<div>
							<p class="font-semibold text-[var(--text-bright)]">{alert.title}</p>
							<p class="text-xs text-[var(--text-tertiary)]">{alert.detail}</p>
						</div>
						<span class="inline-flex items-center gap-2 rounded-full border border-[var(--border-color)] px-3 py-1 text-xs font-semibold" style={`color: ${alert.tone}`}>{alert.severity}</span>
					</div>
					<p class="mt-3 text-[10px] uppercase tracking-[0.28em] text-[var(--text-muted)]">ID {alert.id}</p>
				</div>
			{/each}
		</div>
	</section>

	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<h2 class="text-xl font-semibold text-[var(--text-bright)]">Delivery settings</h2>
		<p class="text-sm text-[var(--text-tertiary)]">
			Configure web push, email digests, or webhook fan-out once integrations are ready. This block is a placeholder for the eventual settings form.
		</p>
		<div class="grid gap-3 text-sm text-[var(--text-secondary)] sm:grid-cols-2">
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/35 px-4 py-4">
				<h3 class="font-semibold text-[var(--text-bright)]">Push notifications</h3>
				<p class="mt-2 text-xs text-[var(--text-tertiary)]">Service worker registration pending setup.</p>
			</div>
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/35 px-4 py-4">
				<h3 class="font-semibold text-[var(--text-bright)]">Email digests</h3>
				<p class="mt-2 text-xs text-[var(--text-tertiary)]">Connect SMTP or transactional provider to begin.</p>
			</div>
		</div>
	</section>
</div>
