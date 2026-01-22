<script lang="ts">
	const collections = [
		{
			name: 'Payments platform',
			sboms: 6,
			description: 'Checkout, billing, and ledger workloads under PCI scope.',
			tag: 'Critical risk surface',
			accent: 'var(--error)'
		},
		{
			name: 'Customer experience',
			sboms: 8,
			description: 'Frontend applications and public APIs served globally.',
			tag: 'SLO-bound services',
			accent: 'var(--accent)'
		},
		{
			name: 'Data and analytics',
			sboms: 5,
			description: 'Batch pipelines and ML training environments.',
			tag: 'Regulated datasets',
			accent: 'var(--info)'
		}
	];

	const sbomRows = [
		{
			artifact: 'checkout-service@8.4.2',
			format: 'CycloneDX JSON',
			components: 412,
			critical: 2,
			high: 5,
			licenseAlerts: 1,
			lastUpdated: '5 minutes ago',
			status: 'Policy block',
			statusColor: 'var(--error)'
		},
		{
			artifact: 'billing-worker@4.9.0',
			format: 'SPDX 2.3',
			components: 267,
			critical: 0,
			high: 3,
			licenseAlerts: 0,
			lastUpdated: '22 minutes ago',
			status: 'Ready for deploy',
			statusColor: 'var(--success)'
		},
		{
			artifact: 'mobile-app@12.3.1',
			format: 'CycloneDX JSON',
			components: 163,
			critical: 1,
			high: 4,
			licenseAlerts: 2,
			lastUpdated: '41 minutes ago',
			status: 'Legal review pending',
			statusColor: 'var(--warning)'
		},
		{
			artifact: 'analytics-job@4.2.0',
			format: 'SPDX 2.3',
			components: 508,
			critical: 0,
			high: 1,
			licenseAlerts: 0,
			lastUpdated: 'Today 03:12 UTC',
			status: 'Ingest complete',
			statusColor: 'var(--accent)'
		},
		{
			artifact: 'edge-appliance@2.8.1',
			format: 'CycloneDX XML',
			components: 298,
			critical: 1,
			high: 2,
			licenseAlerts: 0,
			lastUpdated: 'Yesterday 18:44 UTC',
			status: 'Awaiting VEX update',
			statusColor: 'var(--info)'
		}
	];

	const policyRuns = [
		{
			name: 'Open source license policy',
			status: 'Pass',
			statusColor: 'var(--success)',
			updated: '12 minutes ago',
			details: 'MIT/Apache-2.0 baseline enforced pre-merge.'
		},
		{
			name: 'Critical CVE gate',
			status: 'Failing',
			statusColor: 'var(--error)',
			updated: '18 minutes ago',
			details: 'Blocked checkout-service deploy (2 critical CVEs).'
		},
		{
			name: 'SBOM freshness SLA',
			status: 'Pass',
			statusColor: 'var(--accent)',
			updated: '47 minutes ago',
			details: '33/36 pipelines delivering SBOMs < 30 minutes old.'
		}
	];

	const ingestionCoverage = [
		{
			label: 'GitHub Actions pipelines',
			scope: '13 repositories',
			status: 'Healthy',
			statusColor: 'var(--success)',
			details: 'SBOM export and VEX upload on every release tag.'
		},
		{
			label: 'Jenkins nightly builds',
			scope: '5 jobs',
			status: 'Degraded',
			statusColor: 'var(--warning)',
			details: 'One pipeline missing SBOM due to dependency cache miss.'
		},
		{
			label: 'Manual uploads',
			scope: '4 artefacts',
			status: 'Needs automation',
			statusColor: 'var(--info)',
			details: 'Teams onboarding to automated export next sprint.'
		}
	];

	let uploadOpen = $state(false);
	let uploadError = $state('');
	let uploadSuccess = $state('');
	let uploadBusy = $state(false);
	let uploadFile: File | null = $state(null);
	let uploadForm = $state({
		provider: 'manual',
		org: '',
		slug: '',
		commitSha: '',
		ref: '',
		format: ''
	});

	const submitUpload = async () => {
		uploadError = '';
		uploadSuccess = '';

		if (!uploadFile) {
			uploadError = 'Please select an SBOM file.';
			return;
		}
		if (!uploadForm.commitSha.trim()) {
			uploadError = 'Commit SHA is required.';
			return;
		}
		if (!uploadForm.org.trim() || !uploadForm.slug.trim()) {
			uploadError = 'Org and repo name are required.';
			return;
		}

		uploadBusy = true;

		try {
			const payload = new FormData();
			payload.append('sbom_file', uploadFile);
			payload.append('provider', uploadForm.provider.trim());
			payload.append('org', uploadForm.org.trim());
			payload.append('slug', uploadForm.slug.trim());
			payload.append('commit_sha', uploadForm.commitSha.trim());
			if (uploadForm.ref.trim()) {
				payload.append('ref', uploadForm.ref.trim());
			}
			if (uploadForm.format.trim()) {
				payload.append('format', uploadForm.format.trim());
			}

			const response = await fetch('/api/sboms/upload', {
				method: 'POST',
				credentials: 'include',
				body: payload
			});

			if (!response.ok) {
				uploadError = 'Upload failed. Check the SBOM and repo details.';
				return;
			}

			uploadSuccess = 'SBOM uploaded and queued for parsing.';
			uploadFile = null;
			uploadForm = { ...uploadForm, commitSha: '', ref: '', format: '' };
		} catch {
			uploadError = 'Upload failed. Try again.';
		} finally {
			uploadBusy = false;
		}
	};
</script>

<svelte:head>
	<title>SBOM Library • Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">SBOM library</h1>
				<p class="text-sm text-[var(--text-tertiary)]">Curated view of every artefact tracked across your software supply chain.</p>
			</div>
			<button
				type="button"
				class="rounded-full border border-[var(--border-color)] px-4 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
				onclick={() => {
					uploadOpen = true;
					uploadError = '';
					uploadSuccess = '';
				}}
			>
				Upload SBOM
			</button>
		</header>
		<div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
			{#each collections as collection}
				<article class="metric-card p-5 sm:p-6">
					<div class="flex items-center justify-between gap-3">
						<h2 class="text-lg font-semibold text-[var(--text-bright)]">{collection.name}</h2>
						<span class="text-2xl font-bold" style={`color: ${collection.accent}`}>{collection.sboms}</span>
					</div>
					<p class="mt-2 text-sm text-[var(--text-secondary)]">{collection.description}</p>
					<span class="mt-4 inline-flex items-center gap-2 rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-tertiary)]">{collection.tag}</span>
				</article>
			{/each}
		</div>
	</section>

	{#if uploadOpen}
		<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4">
			<div class="w-full max-w-xl rounded-3xl border border-[var(--border-color)] bg-[var(--main-content-bg)] p-6 shadow-2xl">
				<div class="flex items-start justify-between gap-4">
					<div>
						<h2 class="text-xl font-semibold text-[var(--text-bright)]">Upload SBOM</h2>
						<p class="mt-1 text-sm text-[var(--text-secondary)]">Attach an SBOM to a repo commit and enqueue parsing.</p>
					</div>
					<button
						type="button"
						class="rounded-full border border-[var(--border-color)] px-3 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
						onclick={() => (uploadOpen = false)}
					>
						Close
					</button>
				</div>

				<div class="mt-6 grid gap-4">
					<label class="flex flex-col gap-2 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
						SBOM file
						<input
							type="file"
							accept=".json,application/json"
							class="rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 text-sm text-[var(--text-secondary)]"
							onchange={(event) => {
								const target = event.target as HTMLInputElement;
								uploadFile = target.files ? target.files[0] : null;
							}}
						/>
					</label>

					<div class="grid gap-4 sm:grid-cols-2">
						<label class="flex flex-col gap-2 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
							Org
							<input
								type="text"
								placeholder="team"
								class="rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 text-sm text-[var(--text-secondary)]"
								bind:value={uploadForm.org}
							/>
						</label>
						<label class="flex flex-col gap-2 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
							Repo
							<input
								type="text"
								placeholder="service-api"
								class="rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 text-sm text-[var(--text-secondary)]"
								bind:value={uploadForm.slug}
							/>
						</label>
					</div>

					<div class="grid gap-4 sm:grid-cols-2">
						<label class="flex flex-col gap-2 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
							Commit SHA
							<input
								type="text"
								placeholder="Full SHA"
								class="rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 text-sm text-[var(--text-secondary)]"
								bind:value={uploadForm.commitSha}
							/>
						</label>
						<label class="flex flex-col gap-2 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
							Ref (optional)
							<input
								type="text"
								placeholder="refs/heads/main"
								class="rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 text-sm text-[var(--text-secondary)]"
								bind:value={uploadForm.ref}
							/>
						</label>
					</div>

					<div class="grid gap-4 sm:grid-cols-2">
						<label class="flex flex-col gap-2 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
							Provider
							<input
								type="text"
								placeholder="manual"
								class="rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 text-sm text-[var(--text-secondary)]"
								bind:value={uploadForm.provider}
							/>
						</label>
						<label class="flex flex-col gap-2 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
							Format (optional)
							<input
								type="text"
								placeholder="cyclonedx-json"
								class="rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 text-sm text-[var(--text-secondary)]"
								bind:value={uploadForm.format}
							/>
						</label>
					</div>

					{#if uploadError}
						<p class="text-sm text-[var(--error)]">{uploadError}</p>
					{/if}
					{#if uploadSuccess}
						<p class="text-sm text-[var(--success)]">{uploadSuccess}</p>
					{/if}

					<div class="flex flex-wrap items-center justify-end gap-3">
						<button
							type="button"
							class="rounded-full border border-[var(--border-color)] px-4 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]"
							onclick={() => (uploadOpen = false)}
						>
							Cancel
						</button>
						<button
							type="button"
							class="rounded-full border border-transparent bg-[var(--accent)] px-5 py-2 text-sm font-semibold text-[var(--main-content-bg)] transition hover:opacity-90 disabled:opacity-50"
							disabled={uploadBusy}
							onclick={submitUpload}
						>
							{uploadBusy ? 'Uploading…' : 'Upload'}
						</button>
					</div>
				</div>
			</div>
		</div>
	{/if}

	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">SBOM inventory</h2>
			<div class="flex flex-wrap gap-3 text-sm text-[var(--text-secondary)]">
				<span class="rounded-full border border-[var(--border-color)] px-3 py-1">Filter: critical CVEs</span>
				<span class="rounded-full border border-[var(--border-color)] px-3 py-1">Format: CycloneDX</span>
			</div>
		</header>
		<div class="overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
			<table class="min-w-full divide-y divide-[var(--border-color)]/60 text-sm">
				<thead class="text-xs uppercase tracking-[0.28em] text-[var(--text-tertiary)]">
					<tr>
						<th class="px-5 py-3 text-left">Artefact</th>
						<th class="px-5 py-3 text-left">Format</th>
						<th class="px-5 py-3 text-left">Components</th>
						<th class="px-5 py-3 text-left">Critical</th>
						<th class="px-5 py-3 text-left">High</th>
						<th class="px-5 py-3 text-left">License alerts</th>
						<th class="px-5 py-3 text-left">Last updated</th>
						<th class="px-5 py-3 text-left">Status</th>
					</tr>
				</thead>
				<tbody class="divide-y divide-[var(--border-color)]/40 text-[var(--text-secondary)]">
					{#each sbomRows as row}
						<tr class="transition hover:bg-[var(--hover-bg-subtle)] hover:text-[var(--text-bright)]">
							<td class="px-5 py-3 font-semibold text-[var(--text-bright)]">{row.artifact}</td>
							<td class="px-5 py-3">{row.format}</td>
							<td class="px-5 py-3">{row.components}</td>
							<td class="px-5 py-3 font-semibold" style={`color: ${row.critical > 0 ? 'var(--error)' : 'var(--text-secondary)'}`}>{row.critical}</td>
							<td class="px-5 py-3 font-semibold" style={`color: ${row.high > 0 ? 'var(--warning)' : 'var(--text-secondary)'}`}>{row.high}</td>
							<td class="px-5 py-3 font-semibold" style={`color: ${row.licenseAlerts > 0 ? 'var(--info)' : 'var(--text-secondary)'}`}>{row.licenseAlerts}</td>
							<td class="px-5 py-3 text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">{row.lastUpdated}</td>
							<td class="px-5 py-3">
								<span class="inline-flex items-center gap-2 rounded-full border border-[var(--border-color)] px-3 py-1 text-xs" style={`color: ${row.statusColor}`}>{row.status}</span>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
		<p class="text-xs text-[var(--text-tertiary)]">Connect this table to your inventory service to surface live SBOM telemetry.</p>
	</section>

	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">Compliance and ingestion</h2>
			<button type="button" class="rounded-full border border-[var(--border-color)] px-4 py-2 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-bright)]">
				View policy workspace
			</button>
		</header>
		<div class="grid gap-4 lg:grid-cols-2">
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-5">
				<h3 class="text-sm font-semibold uppercase tracking-[0.28em] text-[var(--text-tertiary)]">Policy runs</h3>
				<ul class="mt-4 space-y-4 text-sm text-[var(--text-secondary)]">
					{#each policyRuns as run}
						<li class="rounded-xl border border-[var(--border-color)]/50 bg-[var(--main-content-bg)]/60 px-4 py-3">
							<div class="flex flex-wrap items-center justify-between gap-2">
								<span class="font-medium text-[var(--text-bright)]">{run.name}</span>
								<span class="text-xs font-semibold" style={`color: ${run.statusColor}`}>{run.status}</span>
							</div>
							<p class="mt-2 text-xs text-[var(--text-tertiary)]">{run.details}</p>
							<p class="mt-2 text-[10px] uppercase tracking-[0.24em] text-[var(--text-muted)]">Updated {run.updated}</p>
						</li>
					{/each}
				</ul>
			</div>
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-5">
				<h3 class="text-sm font-semibold uppercase tracking-[0.28em] text-[var(--text-tertiary)]">Ingestion coverage</h3>
				<ul class="mt-4 space-y-4 text-sm text-[var(--text-secondary)]">
					{#each ingestionCoverage as item}
						<li class="rounded-xl border border-[var(--border-color)]/50 bg-[var(--main-content-bg)]/60 px-4 py-3">
							<div class="flex flex-wrap items-center justify-between gap-2">
								<span class="font-medium text-[var(--text-bright)]">{item.label}</span>
								<span class="text-xs font-semibold" style={`color: ${item.statusColor}`}>{item.status}</span>
							</div>
							<p class="mt-2 text-xs text-[var(--text-tertiary)]">{item.details}</p>
							<p class="mt-2 text-[10px] uppercase tracking-[0.24em] text-[var(--text-muted)]">Coverage: {item.scope}</p>
						</li>
					{/each}
				</ul>
			</div>
		</div>
	</section>
</div>
