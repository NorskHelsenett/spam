<script lang="ts">
	import Loading from '$lib/components/Loading.svelte';
	import DonutChart from '$lib/components/DonutChart.svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import Select from '$lib/components/Select.svelte';
	import MultiSelect from '$lib/components/MultiSelect.svelte';
	import Markdown from '$lib/components/Markdown.svelte';
	import Dialog from '$lib/components/Dialog.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import DependencyDetail from '$lib/components/DependencyDetail.svelte';
	import HealthStatus from '$lib/components/HealthStatus.svelte';
	import Toggle from '$lib/components/Toggle.svelte';
	import Checkbox from '$lib/components/Checkbox.svelte';
	import Radio from '$lib/components/Radio.svelte';
	import ButtonGroup from '$lib/components/ButtonGroup.svelte';
	import ContributorAvatars from '$lib/components/ContributorAvatars.svelte';
	import UserHoverCard from '$lib/components/UserHoverCard.svelte';
	import TriageFinding from '$lib/components/TriageFinding.svelte';
	import Eye from 'lucide-svelte/icons/eye';
	import EyeOff from 'lucide-svelte/icons/eye-off';
	import RotateCw from 'lucide-svelte/icons/rotate-cw';
	import Download from 'lucide-svelte/icons/download';
	import ChevronDown from 'lucide-svelte/icons/chevron-down';
	import Trash2 from 'lucide-svelte/icons/trash-2';
	import AlertTriangle from 'lucide-svelte/icons/alert-triangle';
	import CheckCircle from 'lucide-svelte/icons/check-circle';
	import Info from 'lucide-svelte/icons/info';
	import Send from 'lucide-svelte/icons/send';

	import {
		mockDonut,
		mockMarkdown,
		mockDependency,
		mockTextSamples,
		mockColorSwatches,
		mockSemanticSwatches,
		mockPaletteGroups,
		mockTabs
	} from './fixtures';

	const metricCards = [
		{ label: 'Active runs', value: '12', meta: '+2 since last hour' },
		{ label: 'SBOMs processed', value: '1,243', meta: '98.4% success rate' },
		{ label: 'Secrets found', value: '0', meta: 'No new alerts' },
		{ label: 'Providers', value: '4', meta: '2 private, 2 public' }
	];

	let tabValue = $state(mockTabs[0].value);
	let dialogOpen = $state(false);
	let dependencyOpen = $state(false);

	// ConfirmDialog demos
	let confirmBasicOpen = $state(false);
	let confirmDangerOpen = $state(false);
	let confirmPublishOpen = $state(false);
	let confirmPublishLoading = $state(false);
	let confirmLastResult = $state('');

	const simulateAsync = async (label: string, dialogSetter: (v: boolean) => void) => {
		confirmPublishLoading = true;
		await new Promise((r) => setTimeout(r, 1200));
		confirmPublishLoading = false;
		dialogSetter(false);
		confirmLastResult = label;
		setTimeout(() => { confirmLastResult = ''; }, 3000);
	};
	let page = $state(1);
	let loadingPage = $state(false);

	const totalCount = 128;
	const pageSize = 25;
	const hasNextPage = $derived(page * pageSize < totalCount);

	let inputValue = $state('Observability');
	let emailValue = $state('ops@acme.co');
	let passwordValue = $state('hunter2');
	let showPassword = $state(false);
	let textareaValue = $state('Add more context for this run.');
	let selectValue = $state('weekly');
	let radioValue = $state('alpha');
	let rangeValue = $state(42);
	let checkboxValue = $state(true);
	let toggleValue = $state(true);
	let multiSelectValue: string[] = $state(['github']);
	let multiSelectEmptyValue: string[] = $state([]);
	const multiSelectOptions = [
		{ value: 'github', label: 'GitHub' },
		{ value: 'gitlab', label: 'GitLab' },
		{ value: 'gitea', label: 'Gitea' },
		{ value: 'bitbucket', label: 'Bitbucket' },
		{ value: 'azure', label: 'Azure DevOps', disabled: true }
	];
	const multiSelectSecretTypes = [
		{ value: 'generic-api-key', label: 'generic-api-key' },
		{ value: 'private-key', label: 'private-key' },
		{ value: 'jwt', label: 'jwt' },
		{ value: 'aws-access-key', label: 'aws-access-key' },
		{ value: 'github-pat', label: 'github-pat' },
		{ value: 'slack-token', label: 'slack-token' }
	];
	let multiSelectTypesValue: string[] = $state(['jwt', 'private-key']);
	const mockContributors = [
		{ login: 'jonasbg', name: 'Jonas', email: 'jonas@example.com', avatar_url: 'https://avatars.githubusercontent.com/u/1508560?v=4', contributions: 142 },
		{ login: 'dependabot[bot]', name: 'Dependabot', avatar_url: 'https://avatars.githubusercontent.com/in/29110?v=4', contributions: 87 },
		{ login: 'alice', name: 'Alice Smith', email: 'alice@example.com', contributions: 34 },
		{ login: 'bob', name: 'Bob', contributions: 12 },
	];
	// Triage finding rows — mock data so the row design can be previewed
	// in isolation (it's driven live on the home dashboard).
	const mockFindings = [
		{
			assetType: 'repo',
			assetSlug: 'platform/auth-service',
			trustGrade: 'D',
			href: '#',
			primaryAction: 'Rotate 2 leaked secrets now',
			reasons: [
				{ label: '2 active secrets', cls: 'pill pill-error' },
				{ label: '3 KEV CVEs', cls: 'pill pill-error' },
				{ label: 'EPSS 71%', cls: 'pill pill-warning' }
			]
		},
		{
			assetType: 'image',
			assetSlug: 'registry.acme.io/api-gateway:1.4.2',
			trustGrade: 'C',
			href: '#',
			primaryAction: 'Upgrade to clear 4 critical CVEs',
			reasons: [
				{ label: '4 Critical (fix avail.)', cls: 'pill pill-warning' },
				{ label: 'Unsigned image', cls: 'pill pill-neutral' }
			]
		},
		{
			assetType: 'cluster',
			assetSlug: 'prod-eu-north-1',
			trustGrade: 'B',
			href: '#',
			primaryAction: 'Re-scan — results are 41 days stale',
			reasons: [{ label: 'Scan 41d old', cls: 'pill pill-warning' }]
		}
	];
	let triageDemoOpen = $state(true);
	let buttonGroupValue = $state('3600');
	let fileList = $state<FileList | null>(null);
	let refreshing = $state(false);
	let splitDropdownOpen = $state(false);
	let splitBtnEl: HTMLDivElement | undefined = $state();

	$effect(() => {
		if (!splitDropdownOpen) return;
		const handler = (e: MouseEvent) => {
			if (splitBtnEl && !splitBtnEl.contains(e.target as Node)) splitDropdownOpen = false;
		};
		document.addEventListener('mousedown', handler);
		return () => document.removeEventListener('mousedown', handler);
	});
	let componentsLoading = $state(true);

	$effect(() => {
		const t = setTimeout(() => (componentsLoading = false), 800);
		return () => clearTimeout(t);
	});

	const handleRefresh = async () => {
		if (refreshing) return;
		refreshing = true;
		await new Promise((r) => setTimeout(r, 400)); // simulated fetch
		setTimeout(() => { refreshing = false; }, 1000);
	};

	const selectOptions = [
		{ value: 'daily', label: 'Daily' },
		{ value: 'weekly', label: 'Weekly' },
		{ value: 'monthly', label: 'Monthly' }
	];

	const scrapeIntervalOptions = [
		{ value: '0', label: 'Off' },
		{ value: '900', label: '15 min' },
		{ value: '3600', label: '1 hour' },
		{ value: '21600', label: '6 hours' },
		{ value: '86400', label: '24 hours' }
	];


	const goPrevious = () => {
		if (page <= 1 || loadingPage) return;
		loadingPage = true;
		setTimeout(() => {
			page -= 1;
			loadingPage = false;
		}, 200);
	};

	const goNext = () => {
		if (!hasNextPage || loadingPage) return;
		loadingPage = true;
		setTimeout(() => {
			page += 1;
			loadingPage = false;
		}, 200);
	};
</script>

<svelte:head>
	<title>Component Playground - SPAM</title>
</svelte:head>

<div class="space-y-10 pb-20">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h1 class="text-2xl font-semibold text-[var(--text-bright)] sm:text-3xl">UI Playground</h1>
				<p class="text-sm text-[var(--text-tertiary)]">
					All base elements, tokens, and components live here for fast visual regression checks.
				</p>
			</div>
			<div class="flex items-center gap-2 text-xs text-[var(--text-muted)]">
				<span class="rounded-full border border-[var(--border-color)] px-2 py-1">/playground</span>
				<span class="rounded-full border border-[var(--border-color)] px-2 py-1">Theme aware</span>
			</div>
		</header>

		<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
			{#each metricCards as card (card.label)}
				<div class="metric-card rounded-2xl border border-[var(--border-color)]/60 p-4">
					<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">{card.label}</p>
					<p class="mt-3 text-2xl font-semibold text-[var(--text-bright)]">{card.value}</p>
					<p class="mt-1 text-xs text-[var(--text-tertiary)]">{card.meta}</p>
				</div>
			{/each}
		</div>
	</section>

	<section class="panel-surface space-y-8 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">Typography and Text Scale</h2>
			<p class="text-sm text-[var(--text-tertiary)]">Tokenized sizing and text styles used across the UI.</p>
		</header>
		<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
			{#each mockTextSamples as sample (sample.label)}
				<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
					<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">{sample.label}</p>
					<p class={`mt-2 ${sample.className} text-[var(--text-bright)]`}>{sample.sample}</p>
					<p class="mt-2 text-xs text-[var(--text-tertiary)]">The quick brown fox jumps over the lazy dog.</p>
				</div>
			{/each}
		</div>
		<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
			<p class="text-sm text-[var(--text-secondary)]">
				Inline styles: <span class="font-semibold text-[var(--text-bright)]">bold text</span>,
				<span class="italic">italic text</span>, <span class="underline">underlined</span>,
				<span class="line-through text-[var(--text-muted)]">struck</span>,
				<mark class="rounded bg-[var(--warning)] px-1 text-[var(--text-bright)]">highlighted</mark>,
				and <code class="rounded bg-[var(--hover-bg)] px-1">inline code</code>.
			</p>
			<p class="mt-3 text-xs text-[var(--text-muted)]">
				Shortcuts: <span class="kbd">Cmd</span> <span class="kbd">Shift</span> <span class="kbd">P</span>
			</p>
		</div>
	</section>

	<section class="panel-surface space-y-8 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">Color Tokens</h2>
			<p class="text-sm text-[var(--text-tertiary)]">Background, text, and semantic colors from the theme.</p>
		</header>
		<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
			{#each mockColorSwatches as swatch (swatch.varName)}
				<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
					<div class="h-12 rounded-xl" style={`background: var(${swatch.varName});`}></div>
					<p class="mt-3 text-sm font-medium text-[var(--text-bright)]">{swatch.label}</p>
					<p class="text-xs text-[var(--text-tertiary)]">{swatch.varName}</p>
				</div>
			{/each}
		</div>
		<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
			{#each mockSemanticSwatches as swatch (swatch.varName)}
				<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
					<div class="h-12 rounded-xl" style={`background: var(${swatch.varName});`}></div>
					<p class="mt-3 text-sm font-medium text-[var(--text-bright)]">{swatch.label}</p>
					<p class="text-xs text-[var(--text-tertiary)]">{swatch.varName}</p>
				</div>
			{/each}
		</div>
		<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
			{#each mockPaletteGroups as group (group.name)}
				<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
					<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">{group.name}</p>
					<div class="mt-3 grid grid-cols-2 gap-3">
						{#each group.variants as variant (variant.varName)}
							<div>
								<div class="h-10 rounded-lg" style={`background: var(${variant.varName});`}></div>
								<p class="mt-2 text-xs text-[var(--text-tertiary)]">{variant.label}</p>
							</div>
						{/each}
					</div>
				</div>
			{/each}
		</div>
	</section>

	<section class="panel-surface space-y-8 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">Buttons and Status</h2>
			<p class="text-sm text-[var(--text-tertiary)]">Common button treatments, badges, and hover states.</p>
		</header>
		<div class="flex flex-wrap items-center gap-3">
			<button type="button" class="btn btn-primary">Primary</button>
			<button type="button" class="btn btn-secondary">Secondary</button>
			<button type="button" class="btn btn-ghost">Ghost</button>
			<button type="button" class="btn btn-primary" disabled>Disabled</button>
			<button type="button" class="btn btn-outline">Outline</button>
			<!-- Split button: single pill, left = primary action, right = darker dropdown trigger -->
			<div class="relative" bind:this={splitBtnEl}>
				<div class="flex overflow-hidden rounded-[999px] border border-[var(--border-color)] bg-[var(--hover-bg)]">
					<button type="button"
						class="flex items-center gap-2 px-[1.1rem] py-[0.55rem] text-[0.85rem] font-semibold tracking-[0.02em] text-[var(--text-bright)] transition hover:brightness-110"
						onclick={() => {}}>
						<Download class="h-4 w-4" /> Export CSV
					</button>
					<div class="w-px self-stretch bg-[var(--border-color)]"></div>
					<button type="button"
						class="flex items-center bg-black/[0.06] px-3 py-[0.55rem] text-[var(--text-bright)] transition hover:bg-black/[0.12]"
						onclick={() => (splitDropdownOpen = !splitDropdownOpen)} aria-label="More options">
						<ChevronDown class="h-4 w-4" />
					</button>
				</div>
				{#if splitDropdownOpen}
					<div class="absolute left-0 top-full z-30 mt-1 w-52 overflow-hidden rounded-xl border border-[var(--border-color)] bg-[var(--bg-soft)] py-1 shadow-xl">
						<p class="px-3.5 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Section label</p>
						<button type="button"
							class="flex w-full items-center gap-2 px-3.5 py-2 text-left text-[12px] text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)]"
							onclick={() => (splitDropdownOpen = false)}>
							<Download class="h-3 w-3 shrink-0 text-[var(--accent)]" /> Option A
						</button>
						<div class="mx-3 my-1 border-t border-[var(--border-color)]/60"></div>
						<p class="px-3.5 pb-1 pt-1 text-[10px] font-semibold uppercase tracking-wider text-[var(--text-muted)]">Another section</p>
						<button type="button"
							class="flex w-full items-center gap-2 px-3.5 py-2 text-left text-[12px] text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)]"
							onclick={() => (splitDropdownOpen = false)}>
							<Download class="h-3 w-3 shrink-0 text-[var(--accent)]" /> Option B
						</button>
						<button type="button"
							class="flex w-full cursor-not-allowed items-center gap-2 px-3.5 py-2 text-left text-[12px] text-[var(--text-muted)] opacity-50"
							disabled>
							<Download class="h-3 w-3 shrink-0 text-[var(--accent)]" /> Disabled option
						</button>
					</div>
				{/if}
			</div>
			<button
				type="button"
				class="mt-auto mb-4 ml-auto flex items-center gap-1.5 pt-5 text-[11px] font-medium transition-opacity hover:opacity-70"
				style="color: var(--accent);"
			>
				Open repository
				<svg
					xmlns="http://www.w3.org/2000/svg"
					width="11"
					height="11"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
					stroke-linecap="round"
					stroke-linejoin="round"
					class="lucide-icon lucide lucide-arrow-right"
				>
					<path d="M5 12h14"></path>
					<path d="m12 5 7 7-7 7"></path>
				</svg>
			</button>
			<!-- Canonical refresh button: spins during fetch + 1s after completion for organic feel -->
			<button type="button" class="btn btn-ghost" onclick={handleRefresh} disabled={refreshing}>
				<span class="inline-flex h-[14px] w-[14px] items-center justify-center {refreshing ? 'animate-spin' : ''}">
					<RotateCw size={14} />
				</span>
				Refresh
			</button>
		</div>
		<div class="flex flex-wrap items-center gap-2">
			<span class="pill pill-success">Success</span>
			<span class="pill pill-warning">Warning</span>
			<span class="pill pill-error">Error</span>
			<span class="pill pill-info">Info</span>
			<span class="pill pill-neutral">Neutral</span>
		</div>
		<div class="flex flex-wrap items-center gap-2">
			<span class="badge">Default</span>
			<span class="badge">Approved</span>
			<span class="badge">Pending</span>
			<span class="badge">Read-only</span>
		</div>
	</section>

	<section class="panel-surface space-y-8 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">Forms and Inputs</h2>
			<p class="text-sm text-[var(--text-tertiary)]">Text fields, selections, toggles, and validation states.</p>
		</header>
		<div class="grid gap-6 lg:grid-cols-2">
			<div class="space-y-4">
				<label for="input-text" class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Text</label>
				<input
					id="input-text"
					type="text"
					class="input"
					placeholder="Search..."
					bind:value={inputValue}
				/>

				<label for="input-email" class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Email</label>
				<input id="input-email" type="email" class="input" bind:value={emailValue} />

				<label for="input-password" class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Password</label>
				<div class="relative">
					<input
						id="input-password"
						type={showPassword ? 'text' : 'password'}
						class="input input-with-icon"
						bind:value={passwordValue}
					/>
					<button
						type="button"
						class="absolute right-3 top-1/2 -translate-y-1/2 rounded-full p-2 text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)]"
						onclick={() => (showPassword = !showPassword)}
						aria-label={showPassword ? 'Hide password' : 'Show password'}
					>
						{#if showPassword}
							<EyeOff size={14} />
						{:else}
							<Eye size={14} />
						{/if}
					</button>
				</div>

				<label for="input-textarea" class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Textarea</label>
				<textarea id="input-textarea" rows="3" class="input" bind:value={textareaValue}></textarea>
			</div>
			<div class="space-y-4">
				<span class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Select</span>
				<div class="flex items-center gap-3">
					<Select options={selectOptions} bind:value={selectValue} />
					<Select options={selectOptions} bind:value={selectValue} class="w-full" />
				</div>

				<span class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Multi Select</span>
				<div class="space-y-3">
					<div class="flex items-center gap-3">
						<MultiSelect options={multiSelectOptions} bind:selected={multiSelectValue} placeholder="Providers" />
						<MultiSelect options={multiSelectOptions} bind:selected={multiSelectEmptyValue} placeholder="None selected" />
					</div>
					<div class="flex items-center gap-3">
						<MultiSelect options={multiSelectSecretTypes} bind:selected={multiSelectTypesValue} placeholder="Secret types" size="sm" />
						<MultiSelect options={multiSelectOptions} bind:selected={multiSelectValue} placeholder="Providers" size="sm" class="w-full" />
					</div>
					<p class="text-xs text-[var(--text-tertiary)]">
						Providers: {multiSelectValue.length ? multiSelectValue.join(', ') : 'none'} · Types: {multiSelectTypesValue.length ? multiSelectTypesValue.join(', ') : 'none'}
					</p>
				</div>

				<span class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Radio</span>
				<div class="flex flex-wrap gap-4">
					<Radio name="phase" value="alpha" bind:group={radioValue} label="Alpha" />
					<Radio name="phase" value="beta" bind:group={radioValue} label="Beta" />
				</div>

				<span class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Checkbox</span>
				<Checkbox bind:checked={checkboxValue} label="Enable notifications" />

				<span class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Toggle</span>
				<Toggle bind:checked={toggleValue} label="Feature flag" />

				<span class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Button Group</span>
				<ButtonGroup options={scrapeIntervalOptions} bind:value={buttonGroupValue} />
				<p class="text-xs text-[var(--text-tertiary)]">Scrape interval: {buttonGroupValue === '0' ? 'Off' : scrapeIntervalOptions.find(o => o.value === buttonGroupValue)?.label}</p>

				<label for="input-range" class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Range</label>
				<input id="input-range" type="range" min="0" max="100" bind:value={rangeValue} />
				<p class="text-xs text-[var(--text-tertiary)]">Value: {rangeValue}</p>

				<label for="input-file" class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">File</label>
				<input id="input-file" type="file" class="input" bind:files={fileList} />
				{#if fileList && fileList.length > 0}
					<p class="text-xs text-[var(--text-tertiary)]">{fileList.length} file(s) selected</p>
				{/if}

				<label for="input-validation" class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Validation</label>
				<input id="input-validation" type="text" class="input input-error" value="Invalid value" />
			</div>
		</div>
	</section>

	<section class="panel-surface space-y-8 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">Components</h2>
			<p class="text-sm text-[var(--text-tertiary)]">Svelte components rendered with mock data.</p>
		</header>

		{#if componentsLoading}
			<Loading message="Loading components" variant="bar" size="sm" />
		{:else}
		<div class="grid gap-6 lg:grid-cols-3">
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Loading spinner</p>
				<Loading message="Syncing assets" variant="spinner" size="md" />
			</div>
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Loading bar</p>
				<Loading message="Indexing dependencies" variant="bar" size="sm" />
			</div>
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Loading circle</p>
				<div class="flex items-center justify-center py-5">
					<div class="h-8 w-8 animate-spin rounded-full border-2 border-[var(--accent)] border-t-transparent"></div>
				</div>
			</div>
		</div>

		<div class="grid gap-6 lg:grid-cols-3">
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Tab selector</p>
				<TabSelector options={mockTabs} bind:value={tabValue} />
				<p class="mt-2 text-xs text-[var(--text-tertiary)]">Selected: {tabValue}</p>
			</div>
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Pagination</p>
				<Pagination
					page={page}
					totalCount={totalCount}
					pageSize={pageSize}
					hasNextPage={hasNextPage}
					loading={loadingPage}
					onPrevious={goPrevious}
					onNext={goNext}
				/>
			</div>
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Donut chart</p>
				<DonutChart title={mockDonut.title} total={mockDonut.total} segments={mockDonut.segments} />
			</div>
		</div>

		<div class="grid gap-6 lg:grid-cols-2">
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Markdown</p>
				<Markdown content={mockMarkdown} class="max-w-none" />
			</div>
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Health status</p>
				<p class="mb-3 text-xs text-[var(--text-tertiary)]">Calls /api/healthz on mount.</p>
				<HealthStatus />
			</div>
		</div>

		<div class="grid gap-6 lg:grid-cols-2">
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Contributor Avatars</p>
				<p class="mb-3 text-xs text-[var(--text-tertiary)]">Hover for tooltip with email copy. Reusable across drawers.</p>
				<div class="space-y-4">
					<div>
						<p class="mb-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">4 contributors</p>
						<ContributorAvatars contributors={mockContributors} />
					</div>
					<div>
						<p class="mb-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">Max 2</p>
						<ContributorAvatars contributors={mockContributors} max={2} />
					</div>
					<div>
						<p class="mb-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">Single contributor</p>
						<ContributorAvatars contributors={[mockContributors[0]]} />
					</div>
					<div>
						<p class="mb-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">No avatar (fallback initials)</p>
						<ContributorAvatars contributors={[mockContributors[2], mockContributors[3]]} />
					</div>
				</div>
			</div>

			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">User Hover Card</p>
				<p class="mb-3 text-xs text-[var(--text-tertiary)]">Wrap any trigger (avatar, username, link) to reveal a user tip-card. Click the card to copy email.</p>
				<div class="space-y-4 text-sm text-[var(--text-secondary)]">
					<div>
						<p class="mb-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">Inline username</p>
						<p>
							Committed by
							<UserHoverCard user={mockContributors[0]}>
								<span class="font-medium text-[var(--accent)] hover:underline">@{mockContributors[0].login}</span>
							</UserHoverCard>
							2 days ago.
						</p>
					</div>
					<div>
						<p class="mb-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">Avatar trigger</p>
						<UserHoverCard user={mockContributors[1]}>
							<img
								src={mockContributors[1].avatar_url}
								alt={mockContributors[1].login}
								class="h-8 w-8 rounded-full ring-1 ring-[var(--border-color)]"
							/>
						</UserHoverCard>
					</div>
					<div>
						<p class="mb-1 text-[10px] uppercase tracking-wider text-[var(--text-muted)]">Fallback initial (no avatar, no email)</p>
						<UserHoverCard user={mockContributors[3]}>
							<span class="inline-flex items-center gap-1.5">
								<span class="flex h-6 w-6 items-center justify-center rounded-full bg-[var(--hover-bg)] text-[10px] font-semibold text-[var(--text-secondary)]">
									{mockContributors[3].name?.[0]}
								</span>
								<span class="text-xs">{mockContributors[3].name}</span>
							</span>
						</UserHoverCard>
					</div>
				</div>
			</div>
		</div>

		<!-- ConfirmDialog demos -->
		<div class="space-y-3">
			<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Confirm Dialog</p>
			<div class="flex flex-wrap gap-3">
				<button type="button" class="btn btn-secondary" onclick={() => (confirmBasicOpen = true)}>
					Basic (2 buttons)
				</button>
				<button type="button" class="btn btn-secondary" onclick={() => (confirmDangerOpen = true)}>
					Danger (2 buttons)
				</button>
				<button type="button" class="btn btn-secondary" onclick={() => (confirmPublishOpen = true)}>
					Publish (3 buttons)
				</button>
			</div>
			{#if confirmLastResult}
				<p class="text-xs text-[var(--success)]">→ {confirmLastResult}</p>
			{/if}
		</div>

		<!-- Basic confirm -->
		<ConfirmDialog
			bind:open={confirmBasicOpen}
			title="Save changes?"
			description="Your unsaved edits will be applied to the repository configuration."
			iconVariant="default"
			buttons={[
				{ label: 'Cancel', variant: 'ghost', onclick: () => { confirmBasicOpen = false; } },
				{ label: 'Save', variant: 'primary', onclick: () => { confirmBasicOpen = false; confirmLastResult = 'Saved'; setTimeout(() => { confirmLastResult = ''; }, 3000); } }
			]}
		>
			{#snippet icon()}<CheckCircle size={26} />{/snippet}
		</ConfirmDialog>

		<!-- Danger confirm -->
		<ConfirmDialog
			bind:open={confirmDangerOpen}
			title="Delete repository?"
			description="This action cannot be undone. All associated runs, SBOMs, and secrets will be permanently removed."
			iconVariant="danger"
			buttons={[
				{ label: 'Cancel', variant: 'ghost', onclick: () => { confirmDangerOpen = false; } },
				{ label: 'Delete', variant: 'danger', onclick: () => { confirmDangerOpen = false; confirmLastResult = 'Deleted'; setTimeout(() => { confirmLastResult = ''; }, 3000); } }
			]}
		>
			{#snippet icon()}<Trash2 size={26} />{/snippet}
		</ConfirmDialog>

		<!-- 3-button publish confirm with simulated async -->
		<ConfirmDialog
			bind:open={confirmPublishOpen}
			title="Publish report?"
			description="Choose how you'd like to proceed. Drafts can be edited at any time before publishing."
			iconVariant="info"
			buttons={[
				{ label: 'Cancel', variant: 'ghost', onclick: () => { confirmPublishOpen = false; }, disabled: confirmPublishLoading },
				{ label: 'Save Draft', variant: 'ghost', onclick: () => simulateAsync('Saved as draft', (v) => { confirmPublishOpen = v; }), loading: false, disabled: confirmPublishLoading },
				{ label: 'Publish', variant: 'primary', onclick: () => simulateAsync('Published!', (v) => { confirmPublishOpen = v; }), loading: confirmPublishLoading }
			]}
		>
			{#snippet icon()}<Send size={26} />{/snippet}
		</ConfirmDialog>

		<div class="grid gap-6 lg:grid-cols-2">
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Dialog</p>
				<button type="button" class="btn btn-secondary" onclick={() => (dialogOpen = true)}>
					Open dialog
				</button>
				<Dialog bind:open={dialogOpen}>
					<div class="flex h-full w-full flex-col">
						<div class="border-b border-[var(--border-color)] px-6 py-4">
							<h3 class="text-lg font-semibold text-[var(--text-bright)]">Dialog title</h3>
							<p class="text-xs text-[var(--text-tertiary)]">Secondary description goes here.</p>
						</div>
						<div class="space-y-3 px-6 py-5 text-sm text-[var(--text-secondary)]">
							<p>Dialogs use the shared layout to keep overlays consistent.</p>
							<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-3">
								<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Actions</p>
								<div class="mt-3 flex gap-2">
									<button type="button" class="btn btn-primary" onclick={() => (dialogOpen = false)}>
										Confirm
									</button>
									<button type="button" class="btn btn-ghost" onclick={() => (dialogOpen = false)}>
										Cancel
									</button>
								</div>
							</div>
						</div>
					</div>
				</Dialog>
			</div>
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Dependency detail</p>
				<p class="mb-3 text-xs text-[var(--text-tertiary)]">Opens live data when available.</p>
				<button type="button" class="btn btn-secondary" onclick={() => (dependencyOpen = true)}>
					Open dependency detail
				</button>
				<DependencyDetail
					bind:open={dependencyOpen}
					name={mockDependency.name}
					ecosystem={mockDependency.ecosystem}
					sources={mockDependency.sources}
				/>
			</div>
		</div>
		{/if}
	</section>

	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">Triage Finding Row</h2>
			<p class="text-sm text-[var(--text-tertiary)]">
				The row used on the home triage dashboard. Leads with the action to take; click a row to expand its drivers. No coloured edges — urgency reads from the reason pills.
			</p>
		</header>
		<div class="flex flex-col gap-2">
			<!-- Expanded example with a mock drivers panel. -->
			<TriageFinding
				assetType={mockFindings[0].assetType}
				assetSlug={mockFindings[0].assetSlug}
				trustGrade={mockFindings[0].trustGrade}
				href={mockFindings[0].href}
				primaryAction={mockFindings[0].primaryAction}
				reasons={mockFindings[0].reasons}
				open={triageDemoOpen}
				onToggle={() => (triageDemoOpen = !triageDemoOpen)}
				onAcknowledge={() => {}}
			>
				{#snippet detail()}
					<div class="space-y-2">
						<p class="text-[0.7rem] font-semibold uppercase tracking-[0.1em] text-[var(--text-tertiary)]">Leaked secrets to rotate (2)</p>
						<div class="rounded-xl border border-[var(--border-color)]/60 bg-[var(--card-bg)] p-3">
							<div class="flex flex-wrap items-center gap-2">
								<span class="pill pill-error">aws-access-key</span>
								<span class="font-mono text-xs text-[var(--text-tertiary)]">…a91f3c0d2e</span>
							</div>
							<p class="mt-1 text-sm text-[var(--text-secondary)]">
								<span class="font-semibold text-[var(--text-tertiary)]">Fix.</span> Rotate at the provider, then purge from git history.
							</p>
						</div>
					</div>
				{/snippet}
			</TriageFinding>

			<!-- Collapsed examples across asset types. -->
			{#each mockFindings.slice(1) as f (f.assetSlug)}
				<TriageFinding
					assetType={f.assetType}
					assetSlug={f.assetSlug}
					trustGrade={f.trustGrade}
					href={f.href}
					primaryAction={f.primaryAction}
					reasons={f.reasons}
					onToggle={() => {}}
					onAcknowledge={() => {}}
				/>
			{/each}

			<!-- Read-only (Acknowledge disabled). -->
			<TriageFinding
				assetType="repo"
				assetSlug="platform/legacy-cron"
				trustGrade="A"
				href="#"
				primaryAction="Generate an SBOM so it can be scanned"
				reasons={[{ label: 'No SBOM', cls: 'pill pill-neutral' }]}
				readOnly
				onToggle={() => {}}
				onAcknowledge={() => {}}
			/>
		</div>
	</section>

	<section class="panel-surface space-y-8 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">HTML Elements</h2>
			<p class="text-sm text-[var(--text-tertiary)]">Raw elements used across the app.</p>
		</header>
		<div class="grid gap-8 lg:grid-cols-2">
			<div class="space-y-4">
				<h1 class="text-2xl font-semibold text-[var(--text-bright)]">Heading 1</h1>
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">Heading 2</h2>
				<h3 class="text-lg font-semibold text-[var(--text-bright)]">Heading 3</h3>
				<h4 class="text-base font-semibold text-[var(--text-bright)]">Heading 4</h4>
				<h5 class="text-sm font-semibold text-[var(--text-bright)]">Heading 5</h5>
				<h6 class="text-xs font-semibold text-[var(--text-bright)]">Heading 6</h6>
				<p class="text-sm text-[var(--text-secondary)]">
					Paragraph with <a href="https://example.com" class="text-[var(--info)] underline">a link</a>,
					<strong>strong text</strong>, and <em>emphasis</em>.
				</p>
				<ul class="list-disc pl-5 text-sm text-[var(--text-secondary)]">
					<li>Unordered list item</li>
					<li>Second item</li>
				</ul>
				<ol class="list-decimal pl-5 text-sm text-[var(--text-secondary)]">
					<li>Ordered list item</li>
					<li>Second item</li>
				</ol>
				<blockquote class="border-l-4 border-[var(--accent)] bg-[var(--hover-bg)] px-4 py-3 text-sm text-[var(--text-tertiary)]">
					This is a blockquote used for notes or callouts.
				</blockquote>
				<hr class="border-[var(--border-color)]" />
				<pre class="rounded-xl border border-[var(--border-color)] bg-[var(--hover-bg)] p-4 text-xs text-[var(--text-secondary)]">
<code>const apiUrl = '/api/healthz';
console.log(apiUrl);</code>
				</pre>
			</div>
			<div class="space-y-4">
				<dl class="grid gap-2 text-sm text-[var(--text-secondary)]">
					<div class="grid grid-cols-3 gap-2">
						<dt class="text-[var(--text-tertiary)]">Status</dt>
						<dd class="col-span-2">Operational</dd>
					</div>
					<div class="grid grid-cols-3 gap-2">
						<dt class="text-[var(--text-tertiary)]">Region</dt>
						<dd class="col-span-2">us-west</dd>
					</div>
				</dl>
				<details class="rounded-xl border border-[var(--border-color)] bg-[var(--card-bg)]/40 p-4">
					<summary class="cursor-pointer text-sm text-[var(--text-bright)]">Details summary</summary>
					<p class="mt-2 text-sm text-[var(--text-secondary)]">Additional details appear here.</p>
				</details>
				<table class="min-w-full text-sm text-[var(--text-secondary)]">
					<thead class="text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]">
						<tr>
							<th class="px-3 py-2 text-left">Key</th>
							<th class="px-3 py-2 text-left">Value</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-[var(--border-color)]/60">
						<tr>
							<td class="px-3 py-2">Mode</td>
							<td class="px-3 py-2">Production</td>
						</tr>
						<tr>
							<td class="px-3 py-2">SSE</td>
							<td class="px-3 py-2">Enabled</td>
						</tr>
					</tbody>
				</table>
				<div class="space-y-2">
					<label for="input-progress" class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Progress</label>
					<progress id="input-progress" class="w-full" value="68" max="100"></progress>
					<label for="input-meter" class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Meter</label>
					<meter id="input-meter" class="w-full" min="0" max="100" low="30" high="80" optimum="90" value="72"></meter>
				</div>
					<figure class="rounded-xl border border-[var(--border-color)] bg-[var(--card-bg)]/40 p-4">
						<div class="placeholder-block h-28 w-full rounded-lg"></div>
						<figcaption class="mt-2 text-xs text-[var(--text-tertiary)]">Placeholder media block.</figcaption>
					</figure>
			</div>
		</div>
	</section>
</div>

<style>
	/* btn, pill, input classes are now global in app.css */

	progress,
	meter {
		appearance: none;
		height: 10px;
		border-radius: 999px;
		overflow: hidden;
		background: var(--bg2);
		border: 1px solid var(--border-color);
	}

	progress::-webkit-progress-bar {
		background: var(--bg2);
	}

	progress::-webkit-progress-value {
		background: var(--accent);
	}

	meter::-webkit-meter-bar {
		background: var(--bg2);
	}

	meter::-webkit-meter-optimum-value {
		background: var(--success);
	}

	input[type='range'] {
		appearance: none;
		width: 100%;
		height: 10px;
		border-radius: 999px;
		background: var(--bg2);
		border: 1px solid var(--border-color);
		cursor: pointer;
	}

	input[type='range']::-webkit-slider-thumb {
		appearance: none;
		width: 18px;
		height: 18px;
		border-radius: 999px;
		background: var(--accent);
		border: 2px solid var(--main-content-bg);
		box-shadow: 0 4px 10px rgba(0, 0, 0, 0.25);
		transition: transform 120ms ease;
		cursor: pointer;
	}

	input[type='range']::-webkit-slider-thumb:active {
		transform: scale(1.05);
	}

	input[type='range']::-moz-range-thumb {
		width: 18px;
		height: 18px;
		border-radius: 999px;
		background: var(--accent);
		border: 2px solid var(--main-content-bg);
		box-shadow: 0 4px 10px rgba(0, 0, 0, 0.25);
		transition: transform 120ms ease;
		cursor: pointer;
	}

	input[type='range']::-moz-range-thumb:active {
		transform: scale(1.05);
	}

	input[type='range']::-moz-range-track {
		background: transparent;
		border: none;
	}

	.placeholder-block {
		background: linear-gradient(
			110deg,
			var(--bg2) 10%,
			var(--bg1) 45%,
			var(--bg3) 60%,
			var(--bg2) 90%
		);
		background-size: 200% 100%;
		animation: placeholder-sheen 2.4s linear infinite;
	}

	@keyframes placeholder-sheen {
		0% {
			background-position: 200% 50%;
		}
		100% {
			background-position: -200% 50%;
		}
	}

</style>
