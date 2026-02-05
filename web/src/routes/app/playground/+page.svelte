<script lang="ts">
	import Loading from '$lib/components/Loading.svelte';
	import DonutChart from '$lib/components/DonutChart.svelte';
	import TabSelector from '$lib/components/TabSelector.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import Markdown from '$lib/components/Markdown.svelte';
	import Dialog from '$lib/components/Dialog.svelte';
	import DependencyDetail from '$lib/components/DependencyDetail.svelte';
	import HealthStatus from '$lib/components/HealthStatus.svelte';
	import Toggle from '$lib/components/Toggle.svelte';
	import Checkbox from '$lib/components/Checkbox.svelte';
	import Radio from '$lib/components/Radio.svelte';
	import ChevronDown from 'lucide-svelte/icons/chevron-down';
	import Eye from 'lucide-svelte/icons/eye';
	import EyeOff from 'lucide-svelte/icons/eye-off';

	import {
		mockDonut,
		mockMarkdown,
		mockDependency,
		mockTextSamples,
		mockColorSwatches,
		mockSemanticSwatches,
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
	let selectOpen = $state(false);
	let radioValue = $state('alpha');
	let rangeValue = $state(42);
	let checkboxValue = $state(true);
	let toggleValue = $state(true);
	let fileList = $state<FileList | null>(null);

	const selectOptions = [
		{ value: 'daily', label: 'Daily' },
		{ value: 'weekly', label: 'Weekly' },
		{ value: 'monthly', label: 'Monthly' }
	];

	const selectedOption = $derived(selectOptions.find((option) => option.value === selectValue) ?? selectOptions[0]);

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
				<span class="rounded-full border border-[var(--border-color)] px-2 py-1">/app/playground</span>
				<span class="rounded-full border border-[var(--border-color)] px-2 py-1">Theme aware</span>
			</div>
		</header>

		<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
			{#each metricCards as card}
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
			{#each mockTextSamples as sample}
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
			{#each mockColorSwatches as swatch}
				<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
					<div class="h-12 rounded-xl" style={`background: var(${swatch.varName});`}></div>
					<p class="mt-3 text-sm font-medium text-[var(--text-bright)]">{swatch.label}</p>
					<p class="text-xs text-[var(--text-tertiary)]">{swatch.varName}</p>
				</div>
			{/each}
		</div>
		<div class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
			{#each mockSemanticSwatches as swatch}
				<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
					<div class="h-12 rounded-xl" style={`background: var(${swatch.varName});`}></div>
					<p class="mt-3 text-sm font-medium text-[var(--text-bright)]">{swatch.label}</p>
					<p class="text-xs text-[var(--text-tertiary)]">{swatch.varName}</p>
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
		</div>
		<div class="flex flex-wrap items-center gap-2">
			<span class="pill pill-success">Success</span>
			<span class="pill pill-warning">Warning</span>
			<span class="pill pill-error">Error</span>
			<span class="pill pill-info">Info</span>
			<span class="pill pill-neutral">Neutral</span>
		</div>
	</section>

	<section class="panel-surface space-y-8 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">Forms and Inputs</h2>
			<p class="text-sm text-[var(--text-tertiary)]">Text fields, selections, toggles, and validation states.</p>
		</header>
		<div class="grid gap-6 lg:grid-cols-2">
			<div class="space-y-4">
				<label class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Text</label>
				<input
					type="text"
					class="input"
					placeholder="Search..."
					bind:value={inputValue}
				/>

				<label class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Email</label>
				<input type="email" class="input" bind:value={emailValue} />

				<label class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Password</label>
				<div class="relative">
					<input
						type={showPassword ? 'text' : 'password'}
						class="input input-with-icon"
						bind:value={passwordValue}
					/>
					<button
						type="button"
						class="absolute right-3 top-1/2 -translate-y-1/2 rounded-full p-2 text-[var(--text-secondary)] transition hover:bg-[var(--hover-bg)]"
						on:click={() => (showPassword = !showPassword)}
						aria-label={showPassword ? 'Hide password' : 'Show password'}
					>
						{#if showPassword}
							<EyeOff size={14} />
						{:else}
							<Eye size={14} />
						{/if}
					</button>
				</div>

				<label class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Textarea</label>
				<textarea rows="3" class="input" bind:value={textareaValue}></textarea>
			</div>
			<div class="space-y-4">
				<label class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Select</label>
				<div
					class="select"
					class:open={selectOpen}
					tabindex="0"
					on:focusout={(event) => {
						const nextTarget = event.relatedTarget as Node | null;
						if (!nextTarget || !event.currentTarget.contains(nextTarget)) {
							selectOpen = false;
						}
					}}
				>
					<button
						type="button"
						class="select-button"
						aria-haspopup="listbox"
						aria-expanded={selectOpen}
						on:click={() => (selectOpen = !selectOpen)}
					>
						<span>{selectedOption.label}</span>
						<ChevronDown class="select-caret" aria-hidden="true" />
					</button>
					<div class="select-menu" role="listbox">
						{#each selectOptions as option}
							<button
								type="button"
								class="select-option"
								class:is-active={option.value === selectValue}
								role="option"
								aria-selected={option.value === selectValue}
								on:click={() => {
									selectValue = option.value;
									selectOpen = false;
								}}
							>
								<span>{option.label}</span>
								{#if option.value === selectValue}
									<span class="select-check" aria-hidden="true">●</span>
								{/if}
							</button>
						{/each}
					</div>
				</div>

				<label class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Radio</label>
				<div class="flex flex-wrap gap-4">
					<Radio name="phase" value="alpha" bind:group={radioValue} label="Alpha" />
					<Radio name="phase" value="beta" bind:group={radioValue} label="Beta" />
				</div>

				<label class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Checkbox</label>
				<Checkbox bind:checked={checkboxValue} label="Enable notifications" />

				<label class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Toggle</label>
				<Toggle bind:checked={toggleValue} label="Feature flag" />

				<label class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Range</label>
				<input type="range" min="0" max="100" bind:value={rangeValue} />
				<p class="text-xs text-[var(--text-tertiary)]">Value: {rangeValue}</p>

				<label class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">File</label>
				<input type="file" class="input" bind:files={fileList} />
				{#if fileList && fileList.length > 0}
					<p class="text-xs text-[var(--text-tertiary)]">{fileList.length} file(s) selected</p>
				{/if}

				<label class="block text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Validation</label>
				<input type="text" class="input input-error" value="Invalid value" />
			</div>
		</div>
	</section>

	<section class="panel-surface space-y-8 px-6 py-8 sm:px-10 sm:py-10">
		<header>
			<h2 class="text-xl font-semibold text-[var(--text-bright)]">Components</h2>
			<p class="text-sm text-[var(--text-tertiary)]">Svelte components rendered with mock data.</p>
		</header>

		<div class="grid gap-6 lg:grid-cols-2">
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Loading spinner</p>
				<Loading message="Syncing assets" variant="spinner" size="md" />
			</div>
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4">
				<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Loading bar</p>
				<Loading message="Indexing dependencies" variant="bar" size="sm" />
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
				<p class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Dialog</p>
				<button type="button" class="btn btn-secondary" on:click={() => (dialogOpen = true)}>
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
									<button type="button" class="btn btn-primary" on:click={() => (dialogOpen = false)}>
										Confirm
									</button>
									<button type="button" class="btn btn-ghost" on:click={() => (dialogOpen = false)}>
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
				<button type="button" class="btn btn-secondary" on:click={() => (dependencyOpen = true)}>
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
					<label class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Progress</label>
					<progress class="w-full" value="68" max="100"></progress>
					<label class="text-xs uppercase tracking-[0.2em] text-[var(--text-muted)]">Meter</label>
					<meter class="w-full" min="0" max="100" low="30" high="80" optimum="90" value="72"></meter>
				</div>
				<figure class="rounded-xl border border-[var(--border-color)] bg-[var(--card-bg)]/40 p-4">
					<div class="h-28 w-full rounded-lg bg-gradient-to-r from-[var(--bg2)] via-[var(--bg1)] to-[var(--bg3)]"></div>
					<figcaption class="mt-2 text-xs text-[var(--text-tertiary)]">Placeholder media block.</figcaption>
				</figure>
			</div>
		</div>
	</section>
</div>

<style>
	.btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		border-radius: 999px;
		padding: 0.55rem 1.1rem;
		font-size: 0.85rem;
		font-weight: 600;
		letter-spacing: 0.02em;
		transition: transform 150ms ease, box-shadow 150ms ease, background 150ms ease, color 150ms ease;
	}

	.btn:active {
		transform: scale(0.98);
	}

	.btn-primary {
		background: var(--accent);
		color: var(--main-content-bg);
		box-shadow: 0 10px 20px rgba(0, 0, 0, 0.25);
	}

	.btn-secondary {
		background: var(--hover-bg);
		color: var(--text-bright);
		border: 1px solid var(--border-color);
	}

	.btn-ghost {
		background: transparent;
		color: var(--text-secondary);
		border: 1px dashed var(--border-color);
	}

	.btn-outline {
		background: transparent;
		color: var(--text-bright);
		border: 1px solid var(--accent);
	}

	.btn:disabled {
		opacity: 0.5;
		cursor: not-allowed;
		box-shadow: none;
	}

	.pill {
		display: inline-flex;
		align-items: center;
		gap: 0.35rem;
		border-radius: 999px;
		padding: 0.3rem 0.75rem;
		font-size: 0.7rem;
		letter-spacing: 0.15em;
		text-transform: uppercase;
		border: 1px solid var(--border-color);
	}

	.pill-success {
		background: color-mix(in srgb, var(--success) 20%, transparent);
		color: var(--success);
	}

	.pill-warning {
		background: color-mix(in srgb, var(--warning) 18%, transparent);
		color: var(--warning);
	}

	.pill-error {
		background: color-mix(in srgb, var(--error) 18%, transparent);
		color: var(--error);
	}

	.pill-info {
		background: color-mix(in srgb, var(--info) 18%, transparent);
		color: var(--info);
	}

	.pill-neutral {
		background: color-mix(in srgb, var(--gray) 20%, transparent);
		color: var(--text-secondary);
	}

	.input {
		width: 100%;
		border-radius: 1.25rem;
		border: 1px solid var(--border-color);
		background: transparent;
		padding: 0.75rem 1rem;
		font-size: 0.9rem;
		color: var(--text-secondary);
		transition: border-color 150ms ease, box-shadow 150ms ease;
	}

	.input:focus {
		outline: none;
		border-color: var(--accent);
		box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 30%, transparent);
	}

	.input-error {
		border-color: var(--error);
		box-shadow: 0 0 0 2px color-mix(in srgb, var(--error) 25%, transparent);
	}

	.input-with-icon {
		padding-right: 3rem;
	}

	.select {
		position: relative;
	}

	.select-button {
		width: 100%;
		height: 37px;
		border-radius: 999px;
		border: 1px solid var(--border-color);
		background: var(--card-bg);
		padding: 0 1rem;
		font-size: 0.9rem;
		color: var(--text-secondary);
		display: inline-flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.5rem;
		transition: border-color 150ms ease, box-shadow 150ms ease;
	}

	.select-button:focus-visible {
		outline: none;
		border-color: var(--accent);
		box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 30%, transparent);
	}

	.select-caret {
		width: 14px;
		height: 14px;
		color: var(--text-tertiary);
		transition: transform 150ms ease;
	}

	.select.open .select-caret {
		transform: rotate(180deg);
	}

	.select-menu {
		position: absolute;
		top: calc(100% + 8px);
		left: 0;
		right: 0;
		background: var(--card-bg);
		border: 1px solid var(--border-color);
		border-radius: 1rem;
		padding: 0.4rem;
		box-shadow: 0 16px 40px rgba(0, 0, 0, 0.25);
		max-height: 0;
		opacity: 0;
		transform: translateY(-8px);
		overflow: hidden;
		pointer-events: none;
		transition: max-height 200ms ease, opacity 200ms ease, transform 200ms ease;
		z-index: 20;
	}

	.select.open .select-menu {
		max-height: 220px;
		opacity: 1;
		transform: translateY(0);
		pointer-events: auto;
	}

	.select-option {
		width: 100%;
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.5rem;
		padding: 0.55rem 0.8rem;
		border-radius: 0.75rem;
		font-size: 0.85rem;
		color: var(--text-secondary);
		background: transparent;
		transition: background 150ms ease, color 150ms ease;
	}

	.select-option:hover {
		background: var(--hover-bg-subtle);
		color: var(--text-bright);
	}

	.select-option.is-active {
		background: color-mix(in srgb, var(--accent) 16%, transparent);
		color: var(--text-bright);
	}

	.select-check {
		color: var(--accent);
		font-size: 0.7rem;
	}



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

	.select-button,
	.select-option {
		cursor: pointer;
	}

</style>
