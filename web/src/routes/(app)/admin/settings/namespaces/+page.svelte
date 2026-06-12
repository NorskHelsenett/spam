<script lang="ts">
	import { onMount } from 'svelte';
	import { browser } from '$app/environment';
	import { slide } from 'svelte/transition';
	import RotateCw from 'lucide-svelte/icons/rotate-cw';
	import X from 'lucide-svelte/icons/x';
	import Plus from 'lucide-svelte/icons/plus';

	type HiddenNamespace = {
		id: number;
		pattern: string;
		note: string;
		created_at: string;
		created_by: string;
	};

	const dateFmt = new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
	const formatDate = (iso?: string) => {
		if (!iso) return '—';
		const d = new Date(iso);
		return Number.isNaN(d.getTime()) ? '—' : dateFmt.format(d);
	};

	let items: HiddenNamespace[] = $state([]);
	let loading = $state(true);
	let refreshing = $state(false);
	let error = $state('');
	let formError = $state('');
	let saving = $state(false);
	let newPattern = $state('');
	let newNote = $state('');

	const load = async () => {
		loading = true;
		refreshing = true;
		error = '';
		try {
			const response = await fetch('/api/admin/namespaces/hidden', { credentials: 'include' });
			if (!response.ok) {
				error = response.status === 403 ? 'Admin access required.' : 'Failed to load hidden namespaces.';
				items = [];
				return;
			}
			const payload = await response.json();
			items = payload.items ?? [];
		} catch {
			error = 'Failed to load hidden namespaces.';
		} finally {
			loading = false;
			setTimeout(() => { refreshing = false; }, 1000);
		}
	};

	const add = async (event: SubmitEvent) => {
		event.preventDefault();
		const pattern = newPattern.trim();
		if (!pattern) return;
		saving = true;
		formError = '';
		try {
			const response = await fetch('/api/admin/namespaces/hidden', {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ pattern, note: newNote.trim() })
			});
			if (!response.ok) {
				formError = (await response.text()).trim() || 'Failed to add pattern.';
				return;
			}
			const created: HiddenNamespace = await response.json();
			items = [...items, created].sort((a, b) => a.pattern.localeCompare(b.pattern));
			newPattern = '';
			newNote = '';
		} catch {
			formError = 'Failed to add pattern.';
		} finally {
			saving = false;
		}
	};

	const remove = async (item: HiddenNamespace) => {
		try {
			const response = await fetch(`/api/admin/namespaces/hidden/${item.id}`, {
				method: 'DELETE',
				credentials: 'include'
			});
			if (!response.ok && response.status !== 404) {
				error = 'Failed to remove pattern.';
				return;
			}
			items = items.filter((entry) => entry.id !== item.id);
		} catch {
			error = 'Failed to remove pattern.';
		}
	};

	onMount(() => {
		if (browser) load();
	});
</script>

<svelte:head>
	<title>Namespaces · Settings — Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<section class="panel-surface space-y-6 px-6 py-8 sm:px-10 sm:py-10">
		<header class="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
			<div>
				<h2 class="text-xl font-semibold text-[var(--text-bright)]">Hidden namespaces</h2>
				<p class="text-sm text-[var(--text-tertiary)]">
					Administrative namespaces (agents, operators, platform tooling) hidden from regular users'
					cluster views so teams focus on their own workloads. Admins and global readers always see everything.
				</p>
			</div>
			<button type="button" class="btn btn-ghost shrink-0" onclick={load} disabled={refreshing}>
				<span class="inline-flex h-[14px] w-[14px] items-center justify-center {refreshing ? 'animate-spin' : ''}">
					<RotateCw size={14} />
				</span>
				Refresh
			</button>
		</header>

		<form class="flex flex-col gap-3 sm:flex-row sm:items-end" onsubmit={add}>
			<div class="flex-1 space-y-2">
				<label class="text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]" for="ns-pattern">Namespace pattern</label>
				<input
					id="ns-pattern"
					type="text"
					placeholder="nhn-scam or nhn-*"
					class="w-full rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 font-mono text-sm text-[var(--text-secondary)] focus:border-[var(--accent)] focus:outline-none"
					bind:value={newPattern}
				/>
			</div>
			<div class="flex-[2] space-y-2">
				<label class="text-xs uppercase tracking-[0.2em] text-[var(--text-tertiary)]" for="ns-note">Note</label>
				<input
					id="ns-note"
					type="text"
					placeholder="Why this namespace is administrative (optional)"
					class="w-full rounded-2xl border border-[var(--border-color)] bg-transparent px-4 py-3 text-sm text-[var(--text-secondary)] focus:border-[var(--accent)] focus:outline-none"
					bind:value={newNote}
				/>
			</div>
			<button type="submit" class="btn btn-primary shrink-0" disabled={saving || !newPattern.trim()}>
				<Plus size={14} />
				Add
			</button>
		</form>
		<p class="text-xs text-[var(--text-tertiary)]">
			Exact namespace name or a glob with <code>*</code> wildcards, e.g. <code>nhn-*</code> hides every namespace starting with <code>nhn-</code>.
		</p>

		{#if formError}
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">{formError}</div>
		{/if}
		{#if error}
			<div class="rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40 p-4 text-sm text-[var(--error)]">{error}</div>
		{/if}

		{#if loading}
			<p class="text-sm text-[var(--text-secondary)]">Loading hidden namespaces…</p>
		{:else if items.length === 0}
			<p class="text-sm text-[var(--text-secondary)]">No hidden namespaces yet. Every namespace is visible to every user with cluster access.</p>
		{:else}
			<ul class="divide-y divide-[var(--border-color)]/40 overflow-hidden rounded-2xl border border-[var(--border-color)]/60 bg-[var(--card-bg)]/40">
				{#each items as item (item.id)}
					<li
						transition:slide={{ duration: 200 }}
						class="flex items-center gap-4 px-5 py-4 text-sm transition hover:bg-[var(--hover-bg-subtle)]"
					>
						<code class="shrink-0 rounded-lg border border-[var(--border-color)]/60 bg-[var(--hover-bg)]/30 px-2.5 py-1 font-mono text-[13px] text-[var(--text-bright)]">
							{item.pattern}
						</code>
						<div class="min-w-0 flex-1">
							<p class="truncate text-[var(--text-secondary)]">{item.note || '—'}</p>
							<p class="text-[10px] uppercase tracking-[0.18em] text-[var(--text-tertiary)]">
								Added {formatDate(item.created_at)}{item.created_by ? ` by ${item.created_by}` : ''}
							</p>
						</div>
						<button
							type="button"
							class="shrink-0 rounded-full p-1 text-[var(--text-tertiary)] transition hover:bg-[var(--hover-bg)] hover:text-[var(--text-secondary)]"
							onclick={() => remove(item)}
							aria-label="Remove pattern"
							title="Remove"
						>
							<X size={14} />
						</button>
					</li>
				{/each}
			</ul>
		{/if}
	</section>
</div>
