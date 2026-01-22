<script lang="ts">
	import { onMount } from 'svelte';
	import { createHealthStore, type HealthSnapshot } from '$lib/stores/health';

	export let endpoint = '/api/healthz';

	const health = createHealthStore(endpoint);

	onMount(() => {
		void health.refresh();
	});

	function retry() {
		void health.refresh();
	}

	$: snapshot = $health satisfies HealthSnapshot;
</script>

<section class="health">
	<header>
		<h2>Backend health</h2>
		<button type="button" on:click={retry} disabled={snapshot.status === 'loading'}>
			{snapshot.status === 'loading' ? 'Checking…' : 'Retry'}
		</button>
	</header>

	{#if snapshot.status === 'idle'}
		<p>Idle</p>
	{:else if snapshot.status === 'loading'}
		<p>Checking backend status…</p>
	{:else if snapshot.status === 'ok'}
		<p class="ok">Service reports "{snapshot.message ?? 'ok'}".</p>
	{:else}
		<p class="error">{snapshot.message ?? 'Unknown error'}</p>
	{/if}

	{#if snapshot.timestamp}
		<p class="timestamp">Last checked at {new Date(snapshot.timestamp).toLocaleTimeString()}</p>
	{/if}
</section>

<style>
	.health {
		border: 1px solid rgba(0, 0, 0, 0.1);
		border-radius: 0.75rem;
		padding: 1.5rem;
		max-width: 32rem;
		background: rgba(255, 255, 255, 0.75);
		box-shadow: 0 6px 24px rgba(0, 0, 0, 0.12);
	}

	header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 1rem;
	}

	h2 {
		margin: 0;
		font-size: 1.25rem;
	}

	button {
		padding: 0.35rem 0.9rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(0, 0, 0, 0.15);
		background: #ffffff;
		cursor: pointer;
		transition: background 0.2s ease;
		font-weight: 600;
	}

	button:disabled {
		cursor: not-allowed;
		background: rgba(255, 255, 255, 0.6);
	}

	button:not(:disabled):hover {
		background: rgba(0, 0, 0, 0.05);
	}

	.ok {
		color: #116611;
	}

	.error {
		color: #8b0000;
	}

	.timestamp {
		color: rgba(0, 0, 0, 0.65);
		font-size: 0.875rem;
		margin-top: 0.75rem;
	}
</style>
