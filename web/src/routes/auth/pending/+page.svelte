<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { Hourglass, Shield } from 'lucide-svelte';

	let status = 'Waiting for admin approval...';
	let connecting = true;
	let error = '';

	onMount(() => {
		const stream = new EventSource('/api/auth/pending/stream');

		stream.addEventListener('pending', () => {
			connecting = false;
		});

		stream.addEventListener('approved', () => {
			goto('/app');
		});

		stream.onerror = () => {
			error = 'Lost connection to approval stream. Retrying...';
			connecting = false;
		};

		return () => {
			stream.close();
		};
	});

	const retryLogin = () => {
		goto('/auth/login');
	};
</script>

<svelte:head>
	<title>Pending Approval - SPAM Dashboard</title>
</svelte:head>

<div class="pending-page">
	<div class="pending-card">
		<div class="pending-header">
			<div class="pending-icon">
				<Hourglass size={28} />
			</div>
			<div>
				<h1>Access Pending</h1>
				<p>Your account is waiting for admin approval.</p>
			</div>
		</div>

		<div class="pending-body">
			<div class="pending-status">
				{#if connecting}
					<span class="pending-dot"></span>
					<span>Connecting to approval stream…</span>
				{:else}
					<span class="pending-dot"></span>
					<span>{status}</span>
				{/if}
			</div>
			{#if error}
				<p class="pending-error">{error}</p>
			{/if}
		</div>

		<div class="pending-actions">
			<button class="pending-button" on:click={retryLogin}>
				<Shield size={18} />
				<span>Back to sign in</span>
			</button>
		</div>
	</div>
</div>

<style>
	.pending-page {
		min-height: 100vh;
		background-color: var(--main-content-bg);
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 2rem;
	}

	.pending-card {
		width: 100%;
		max-width: 520px;
		background-color: var(--card-bg);
		border: 1px solid var(--border-color);
		border-radius: 20px;
		padding: 2.5rem;
		box-shadow: 0 24px 50px rgba(0, 0, 0, 0.35);
		display: flex;
		flex-direction: column;
		gap: 1.75rem;
	}

	.pending-header {
		display: flex;
		gap: 1rem;
		align-items: center;
	}

	.pending-header h1 {
		margin: 0;
		font-size: 2rem;
		color: var(--text-bright);
	}

	.pending-header p {
		margin: 0.35rem 0 0;
		color: var(--text-secondary);
	}

	.pending-icon {
		height: 56px;
		width: 56px;
		border-radius: 16px;
		background: linear-gradient(135deg, rgba(255, 184, 77, 0.2), rgba(255, 94, 94, 0.2));
		display: flex;
		align-items: center;
		justify-content: center;
		color: var(--warning);
	}

	.pending-body {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
		color: var(--text-secondary);
	}

	.pending-status {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		font-size: 1rem;
	}

	.pending-dot {
		width: 10px;
		height: 10px;
		border-radius: 50%;
		background-color: var(--warning);
		animation: pulse 1.4s infinite ease-in-out;
	}

	.pending-error {
		color: var(--error);
		font-size: 0.95rem;
	}

	.pending-actions {
		display: flex;
		justify-content: flex-end;
	}

	.pending-button {
		display: inline-flex;
		align-items: center;
		gap: 0.5rem;
		border: 1px solid var(--border-color);
		background-color: transparent;
		color: var(--text-secondary);
		padding: 0.75rem 1.25rem;
		border-radius: 999px;
		cursor: pointer;
		transition: all 0.2s ease;
	}

	.pending-button:hover {
		background-color: var(--hover-bg);
		color: var(--text-bright);
	}

	@keyframes pulse {
		0%,
		100% {
			opacity: 0.4;
			transform: scale(0.9);
		}
		50% {
			opacity: 1;
			transform: scale(1.15);
		}
	}
</style>
