<script lang="ts">
	import { onMount } from 'svelte';
	import HealthStatus from '$lib/components/HealthStatus.svelte';

	type UserInfo = {
		subject: string;
		email?: string;
		name?: string;
		claims?: Record<string, unknown>;
	};

	let user: UserInfo | null = null;
	let loading = true;
	let error: string | null = null;

	onMount(() => {
		void refreshUser();
	});

	async function refreshUser() {
		loading = true;
		error = null;

		try {
			const response = await fetch('/api/auth/me', { credentials: 'include' });
			if (response.ok) {
				user = (await response.json()) as UserInfo;
			} else if (response.status === 401) {
				user = null;
			} else {
				error = `Unable to load user (${response.status})`;
			}
		} catch (err) {
			console.error(err);
			error = 'Unable to reach the auth service.';
		} finally {
			loading = false;
		}
	}

	function login() {
		window.location.href = '/api/auth/login';
	}

	async function logout() {
		await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
		await refreshUser();
	}
</script>

<main class="hero">
	<section>
		<h1>Spam Monitor</h1>
		<p>Live view of backend status and authenticated user info.</p>
		<div class="auth">
			<header>
				<h2>Authentication</h2>
				{#if user}
					<button type="button" on:click={logout}>Sign out</button>
				{:else}
					<button type="button" on:click={login} disabled={loading}>Sign in with OIDC</button>
				{/if}
			</header>

			{#if loading}
				<p>Checking session…</p>
			{:else if user}
				<p class="ok">Signed in as {user.name ?? user.email ?? user.subject}.</p>
				<pre>{JSON.stringify(user, null, 2)}</pre>
			{:else}
				<p>Sign in to see the verified user object returned by the BFF.</p>
			{/if}

			{#if error}
				<p class="error">{error}</p>
			{/if}
		</div>
		<HealthStatus />
	</section>
</main>

<style>
	.hero {
		min-height: 100vh;
		display: grid;
		place-items: center;
		background: linear-gradient(135deg, #f7f7ff 0%, #eef5ff 100%);
		padding: 2rem;
	}

	section {
		display: grid;
		gap: 1.5rem;
		text-align: center;
	}

	.auth {
		border: 1px solid rgba(0, 0, 0, 0.1);
		border-radius: 0.75rem;
		padding: 1.5rem;
		background: rgba(255, 255, 255, 0.8);
		box-shadow: 0 6px 20px rgba(0, 0, 0, 0.08);
		display: grid;
		gap: 0.75rem;
	}

	.auth header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 1rem;
	}

	.auth h2 {
		margin: 0;
		font-size: 1.2rem;
	}

	.auth button {
		padding: 0.35rem 0.9rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(0, 0, 0, 0.15);
		background: #ffffff;
		cursor: pointer;
		transition: background 0.2s ease;
		font-weight: 600;
	}

	.auth button:disabled {
		cursor: not-allowed;
		background: rgba(255, 255, 255, 0.6);
	}

	.auth button:not(:disabled):hover {
		background: rgba(0, 0, 0, 0.05);
	}

	.auth pre {
		background: rgba(0, 0, 0, 0.05);
		border-radius: 0.5rem;
		padding: 0.75rem;
		text-align: left;
		white-space: pre-wrap;
		word-break: break-word;
	}

	h1 {
		margin: 0;
		font-size: clamp(2rem, 5vw, 3.5rem);
	}

	p {
		margin: 0;
		font-size: 1.05rem;
		color: rgba(0, 0, 0, 0.65);
	}

	.ok {
		color: #116611;
	}

	.error {
		color: #8b0000;
	}
</style>
