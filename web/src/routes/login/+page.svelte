<script lang="ts">
	// Redirect to the proper auth login page
	if (typeof window !== 'undefined') {
		window.location.href = '/auth/login';
	}
</script>

<svelte:head>
	<title>Redirecting...</title>
</svelte:head>

<div class="login-redirect">
	<p>Redirecting to login...</p>
</div>

<style>
	.login-redirect {
		display: flex;
		align-items: center;
		justify-content: center;
		min-height: 100vh;
		font-size: 1.25rem;
		color: var(--text-secondary);
	}
</style>
