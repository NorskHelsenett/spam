<script lang="ts">
	import { onMount } from 'svelte';
	
	onMount(async () => {
		try {
			// Check if user is authenticated via backend API
			const response = await fetch('/api/auth/me', {
				credentials: 'include'
			});
			
			if (response.ok) {
				// User is logged in, redirect to app
				window.location.href = '/app';
			} else {
				// Not logged in, redirect to login
				window.location.href = '/auth/login';
			}
		} catch (error) {
			// Error checking auth, redirect to login
			window.location.href = '/auth/login';
		}
	});
</script>

<svelte:head>
	<title>Redirecting...</title>
</svelte:head>

<div style="display: flex; align-items: center; justify-content: center; min-height: 100vh; color: var(--text-secondary);">
	<p>Redirecting...</p>
</div>
