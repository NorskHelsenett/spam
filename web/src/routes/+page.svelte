<script lang="ts">
	import HealthStatus from '$lib/components/HealthStatus.svelte';
</script>

<main class="hero">
	<section>
		<h1>Spam Monitor</h1>
		<p>Live view of backend status.</p>
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

	h1 {
		margin: 0;
		font-size: clamp(2rem, 5vw, 3.5rem);
	}

	p {
		margin: 0;
		font-size: 1.05rem;
		color: rgba(0, 0, 0, 0.65);
	}
</style>
