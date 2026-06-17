<script lang="ts">
	import OsvScanSection from '$lib/components/settings/OsvScanSection.svelte';
	import SbomScanSection from '$lib/components/settings/SbomScanSection.svelte';
	import SecretProbeSection from '$lib/components/settings/SecretProbeSection.svelte';
</script>

<svelte:head>
	<title>Scanners · Settings — Spam Monitor</title>
</svelte:head>

<div class="space-y-8 sm:space-y-12">
	<OsvScanSection />
	<SbomScanSection />
	<SecretProbeSection />
</div>
