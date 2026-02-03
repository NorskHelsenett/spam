<script lang="ts">
	import { Loader2 } from 'lucide-svelte';

	export let message = 'Loading...';
	export let variant: 'spinner' | 'bar' = 'spinner';
	export let size: 'sm' | 'md' | 'lg' = 'md';

	const sizeClasses = {
		sm: { outer: 'h-8 w-8', inner: 'h-6 w-6', icon: 'h-4 w-4', text: 'text-xs', bar: 'h-1' },
		md: { outer: 'h-14 w-14', inner: 'h-10 w-10', icon: 'h-6 w-6', text: 'text-sm', bar: 'h-1.5' },
		lg: { outer: 'h-20 w-20', inner: 'h-14 w-14', icon: 'h-8 w-8', text: 'text-base', bar: 'h-2' }
	};

	$: classes = sizeClasses[size];
</script>

<div class="flex min-h-[200px] w-full flex-col items-center justify-center gap-4">
	{#if variant === 'spinner'}
		<div class="relative flex items-center justify-center {classes.outer}">
			<div class="ring-clockwise {classes.outer} absolute rounded-full border-2 border-transparent border-t-[var(--accent)] border-r-[var(--accent)]"></div>
			<div class="ring-counter {classes.inner} absolute rounded-full border-2 border-transparent border-b-[var(--info)] border-l-[var(--info)]"></div>
			<Loader2 class="{classes.icon} text-[var(--text-muted)]" />
		</div>
	{:else}
		<div class="w-48 overflow-hidden rounded-full bg-[var(--border-color)]/30">
			<div class="loading-bar {classes.bar} rounded-full bg-[var(--accent)]"></div>
		</div>
	{/if}
	<p class="{classes.text} uppercase tracking-[0.2em] text-[var(--text-muted)]">{message}</p>
</div>

<style>
	.ring-clockwise {
		animation: spin-right 1.2s linear infinite;
	}

	.ring-counter {
		animation: spin-left 0.9s linear infinite;
	}

	.loading-bar {
		animation: slide 1.5s ease-in-out infinite;
	}

	@keyframes spin-right {
		from {
			transform: rotate(0deg);
		}
		to {
			transform: rotate(360deg);
		}
	}

	@keyframes spin-left {
		from {
			transform: rotate(0deg);
		}
		to {
			transform: rotate(-360deg);
		}
	}

	@keyframes slide {
		0% {
			width: 20%;
			margin-left: 0;
		}
		50% {
			width: 50%;
			margin-left: 25%;
		}
		100% {
			width: 20%;
			margin-left: 80%;
		}
	}
</style>
