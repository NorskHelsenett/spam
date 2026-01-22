<script lang="ts">
	import { X } from 'lucide-svelte';
	import { browser } from '$app/environment';
	
	let { 
		open = $bindable(false),
		onClose = () => {},
		children
	}: {
		open?: boolean;
		onClose?: () => void;
		children?: any;
	} = $props();

	const handleClose = () => {
		open = false;
		onClose();
	};

	const handleBackdropClick = (e: MouseEvent) => {
		if (e.target === e.currentTarget) {
			handleClose();
		}
	};

	const handleKeydown = (e: KeyboardEvent) => {
		if (e.key === 'Escape' && open) {
			handleClose();
		}
	};

	$effect(() => {
		if (!browser) return;
		
		if (open) {
			document.body.style.overflow = 'hidden';
			document.addEventListener('keydown', handleKeydown);
		} else {
			document.body.style.overflow = '';
			document.removeEventListener('keydown', handleKeydown);
		}

		return () => {
			document.body.style.overflow = '';
			document.removeEventListener('keydown', handleKeydown);
		};
	});
</script>

{#if open}
	<!-- Backdrop -->
	<div 
		class="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm"
		onclick={handleBackdropClick}
		role="presentation"
	>
		<!-- Dialog Container -->
		<div 
			class="fixed left-1/2 top-1/2 z-50 flex h-[55vh] w-[90vw] max-w-4xl flex-col overflow-hidden rounded-2xl border border-[var(--hover-bg)] bg-[var(--main-content-bg)] shadow-2xl md:flex-row" 
			style="transform: translate(-50%, -50%) scale(1.1); transform-origin: center center;"
			role="dialog"
			aria-modal="true"
		>
			{@render children?.()}
		</div>
	</div>
{/if}
