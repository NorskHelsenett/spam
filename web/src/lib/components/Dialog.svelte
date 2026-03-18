<script lang="ts">
	import { X } from 'lucide-svelte';
	import { browser } from '$app/environment';

	let {
		open = $bindable(false),
		onClose = () => {},
		showCloseButton = true,
		maxWidth = 'max-w-5xl',
		children
	}: {
		open?: boolean;
		onClose?: () => void;
		showCloseButton?: boolean;
		maxWidth?: string;
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
		class="fixed inset-0 z-50 bg-black/25 backdrop-blur-[1px]"
		onclick={handleBackdropClick}
		role="presentation"
	>
		<!-- Dialog Container -->
		<div
			class="fixed left-1/2 top-1/2 z-50 flex h-auto max-h-[95vh] min-h-[80vh] w-[95vw] {maxWidth} flex-col overflow-hidden rounded-2xl border border-[var(--hover-bg)] bg-[var(--main-content-bg)] shadow-2xl"
			style="transform: translate(-50%, -50%);"
			role="dialog"
			aria-modal="true"
		>
			{#if showCloseButton}
				<!-- Close Button Sidebar -->
				<div class="flex shrink-0 select-none flex-row flex-wrap overflow-x-auto p-1.5 md:min-w-[180px] md:max-w-[210px] md:flex-col md:p-0">
					<div class="hidden py-3 ps-2.5 md:block">
						<button
							type="button"
							class="flex h-9 w-9 items-center justify-center rounded-lg bg-transparent transition hover:bg-[var(--hover-bg)]"
							aria-label="Close"
							onclick={handleClose}
						>
							<X size={20} stroke-width={2} />
						</button>
					</div>
				</div>
			{/if}
			{@render children?.()}
		</div>
	</div>
{/if}
