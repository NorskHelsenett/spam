<script lang="ts">
	import { browser } from '$app/environment';
	import { Loader2 } from 'lucide-svelte';
	import type { Snippet } from 'svelte';

	type ButtonVariant = 'primary' | 'danger' | 'warning' | 'success' | 'ghost';
	type IconVariant = 'default' | 'danger' | 'warning' | 'success' | 'info';

	export type ConfirmButton = {
		label: string;
		variant?: ButtonVariant;
		loading?: boolean;
		disabled?: boolean;
		onclick: () => void;
	};

	let {
		open = $bindable(false),
		title,
		description,
		icon,
		iconVariant = 'default',
		buttons = [],
		onClose = () => {}
	}: {
		open?: boolean;
		title: string;
		description?: string;
		icon?: Snippet;
		iconVariant?: IconVariant;
		buttons?: ConfirmButton[];
		onClose?: () => void;
	} = $props();

	const handleClose = () => {
		open = false;
		onClose();
	};

	const handleKeydown = (e: KeyboardEvent) => {
		if (e.key === 'Escape') handleClose();
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

	const iconBg: Record<IconVariant, string> = {
		default: 'color-mix(in srgb, var(--accent) 15%, transparent)',
		danger:  'color-mix(in srgb, var(--error) 15%, transparent)',
		warning: 'color-mix(in srgb, var(--warning) 15%, transparent)',
		success: 'color-mix(in srgb, var(--success) 15%, transparent)',
		info:    'color-mix(in srgb, var(--info) 15%, transparent)'
	};

	const iconFg: Record<IconVariant, string> = {
		default: 'var(--accent)',
		danger:  'var(--error)',
		warning: 'var(--warning)',
		success: 'var(--success)',
		info:    'var(--info)'
	};

	const btnStyles: Record<ButtonVariant, string> = {
		primary: 'bg-[var(--accent)] text-[var(--bg)] hover:opacity-90',
		danger:  'bg-[var(--error)] text-white hover:opacity-90',
		warning: 'bg-[var(--warning)] text-[var(--bg)] hover:opacity-90',
		success: 'bg-[var(--success)] text-[var(--bg)] hover:opacity-90',
		ghost:   'border border-[var(--border-color)] bg-transparent text-[var(--text-secondary)] hover:bg-[var(--hover-bg)]'
	};

	const btnClass = (variant: ButtonVariant = 'ghost') =>
		`flex-1 rounded-full py-3 text-base font-medium transition whitespace-nowrap ${btnStyles[variant]}`;
</script>

{#if open}
	<!-- Backdrop -->
	<div
		class="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-[2px]"
		onclick={handleClose}
		role="presentation"
	>
		<!-- Card -->
		<div
			class="w-full max-w-sm space-y-6 rounded-3xl bg-[var(--main-content-bg)] p-8 shadow-[0_8px_40px_rgba(0,0,0,0.28)]"
			onclick={(e) => e.stopPropagation()}
			role="dialog"
			aria-modal="true"
		>
			<!-- Icon + title + description -->
			<div class="flex flex-col items-center gap-3 text-center">
				{#if icon}
					<div
						class="flex h-14 w-14 items-center justify-center rounded-full"
						style="background: {iconBg[iconVariant]}; color: {iconFg[iconVariant]};"
					>
						{@render icon()}
					</div>
				{/if}

				<h2 class="text-xl font-semibold text-[var(--text-bright)]">{title}</h2>

				{#if description}
					<p class="text-sm leading-relaxed text-[var(--text-secondary)]">{description}</p>
				{/if}
			</div>

			<!-- Pill buttons -->
			{#if buttons.length > 0}
				<div class="flex gap-3">
					{#each buttons as btn}
						<button
							type="button"
							class={btnClass(btn.variant)}
							onclick={btn.onclick}
							disabled={btn.disabled || btn.loading}
						>
							{#if btn.loading}
								<span class="inline-flex items-center justify-center gap-2">
									<Loader2 size={16} class="animate-spin" />
									{btn.label}
								</span>
							{:else}
								{btn.label}
							{/if}
						</button>
					{/each}
				</div>
			{/if}
		</div>
	</div>
{/if}
