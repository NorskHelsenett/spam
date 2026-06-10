<script lang="ts">
	import { tick } from 'svelte';
	import { MessageCircle, Minus, Send, Square, X } from 'lucide-svelte';

	type ChatMessage = { role: 'user' | 'assistant'; content: string };

	let {
		open = $bindable(false),
		assetType = '',
		assetId = '',
		assetSlug = ''
	}: {
		open?: boolean;
		assetType?: string;
		assetId?: string;
		assetSlug?: string;
	} = $props();

	let messages = $state<ChatMessage[]>([]);
	let input = $state('');
	let sending = $state(false);
	let error = $state('');
	let minimized = $state(false);
	let messagesFor = $state('');
	let bodyEl: HTMLElement | undefined = $state();

	// Reset the conversation when the window opens for a different asset.
	$effect(() => {
		if (!open) return;
		const key = `${assetType}|${assetId}`;
		if (messagesFor !== key) {
			messagesFor = key;
			messages = [];
			error = '';
			minimized = false;
		}
	});

	// --- Dragging -------------------------------------------------
	// Fixed-position window; the header is the drag handle. Position
	// is anchored bottom-right until the first drag converts it to
	// explicit left/top coordinates.
	let pos = $state<{ left: number; top: number } | null>(null);
	let dragFrom: { x: number; y: number; left: number; top: number } | null = null;
	let winEl: HTMLElement | undefined = $state();

	const onDragStart = (e: PointerEvent) => {
		if (!winEl) return;
		const rect = winEl.getBoundingClientRect();
		dragFrom = { x: e.clientX, y: e.clientY, left: rect.left, top: rect.top };
		(e.target as HTMLElement).setPointerCapture?.(e.pointerId);
		window.addEventListener('pointermove', onDragMove);
		window.addEventListener('pointerup', onDragEnd, { once: true });
	};
	const onDragMove = (e: PointerEvent) => {
		if (!dragFrom || !winEl) return;
		const w = winEl.offsetWidth;
		const left = Math.min(Math.max(dragFrom.left + e.clientX - dragFrom.x, 8), window.innerWidth - w - 8);
		const top = Math.min(Math.max(dragFrom.top + e.clientY - dragFrom.y, 8), window.innerHeight - 48);
		pos = { left, top };
	};
	const onDragEnd = () => {
		dragFrom = null;
		window.removeEventListener('pointermove', onDragMove);
	};

	const scrollToEnd = async () => {
		await tick();
		bodyEl?.scrollTo({ top: bodyEl.scrollHeight });
	};

	const send = async () => {
		const text = input.trim();
		if (!text || sending) return;
		input = '';
		error = '';
		messages = [...messages, { role: 'user', content: text }];
		sending = true;
		void scrollToEnd();
		try {
			const res = await fetch('/api/triage/chat', {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ asset_type: assetType, asset_id: assetId, messages })
			});
			if (res.status === 503) throw new Error('Finding chat is not enabled — turn it on under /admin/ai.');
			if (!res.ok) throw new Error(`HTTP ${res.status}`);
			const data = (await res.json()) as { reply: string };
			messages = [...messages, { role: 'assistant', content: data.reply }];
		} catch (e) {
			error = e instanceof Error ? e.message : 'Chat request failed';
		} finally {
			sending = false;
			void scrollToEnd();
		}
	};

	const onKeydown = (e: KeyboardEvent) => {
		if (e.key === 'Enter' && !e.shiftKey) {
			e.preventDefault();
			void send();
		}
	};
</script>

{#if open}
	<section
		bind:this={winEl}
		class="chat-window"
		class:minimized
		style={pos ? `left: ${pos.left}px; top: ${pos.top}px; right: auto; bottom: auto;` : ''}
		aria-label="Finding chat"
	>
		<!-- svelte-ignore a11y_no_static_element_interactions -->
		<header class="chat-head" aria-label="Drag to move" onpointerdown={onDragStart}>
			<MessageCircle size={14} />
			<span class="chat-title" title={assetSlug}>{assetSlug}</span>
			<div class="chat-actions">
				<button type="button" class="chat-icon-btn" aria-label={minimized ? 'Restore' : 'Minimize'} onclick={() => (minimized = !minimized)}>
					{#if minimized}<Square size={12} />{:else}<Minus size={13} />{/if}
				</button>
				<button type="button" class="chat-icon-btn" aria-label="Close chat" onclick={() => (open = false)}>
					<X size={14} />
				</button>
			</div>
		</header>

		{#if !minimized}
			<div class="chat-body" bind:this={bodyEl}>
				{#if messages.length === 0}
					<p class="chat-empty">
						Ask about this finding — exploitability, what to patch first, possible mitigations, or whether it even applies to your setup. The model sees the same KEV/EPSS/exposure evidence the card shows.
					</p>
				{/if}
				{#each messages as m}
					<div class="chat-msg" class:user={m.role === 'user'}>
						<p>{m.content}</p>
					</div>
				{/each}
				{#if sending}
					<div class="chat-msg">
						<p class="chat-pending">Thinking…</p>
					</div>
				{/if}
				{#if error}
					<p class="chat-error">{error}</p>
				{/if}
			</div>

			<footer class="chat-input-row">
				<textarea
					rows="2"
					class="input chat-input"
					placeholder="Ask about this vulnerability…"
					bind:value={input}
					onkeydown={onKeydown}
				></textarea>
				<button type="button" class="btn btn-primary chat-send !shadow-none" onclick={send} disabled={sending || !input.trim()} aria-label="Send">
					<Send size={14} />
				</button>
			</footer>
		{/if}
	</section>
{/if}

<style>
	.chat-window {
		position: fixed;
		right: 1.25rem;
		bottom: 1.25rem;
		z-index: 900;
		display: flex;
		flex-direction: column;
		width: min(26rem, calc(100vw - 2rem));
		max-height: min(34rem, calc(100vh - 4rem));
		border-radius: 0.9rem;
		background: var(--main-content-bg);
		border: 1px solid var(--border-color);
		box-shadow: 0 14px 40px rgba(0, 0, 0, 0.45);
		overflow: hidden;
	}
	.chat-window.minimized {
		max-height: none;
	}

	.chat-head {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.55rem 0.75rem;
		cursor: grab;
		user-select: none;
		color: var(--text-secondary);
		background: color-mix(in srgb, var(--bg2) 60%, transparent);
		touch-action: none;
	}
	.chat-head:active {
		cursor: grabbing;
	}
	.chat-title {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		font-size: 0.8rem;
		font-weight: 600;
		color: var(--text-bright);
	}
	.chat-actions {
		display: inline-flex;
		gap: 0.2rem;
	}
	.chat-icon-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		width: 1.6rem;
		height: 1.6rem;
		border: 0;
		border-radius: 0.4rem;
		background: transparent;
		color: var(--text-muted);
		cursor: pointer;
		transition: background 120ms ease, color 120ms ease;
	}
	.chat-icon-btn:hover {
		background: var(--hover-bg);
		color: var(--text-bright);
	}

	.chat-body {
		flex: 1;
		min-height: 9rem;
		overflow-y: auto;
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		padding: 0.75rem;
	}
	.chat-empty {
		margin: 0;
		font-size: 0.75rem;
		line-height: 1.5;
		color: var(--text-muted);
	}
	.chat-msg {
		display: flex;
		justify-content: flex-start;
	}
	.chat-msg.user {
		justify-content: flex-end;
	}
	.chat-msg p {
		margin: 0;
		max-width: 88%;
		padding: 0.45rem 0.65rem;
		border-radius: 0.7rem;
		font-size: 0.8rem;
		line-height: 1.5;
		white-space: pre-line;
		color: var(--text-secondary);
		background: color-mix(in srgb, var(--bg2) 70%, transparent);
	}
	.chat-msg.user p {
		color: var(--text-bright);
		background: color-mix(in srgb, var(--accent) 14%, transparent);
	}
	.chat-pending {
		font-style: italic;
		color: var(--text-muted);
	}
	.chat-error {
		margin: 0;
		font-size: 0.75rem;
		color: var(--error);
	}

	.chat-input-row {
		display: flex;
		align-items: flex-end;
		gap: 0.5rem;
		padding: 0.6rem 0.75rem 0.75rem;
	}
	.chat-input {
		flex: 1;
		resize: none;
		font-size: 0.8rem;
	}
	.chat-send {
		padding: 0.55rem 0.8rem;
	}
</style>
