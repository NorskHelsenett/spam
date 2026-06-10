<script lang="ts">
	import { tick } from 'svelte';
	import { MessageCircle, Minus, Send, Square, X } from 'lucide-svelte';
	import Markdown from '$lib/components/Markdown.svelte';

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
	let streamingReply = $state('');
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

	// --- Window geometry ------------------------------------------
	// Anchored bottom-right until the user drags (converts to explicit
	// left/top) or resizes (also fixes the size). The chrome bar is
	// the drag handle; the corner grip resizes.
	let pos = $state<{ left: number; top: number } | null>(null);
	let size = $state<{ w: number; h: number } | null>(null);
	let dragFrom: { x: number; y: number; left: number; top: number } | null = null;
	let resizeFrom: { x: number; y: number; w: number; h: number } | null = null;
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

	const onResizeStart = (e: PointerEvent) => {
		if (!winEl) return;
		e.stopPropagation();
		const rect = winEl.getBoundingClientRect();
		// Pin the window's top-left so growing the corner feels natural
		// even while the window is still bottom-right anchored.
		pos = { left: rect.left, top: rect.top };
		resizeFrom = { x: e.clientX, y: e.clientY, w: rect.width, h: rect.height };
		(e.target as HTMLElement).setPointerCapture?.(e.pointerId);
		window.addEventListener('pointermove', onResizeMove);
		window.addEventListener('pointerup', onResizeEnd, { once: true });
	};
	const onResizeMove = (e: PointerEvent) => {
		if (!resizeFrom) return;
		size = {
			w: Math.min(Math.max(resizeFrom.w + e.clientX - resizeFrom.x, 300), window.innerWidth - 16),
			h: Math.min(Math.max(resizeFrom.h + e.clientY - resizeFrom.y, 320), window.innerHeight - 16)
		};
	};
	const onResizeEnd = () => {
		resizeFrom = null;
		window.removeEventListener('pointermove', onResizeMove);
	};

	const windowStyle = $derived(() => {
		let style = '';
		if (pos) style += `left: ${pos.left}px; top: ${pos.top}px; right: auto; bottom: auto;`;
		if (size && !minimized) style += `width: ${size.w}px; height: ${size.h}px; max-height: none;`;
		return style;
	});

	const scrollToEnd = async () => {
		await tick();
		bodyEl?.scrollTo({ top: bodyEl.scrollHeight });
	};

	// consumeSSEEvent applies one "data: {...}" block to the
	// in-progress reply. Throws on a server-reported error.
	const consumeSSEEvent = (evt: string) => {
		const line = evt.trim();
		if (!line.startsWith('data:')) return;
		let parsed: { thinking?: boolean; delta?: string; done?: boolean; error?: string };
		try {
			parsed = JSON.parse(line.slice(5).trim());
		} catch {
			return;
		}
		if (parsed.error) throw new Error(parsed.error);
		if (parsed.delta) {
			streamingReply += parsed.delta;
			void scrollToEnd();
		}
	};

	// --- Streaming send -------------------------------------------
	// The server relays SSE data events: {"thinking":true} while the
	// reasoning model deliberates, {"delta":"…"} per visible chunk,
	// {"done":true} / {"error":"…"} to finish.
	const send = async () => {
		const text = input.trim();
		if (!text || sending) return;
		input = '';
		error = '';
		messages = [...messages, { role: 'user', content: text }];
		sending = true;
		streamingReply = '';
		void scrollToEnd();
		try {
			const res = await fetch('/api/triage/chat', {
				method: 'POST',
				credentials: 'include',
				headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
				body: JSON.stringify({ asset_type: assetType, asset_id: assetId, messages })
			});
			if (res.status === 503) throw new Error('Finding chat is not enabled — turn it on under /admin/ai.');
			if (!res.ok) throw new Error(`HTTP ${res.status}`);

			const isStream = (res.headers.get('content-type') ?? '').toLowerCase().includes('text/event-stream');
			if (isStream && res.body) {
				const reader = res.body.getReader();
				const decoder = new TextDecoder();
				let buffer = '';
				for (;;) {
					const { done, value } = await reader.read();
					if (done) break;
					buffer += decoder.decode(value, { stream: true });
					// SSE events end with a blank line; tolerate \r\n.
					const events = buffer.replace(/\r\n/g, '\n').split('\n\n');
					buffer = events.pop() ?? '';
					for (const evt of events) consumeSSEEvent(evt);
				}
				consumeSSEEvent(buffer);
				if (streamingReply.trim()) {
					messages = [...messages, { role: 'assistant', content: streamingReply.trim() }];
				}
			} else {
				// Non-stream reply. Be liberal: a proxy (or version skew)
				// may hand us an SSE-shaped body under a JSON-ish
				// content type — detect and parse it instead of choking.
				const text = await res.text();
				const trimmed = text.trimStart();
				if (trimmed.startsWith('data:')) {
					for (const evt of trimmed.replace(/\r\n/g, '\n').split('\n\n')) consumeSSEEvent(evt);
					if (streamingReply.trim()) {
						messages = [...messages, { role: 'assistant', content: streamingReply.trim() }];
					}
				} else {
					const data = JSON.parse(text) as { reply: string };
					messages = [...messages, { role: 'assistant', content: data.reply }];
				}
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Chat request failed';
		} finally {
			sending = false;
			streamingReply = '';
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
		style={windowStyle()}
		aria-label="Finding chat"
	>
		<!-- Window chrome: drag handle + hide/close. Deliberately not
		     part of the chat surface below. -->
		<!-- svelte-ignore a11y_no_static_element_interactions -->
		<div class="win-chrome" aria-label="Drag to move" onpointerdown={onDragStart}>
			<MessageCircle size={14} />
			<span class="win-title" title={assetSlug}>{assetSlug}</span>
			<div class="win-actions">
				<button type="button" class="win-btn" aria-label={minimized ? 'Restore' : 'Hide'} onclick={() => (minimized = !minimized)} onpointerdown={(e) => e.stopPropagation()}>
					{#if minimized}<Square size={12} />{:else}<Minus size={13} />{/if}
				</button>
				<button type="button" class="win-btn" aria-label="Close" onclick={() => (open = false)} onpointerdown={(e) => e.stopPropagation()}>
					<X size={14} />
				</button>
			</div>
		</div>

		{#if !minimized}
			<div class="chat-body" bind:this={bodyEl}>
				{#if messages.length === 0 && !sending}
					<p class="chat-empty">
						Ask about this finding — exploitability, what to patch first, possible mitigations, or whether it even applies to your setup. The model sees the full evidence: all CVEs with advisories, exposure, and the dashboard's own assessment.
					</p>
				{/if}
				{#each messages as m}
					<div class="chat-msg" class:user={m.role === 'user'}>
						{#if m.role === 'assistant'}
							<div class="chat-bubble chat-md"><Markdown content={m.content} /></div>
						{:else}
							<p class="chat-bubble">{m.content}</p>
						{/if}
					</div>
				{/each}
				{#if sending && streamingReply}
					<div class="chat-msg">
						<div class="chat-bubble chat-md"><Markdown content={streamingReply} /></div>
					</div>
				{:else if sending}
					<div class="chat-msg">
						<p class="chat-bubble chat-thinking">
							Thinking<span class="dots"><span>.</span><span>.</span><span>.</span></span>
						</p>
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

			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div class="chat-resize" aria-label="Resize" onpointerdown={onResizeStart}></div>
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

	/* Outer window chrome — owns drag + hide/close, visually separate
	   from the chat surface. */
	.win-chrome {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 0.7rem;
		cursor: grab;
		user-select: none;
		color: var(--text-secondary);
		background: var(--bg2);
		border-bottom: 1px solid var(--border-color);
		touch-action: none;
		flex-shrink: 0;
	}
	.win-chrome:active {
		cursor: grabbing;
	}
	.chat-window.minimized .win-chrome {
		border-bottom: 0;
	}
	.win-title {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		font-size: 0.8rem;
		font-weight: 600;
		color: var(--text-bright);
	}
	.win-actions {
		display: inline-flex;
		gap: 0.2rem;
	}
	.win-btn {
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
	.win-btn:hover {
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
	.chat-bubble {
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
	.chat-msg.user .chat-bubble {
		color: var(--text-bright);
		background: color-mix(in srgb, var(--accent) 14%, transparent);
	}
	/* Markdown bubbles handle their own block flow. */
	.chat-md {
		white-space: normal;
	}
	.chat-md :global(p) {
		margin: 0 0 0.45rem;
	}
	.chat-md :global(p:last-child) {
		margin-bottom: 0;
	}
	.chat-md :global(ul),
	.chat-md :global(ol) {
		margin: 0.25rem 0 0.45rem;
		padding-left: 1.1rem;
	}
	.chat-md :global(code) {
		font-size: 0.72rem;
		background: var(--hover-bg);
		border-radius: 0.25rem;
		padding: 0.05rem 0.3rem;
	}
	.chat-md :global(pre) {
		overflow-x: auto;
		background: var(--hover-bg);
		border-radius: 0.5rem;
		padding: 0.5rem;
		margin: 0.35rem 0;
	}
	.chat-md :global(h1),
	.chat-md :global(h2),
	.chat-md :global(h3),
	.chat-md :global(h4) {
		font-size: 0.82rem;
		font-weight: 700;
		margin: 0.5rem 0 0.25rem;
		color: var(--text-bright);
	}

	.chat-thinking {
		font-style: italic;
		color: var(--text-muted);
	}
	.dots span {
		display: inline-block;
		animation: chat-dot 1.2s infinite ease-in-out;
	}
	.dots span:nth-child(2) {
		animation-delay: 0.18s;
	}
	.dots span:nth-child(3) {
		animation-delay: 0.36s;
	}
	@keyframes chat-dot {
		0%,
		60%,
		100% {
			transform: translateY(0);
			opacity: 0.4;
		}
		30% {
			transform: translateY(-3px);
			opacity: 1;
		}
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
		flex-shrink: 0;
	}
	.chat-input {
		flex: 1;
		resize: none;
		font-size: 0.8rem;
	}
	.chat-send {
		padding: 0.55rem 0.8rem;
	}

	/* Corner grip — two short strokes, no border styling. */
	.chat-resize {
		position: absolute;
		right: 0;
		bottom: 0;
		width: 16px;
		height: 16px;
		cursor: nwse-resize;
		touch-action: none;
		background:
			linear-gradient(135deg, transparent 55%, var(--text-muted) 55%, var(--text-muted) 60%, transparent 60%),
			linear-gradient(135deg, transparent 75%, var(--text-muted) 75%, var(--text-muted) 80%, transparent 80%);
		opacity: 0.6;
	}
	.chat-resize:hover {
		opacity: 1;
	}
</style>
