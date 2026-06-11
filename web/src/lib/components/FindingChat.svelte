<script lang="ts">
	import { tick } from 'svelte';
	import { Bot, Minus, RotateCcw, Send, Square, X } from 'lucide-svelte';
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
	let retryAttempt = $state(0); // attempt about to run; 0 = first try
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
			historyIdx = null;
			historyDraft = '';
		}
	});

	// --- Window geometry ------------------------------------------
	// Anchored bottom-right until the user drags (converts to explicit
	// left/top) or resizes (also fixes the size). The chrome bar is
	// the drag handle; the corner grip resizes.
	let pos = $state<{ left: number; top: number } | null>(null);
	let size = $state<{ w: number; h: number } | null>(null);
	let dragFrom: { x: number; y: number; left: number; top: number } | null = null;
	let resizeFrom: { x: number; y: number; w: number; h: number; left: number; top: number } | null = null;
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

	// Any edge or corner resizes; opposite edges stay pinned.
	type Edges = { n?: boolean; s?: boolean; e?: boolean; w?: boolean };
	let resizeEdges: Edges = {};
	const onResizeStart = (edges: Edges) => (e: PointerEvent) => {
		if (!winEl) return;
		e.stopPropagation();
		const rect = winEl.getBoundingClientRect();
		pos = { left: rect.left, top: rect.top };
		resizeEdges = edges;
		resizeFrom = { x: e.clientX, y: e.clientY, w: rect.width, h: rect.height, left: rect.left, top: rect.top };
		(e.target as HTMLElement).setPointerCapture?.(e.pointerId);
		window.addEventListener('pointermove', onResizeMove);
		window.addEventListener('pointerup', onResizeEnd, { once: true });
	};
	const onResizeMove = (e: PointerEvent) => {
		if (!resizeFrom) return;
		const dx = e.clientX - resizeFrom.x;
		const dy = e.clientY - resizeFrom.y;
		let w = resizeFrom.w;
		let h = resizeFrom.h;
		if (resizeEdges.e) w += dx;
		if (resizeEdges.w) w -= dx;
		if (resizeEdges.s) h += dy;
		if (resizeEdges.n) h -= dy;
		w = Math.min(Math.max(w, 300), window.innerWidth - 16);
		h = Math.min(Math.max(h, 320), window.innerHeight - 16);
		// Dragging the west/north edge moves the origin so the
		// opposite edge stays where it is.
		const left = resizeEdges.w ? resizeFrom.left + (resizeFrom.w - w) : resizeFrom.left;
		const top = resizeEdges.n ? resizeFrom.top + (resizeFrom.h - h) : resizeFrom.top;
		pos = { left, top };
		size = { w, h };
	};
	const onResizeEnd = () => {
		resizeFrom = null;
		resizeEdges = {};
		window.removeEventListener('pointermove', onResizeMove);
	};

	// Minimizing docks the window back to its bottom-right home.
	const toggleMinimize = () => {
		minimized = !minimized;
		if (minimized) pos = null;
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

	// Errors that more attempts won't fix (config / client errors).
	class NoRetryError extends Error {}

	const sleep = (ms: number, signal: AbortSignal) =>
		new Promise<void>((resolve) => {
			const done = () => {
				clearTimeout(timer);
				signal.removeEventListener('abort', done);
				resolve();
			};
			const timer = setTimeout(done, ms);
			signal.addEventListener('abort', done);
		});

	// attemptOnce runs a single request/stream cycle and returns the
	// assistant's reply text (possibly empty). Throws on transport or
	// server-reported errors.
	const attemptOnce = async (signal: AbortSignal): Promise<string> => {
		streamingReply = '';
		const res = await fetch('/api/triage/chat', {
			method: 'POST',
			credentials: 'include',
			headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
			body: JSON.stringify({ asset_type: assetType, asset_id: assetId, messages }),
			signal
		});
		if (res.status === 503) throw new NoRetryError('Finding chat is not enabled — turn it on under /admin/ai.');
		if (!res.ok) {
			// Client errors won't be fixed by retrying; server hiccups might.
			const fatal = res.status >= 400 && res.status < 500 && res.status !== 429;
			throw fatal ? new NoRetryError(`HTTP ${res.status}`) : new Error(`HTTP ${res.status}`);
		}

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
			return streamingReply.trim();
		}

		// Non-stream reply. Be liberal: a proxy (or version skew)
		// may hand us an SSE-shaped body under a JSON-ish
		// content type — detect and parse it instead of choking.
		const text = await res.text();
		const trimmed = text.trimStart();
		if (trimmed.startsWith('data:')) {
			for (const evt of trimmed.replace(/\r\n/g, '\n').split('\n\n')) consumeSSEEvent(evt);
			return streamingReply.trim();
		}
		return (JSON.parse(text) as { reply: string }).reply;
	};

	// request streams a reply for the conversation as it stands,
	// auto-retrying transient failures (network drops, 5xx, stream
	// errors, empty replies) before surfacing the error + Resend.
	const MAX_ATTEMPTS = 3;
	let aborter: AbortController | null = null;
	const request = async () => {
		error = '';
		sending = true;
		retryAttempt = 0;
		aborter = new AbortController();
		const { signal } = aborter;
		void scrollToEnd();
		try {
			for (let attempt = 1; ; attempt++) {
				try {
					const reply = (await attemptOnce(signal)).trim();
					if (!reply) throw new Error('The model returned an empty reply');
					messages = [...messages, { role: 'assistant', content: reply }];
					return;
				} catch (e) {
					if (signal.aborted || e instanceof NoRetryError || attempt >= MAX_ATTEMPTS) throw e;
					retryAttempt = attempt + 1;
					await sleep(attempt * 1500, signal);
					if (signal.aborted) return;
				}
			}
		} catch (e) {
			// Closing the window aborts the request — not an error.
			if (signal.aborted || (e instanceof DOMException && e.name === 'AbortError')) return;
			error = e instanceof Error ? e.message : 'Chat request failed';
		} finally {
			sending = false;
			retryAttempt = 0;
			streamingReply = '';
			void scrollToEnd();
		}
	};

	const send = async () => {
		const text = input.trim();
		if (!text || sending) return;
		input = '';
		historyIdx = null;
		historyDraft = '';
		messages = [...messages, { role: 'user', content: text }];
		await request();
	};

	const resend = () => {
		if (sending || messages.length === 0) return;
		void request();
	};

	// Starter queries shown while the conversation is empty. Each maps
	// to evidence the grounding payload actually carries (tier reasons,
	// exposure, fix versions, image metadata).
	const suggestions = [
		'Is this actually exploitable in our environment?',
		'What should we patch first, and to which version?',
		'Can we mitigate this without upgrading?',
		'Why did this finding get its tier — do you agree?',
		'Write a short summary for a ticket.'
	];

	const sendSuggestion = (q: string) => {
		if (sending) return;
		input = q;
		void send();
	};

	// Closing discards the conversation; reopening starts fresh.
	const close = () => {
		open = false;
		aborter?.abort();
		messages = [];
		input = '';
		error = '';
		messagesFor = '';
		historyIdx = null;
		historyDraft = '';
	};

	// --- Input history --------------------------------------------
	// Arrow up/down in the input recalls previously sent messages,
	// shell-style. Arrows are only hijacked at the edge of the text
	// so caret movement inside a multi-line draft still works.
	let historyIdx: number | null = null;
	let historyDraft = '';

	const navigateHistory = (e: KeyboardEvent) => {
		const el = e.currentTarget as HTMLTextAreaElement;
		const hist = messages.filter((m) => m.role === 'user').map((m) => m.content);
		if (hist.length === 0) return;
		if (e.key === 'ArrowUp') {
			if (el.value.slice(0, el.selectionStart).includes('\n')) return;
			if (historyIdx === null) {
				historyDraft = input;
				historyIdx = hist.length - 1;
			} else if (historyIdx > 0) {
				historyIdx -= 1;
			}
			input = hist[historyIdx];
		} else {
			if (historyIdx === null) return;
			if (el.value.slice(el.selectionEnd).includes('\n')) return;
			if (historyIdx < hist.length - 1) {
				historyIdx += 1;
				input = hist[historyIdx];
			} else {
				// Walked past the newest entry — restore the draft.
				historyIdx = null;
				input = historyDraft;
			}
		}
		e.preventDefault();
		void tick().then(() => el.setSelectionRange(el.value.length, el.value.length));
	};

	const onKeydown = (e: KeyboardEvent) => {
		if (e.key === 'Enter' && !e.shiftKey) {
			e.preventDefault();
			void send();
		} else if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
			navigateHistory(e);
		}
	};
</script>

{#if open}
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<section
		bind:this={winEl}
		class="chat-window"
		class:minimized
		class:engaged={messages.length > 0 || sending}
		style={windowStyle()}
		aria-label="Finding chat"
		onpointerdown={(e) => {
			// Grabbing the bare frame (not chat content / controls /
			// resize strips) moves the window, same as the title bar.
			if (e.target === e.currentTarget) onDragStart(e);
		}}
	>
		<!-- Window chrome: drag handle + hide/close. Deliberately not
		     part of the chat surface below. -->
		<!-- svelte-ignore a11y_no_static_element_interactions -->
		<div class="win-chrome" aria-label="Drag to move" onpointerdown={onDragStart}>
			<Bot size={15} />
			<span class="win-title" title={assetSlug}>{assetSlug}</span>
		</div>
		<!-- Window controls live on the outer title border, not in the
		     chat surface. -->
		<div class="win-actions">
			<button type="button" class="win-btn" aria-label={minimized ? 'Restore' : 'Hide'} onclick={toggleMinimize} onpointerdown={(e) => e.stopPropagation()}>
				{#if minimized}<Square size={12} />{:else}<Minus size={13} />{/if}
			</button>
			<button type="button" class="win-btn" aria-label="Close" onclick={close} onpointerdown={(e) => e.stopPropagation()}>
				<X size={14} />
			</button>
		</div>

		{#if !minimized}
			<div class="chat-body" bind:this={bodyEl}>
				{#if messages.length === 0 && !sending}
					<p class="chat-empty">
						Ask about this finding — exploitability, what to patch first, possible mitigations, or whether it even applies to your setup. The model sees the full evidence: all CVEs with advisories, exposure, image metadata and labels, and the dashboard's own assessment.
					</p>
					<div class="chat-suggestions">
						{#each suggestions as q}
							<button type="button" class="chat-suggestion" onclick={() => sendSuggestion(q)}>{q}</button>
						{/each}
					</div>
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
							{#if retryAttempt}Hit a snag — retrying ({retryAttempt}/{MAX_ATTEMPTS}){:else}Thinking{/if}<span class="dots"><span>.</span><span>.</span><span>.</span></span>
						</p>
					</div>
				{/if}
				{#if error}
					<div class="chat-error-row">
						<p class="chat-error">{error}</p>
						<button type="button" class="chat-retry" onclick={resend} disabled={sending}>
							<RotateCcw size={12} />
							Resend
						</button>
					</div>
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

		{#if !minimized}
			<!-- Resize handles on every edge and corner. -->
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div class="rz rz-n" onpointerdown={onResizeStart({ n: true })}></div>
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div class="rz rz-s" onpointerdown={onResizeStart({ s: true })}></div>
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div class="rz rz-e" onpointerdown={onResizeStart({ e: true })}></div>
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div class="rz rz-w" onpointerdown={onResizeStart({ w: true })}></div>
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div class="rz rz-ne" onpointerdown={onResizeStart({ n: true, e: true })}></div>
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div class="rz rz-nw" onpointerdown={onResizeStart({ n: true, w: true })}></div>
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div class="rz rz-se" onpointerdown={onResizeStart({ s: true, e: true })}></div>
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<div class="rz rz-sw" onpointerdown={onResizeStart({ s: true, w: true })}></div>
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
		width: min(68rem, calc(100vw - 2rem));
		max-height: calc(100vh - 4rem);
		border-radius: 0.9rem;
		background: var(--main-content-bg);
		border: 1px solid var(--border-color);
		box-shadow: 0 14px 40px rgba(0, 0, 0, 0.45);
	}
	/* The start window stays content-sized (empty-state blurb +
	   starter queries + input). Once a conversation is underway the
	   window takes its full working height — fixed, not max, so it
	   doesn't collapse to fit a short exchange. */
	.chat-window.engaged {
		height: min(48rem, calc(100vh - 4rem));
	}
	/* Minimized docks as a compact chip: title bar only, narrow.
	   Declared after .engaged so it wins while a chat is running. */
	.chat-window.minimized {
		width: min(22rem, calc(100vw - 2rem));
		height: auto;
		max-height: none;
	}

	/* Outer window chrome — owns drag + hide/close, visually separate
	   from the chat surface. */
	.win-chrome {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.5rem 0.7rem;
		border-radius: 0.9rem 0.9rem 0 0;
		cursor: grab;
		user-select: none;
		color: var(--text-secondary);
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
		padding-right: 3.6rem; /* keep clear of the border controls */
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		font-size: 0.8rem;
		font-weight: 600;
		color: var(--text-bright);
	}
	/* Controls anchored to the outer title border (top-right of the
	   frame), above the chrome's drag surface. */
	.win-actions {
		position: absolute;
		top: 0.3rem;
		right: 0.4rem;
		display: inline-flex;
		gap: 0.2rem;
		z-index: 2;
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
	.chat-suggestions {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 0.4rem;
	}
	.chat-suggestion {
		border: 1px solid var(--border-color);
		border-radius: 0.7rem;
		padding: 0.35rem 0.65rem;
		font-size: 0.75rem;
		line-height: 1.4;
		text-align: left;
		color: var(--text-secondary);
		background: transparent;
		cursor: pointer;
		transition: background 120ms ease, color 120ms ease;
	}
	.chat-suggestion:hover {
		background: var(--hover-bg);
		color: var(--text-bright);
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

	.chat-error-row {
		display: flex;
		align-items: baseline;
		justify-content: space-between;
		gap: 0.5rem;
	}
	.chat-error {
		margin: 0;
		font-size: 0.75rem;
		color: var(--error);
	}
	.chat-retry {
		display: inline-flex;
		align-items: center;
		gap: 0.3rem;
		flex-shrink: 0;
		border: 1px solid var(--border-color);
		border-radius: 0.4rem;
		padding: 0.2rem 0.55rem;
		font-size: 0.72rem;
		font-weight: 600;
		color: var(--text-secondary);
		background: transparent;
		cursor: pointer;
		transition: background 120ms ease, color 120ms ease;
	}
	.chat-retry:hover:not(:disabled) {
		background: var(--hover-bg);
		color: var(--text-bright);
	}
	.chat-retry:disabled {
		opacity: 0.5;
		cursor: default;
	}

	.chat-input-row {
		display: flex;
		align-items: flex-end;
		gap: 0.5rem;
		padding: 0.6rem 0.75rem 0.75rem;
		flex-shrink: 0;
	}
	.chat-window.minimized .win-chrome {
		border-radius: 0.9rem;
	}
	.chat-input {
		flex: 1;
		resize: none;
		font-size: 0.8rem;
	}
	.chat-send {
		padding: 0.55rem 0.8rem;
	}

	/* Invisible resize strips on every edge + corner. */
	.rz {
		position: absolute;
		touch-action: none;
		z-index: 3;
	}
	.rz-n { top: -3px; left: 10px; right: 10px; height: 7px; cursor: ns-resize; }
	.rz-s { bottom: -3px; left: 10px; right: 10px; height: 7px; cursor: ns-resize; }
	.rz-e { right: -3px; top: 10px; bottom: 10px; width: 7px; cursor: ew-resize; }
	.rz-w { left: -3px; top: 10px; bottom: 10px; width: 7px; cursor: ew-resize; }
	.rz-ne { top: -3px; right: -3px; width: 13px; height: 13px; cursor: nesw-resize; }
	.rz-nw { top: -3px; left: -3px; width: 13px; height: 13px; cursor: nwse-resize; }
	.rz-se { bottom: -3px; right: -3px; width: 13px; height: 13px; cursor: nwse-resize; }
	.rz-sw { bottom: -3px; left: -3px; width: 13px; height: 13px; cursor: nesw-resize; }
</style>
