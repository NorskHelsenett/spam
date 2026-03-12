<script lang="ts">
	import { onMount } from 'svelte';
	import { marked } from 'marked';
	import DOMPurify from 'dompurify';

	interface Props {
		content: string;
		class?: string;
	}

	let { content, class: className = '' }: Props = $props();

	let html = $state('');

	// Configure marked
	marked.setOptions({
		gfm: true,
		breaks: true
	});

	// Open all links in a new tab
	const renderer = new marked.Renderer();
	renderer.link = ({ href, title, text }: { href: string; title?: string | null; text: string }) =>
		`<a href="${href}"${title ? ` title="${title}"` : ''} target="_blank" rel="noopener noreferrer">${text}</a>`;
	marked.use({ renderer });

	// Configure DOMPurify
	const sanitize = (dirty: string): string => {
		return DOMPurify.sanitize(dirty, {
			ADD_ATTR: ['target', 'rel'],
			ADD_TAGS: ['iframe'],
			FORBID_TAGS: ['style', 'script'],
			FORBID_ATTR: ['onerror', 'onload', 'onclick']
		});
	};

	$effect(() => {
		if (content) {
			const rendered = marked.parse(content);
			if (typeof rendered === 'string') {
				html = sanitize(rendered);
			} else {
				// Handle promise (async parsing)
				rendered.then((result) => {
					html = sanitize(result);
				});
			}
		} else {
			html = '';
		}
	});
</script>

<div class="prose {className}">
	{@html html}
</div>

<style>
	/* Base styles using theme variables (works for both light and dark) */
	.prose {
		line-height: 1.7;
		color: var(--text-primary);
	}
	.prose :global(h1) {
		font-size: 1.75rem;
		font-weight: 600;
		margin-top: 1.5rem;
		margin-bottom: 0.75rem;
		color: var(--accent);
		border-bottom: 1px solid var(--border-color);
		padding-bottom: 0.5rem;
	}
	.prose :global(h2) {
		font-size: 1.4rem;
		font-weight: 600;
		margin-top: 1.5rem;
		margin-bottom: 0.5rem;
		color: var(--accent);
		border-bottom: 1px solid var(--border-color);
		padding-bottom: 0.375rem;
	}
	.prose :global(h3) {
		font-size: 1.15rem;
		font-weight: 600;
		margin-top: 1.25rem;
		margin-bottom: 0.5rem;
		color: var(--accent);
	}
	.prose :global(h4),
	.prose :global(h5),
	.prose :global(h6) {
		font-size: 1rem;
		font-weight: 600;
		margin-top: 1rem;
		margin-bottom: 0.5rem;
		color: var(--accent);
	}
	.prose :global(p) {
		margin-bottom: 0.75rem;
	}
	.prose :global(strong) {
		font-weight: 600;
	}
	.prose :global(code) {
		background: var(--hover-bg);
		padding: 0.125rem 0.375rem;
		border-radius: 0.25rem;
		font-size: 0.875rem;
		font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
	}
	.prose :global(pre) {
		background: var(--hover-bg);
		padding: 1rem;
		border-radius: 0.5rem;
		border: 1px solid var(--border-color);
		overflow-x: auto;
		max-width: 100%;
		margin: 1rem 0;
	}
	.prose :global(pre code) {
		background: none;
		padding: 0;
	}
	.prose :global(a) {
		color: var(--info);
		text-decoration: underline;
		text-underline-offset: 2px;
	}
	.prose :global(a:hover) {
		text-decoration: none;
	}
	.prose :global(ul) {
		list-style: disc;
		padding-left: 1.5rem;
		margin: 0.5rem 0;
	}
	.prose :global(ol) {
		list-style: decimal;
		padding-left: 1.5rem;
		margin: 0.5rem 0;
	}
	.prose :global(li) {
		margin: 0.25rem 0;
	}
	.prose :global(ul.task-list) {
		list-style: none;
		padding-left: 0;
	}
	.prose :global(li.task-list-item) {
		list-style: none;
	}
	.prose :global(li:has(> input[type='checkbox'])) {
		list-style: none;
	}
	.prose :global(li:has(> input[type='checkbox']))::marker {
		content: '';
	}
	.prose :global(li::marker) {
		color: var(--text-muted);
	}
	.prose :global(li > ul),
	.prose :global(li > ol) {
		margin: 0.25rem 0;
	}
	.prose :global(hr) {
		border-color: var(--border-color);
		margin: 1.5rem 0;
	}
	.prose :global(img) {
		max-width: 100%;
		border-radius: 0.5rem;
		margin: 1rem 0;
		border: 1px solid var(--border-color);
	}
	.prose :global(blockquote) {
		border-left: 3px solid var(--accent);
		background: var(--hover-bg);
		padding: 0.75rem 1rem;
		margin: 0 0 1rem 0;
		color: var(--text-muted);
		font-style: italic;
		border-radius: 0 0.25rem 0.25rem 0;
	}
	.prose :global(blockquote p:last-child) {
		margin-bottom: 0;
	}
	.prose :global(table) {
		width: 100%;
		border-collapse: collapse;
		margin: 1rem 0;
		border: 1px solid var(--border-color);
	}
	.prose :global(th),
	.prose :global(td) {
		border: 1px solid var(--border-color);
		padding: 0.5rem 0.75rem;
		text-align: left;
	}
	.prose :global(th) {
		background: var(--hover-bg);
		color: var(--accent);
		font-weight: 600;
	}
	.prose :global(tr:nth-child(even)) {
		background: var(--hover-bg-subtle);
	}
	.prose :global(input[type='checkbox']) {
		margin-right: 0.5rem;
		accent-color: var(--success);
	}
	.prose :global(del) {
		color: var(--error);
		text-decoration: line-through;
	}
	.prose :global(mark) {
		background: var(--warning);
		color: var(--text-bright);
		padding: 0.1rem 0.25rem;
		border-radius: 0.125rem;
	}

	/* Dark mode Gruvbox overrides */
	:global(html.dark) .prose :global(h1) {
		color: #fe8019; /* gruvbox orange */
	}
	:global(html.dark) .prose :global(h2) {
		color: #fabd2f; /* gruvbox yellow */
	}
	:global(html.dark) .prose :global(h3) {
		color: #b8bb26; /* gruvbox green */
	}
	:global(html.dark) .prose :global(h4) {
		color: #8ec07c; /* gruvbox aqua */
	}
	:global(html.dark) .prose :global(h5),
	:global(html.dark) .prose :global(h6) {
		color: #83a598; /* gruvbox blue */
	}
	:global(html.dark) .prose :global(strong) {
		color: #fe8019; /* gruvbox orange */
	}
	:global(html.dark) .prose :global(em) {
		color: #fabd2f; /* gruvbox yellow */
	}
	:global(html.dark) .prose :global(code) {
		color: #8ec07c; /* gruvbox aqua */
	}
	:global(html.dark) .prose :global(a) {
		color: #83a598; /* gruvbox blue */
	}
	:global(html.dark) .prose :global(a:hover) {
		color: #8ec07c; /* gruvbox aqua */
	}
	:global(html.dark) .prose :global(blockquote) {
		border-left-color: #8ec07c; /* gruvbox aqua */
	}
	:global(html.dark) .prose :global(th) {
		color: #fabd2f; /* gruvbox yellow */
	}
</style>
