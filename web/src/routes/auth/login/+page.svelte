<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import ArrowRight from 'lucide-svelte/icons/arrow-right';
	import Package from 'lucide-svelte/icons/package';

	let loading = $state(false);

	onMount(async () => {
		try {
			const response = await fetch('/api/auth/me', { credentials: 'include' });
			if (response.ok) goto('/app');
		} catch {
			// not logged in — stay
		}
	});

	function handleLogin() {
		loading = true;
		window.location.href = '/api/auth/login';
	}
</script>

<svelte:head>
	<title>Sign in — SPAM</title>
</svelte:head>

<div class="page">
	<aside class="panel">
		<header class="brand">
			<span class="mark" aria-hidden="true">
				<Package size={18} strokeWidth={2.25} />
			</span>
			<span class="wordmark">SPAM</span>
		</header>

		<div class="body">
			<p class="eyebrow">Sign in</p>
			<h1>Continue to your dashboard.</h1>
			<p class="lede">
				Authenticate with your organization's identity provider to access SBOM inventory, advisories
				and asset health.
			</p>

			<button class="btn btn-primary cta" onclick={handleLogin} disabled={loading}>
				<span>{loading ? 'Redirecting…' : 'Continue with SSO'}</span>
				<ArrowRight size={16} strokeWidth={2.25} />
			</button>

			<p class="hint">
				You will be redirected to your identity provider. No credentials are stored by SPAM.
			</p>
		</div>

		<footer class="meta">
			<span>Software Package Asset Management</span>
			<span class="dot-sep">·</span>
			<span>Norsk Helsenett SF</span>
		</footer>
	</aside>

	<section class="hero" aria-hidden="true">
		<div class="hero-glow"></div>
		<div class="hero-grid"></div>

		<svg
			class="hero-art"
			viewBox="0 0 600 600"
			fill="none"
			xmlns="http://www.w3.org/2000/svg"
		>
			<defs>
				<linearGradient id="topFace" x1="0.5" y1="0" x2="0.5" y2="1">
					<stop offset="0%" stop-color="var(--accent)" stop-opacity="0.45" />
					<stop offset="100%" stop-color="var(--accent)" stop-opacity="0.15" />
				</linearGradient>
				<linearGradient id="leftFace" x1="0" y1="0" x2="1" y2="1">
					<stop offset="0%" stop-color="var(--warning)" stop-opacity="0.28" />
					<stop offset="100%" stop-color="var(--warning)" stop-opacity="0.06" />
				</linearGradient>
				<linearGradient id="rightFace" x1="1" y1="0" x2="0" y2="1">
					<stop offset="0%" stop-color="var(--accent-dark)" stop-opacity="0.22" />
					<stop offset="100%" stop-color="var(--accent-dark)" stop-opacity="0.04" />
				</linearGradient>
			</defs>

			<!-- 3 visible faces of an isometric cube -->
			<polygon points="300,100 473,200 300,300 127,200" fill="url(#topFace)" />
			<polygon points="127,200 300,300 300,500 127,400" fill="url(#leftFace)" />
			<polygon points="473,200 473,400 300,500 300,300" fill="url(#rightFace)" />

			<!-- Outer silhouette -->
			<polygon
				points="300,100 473,200 473,400 300,500 127,400 127,200"
				stroke="var(--accent)"
				stroke-width="1.5"
				stroke-opacity="0.7"
				stroke-linejoin="round"
			/>

			<!-- Interior Y (3 edges meeting at front-bottom corner) -->
			<g stroke="var(--accent)" stroke-opacity="0.55" stroke-width="1.25" stroke-linecap="round">
				<line x1="300" y1="100" x2="300" y2="300" />
				<line x1="127" y1="200" x2="300" y2="300" />
				<line x1="473" y1="200" x2="300" y2="300" />
			</g>

			<!-- Vertex nodes (read as "components" / SBOM) -->
			<g fill="var(--accent)">
				<circle cx="300" cy="100" r="4" />
				<circle cx="473" cy="200" r="4" />
				<circle cx="473" cy="400" r="4" />
				<circle cx="300" cy="500" r="4" />
				<circle cx="127" cy="400" r="4" />
				<circle cx="127" cy="200" r="4" />
				<circle cx="300" cy="300" r="5" />
			</g>

			<!-- Faint orbital cube hint -->
			<g
				stroke="var(--accent)"
				stroke-opacity="0.18"
				stroke-width="0.75"
				stroke-dasharray="3 5"
				fill="none"
			>
				<polygon points="300,40 545,180 545,420 300,560 55,420 55,180" />
			</g>
		</svg>

		<div class="hero-caption">
			<p class="caption-line">Inventory · Advisories · Provenance</p>
		</div>
	</section>
</div>

<style>
	.page {
		min-height: 100vh;
		display: grid;
		grid-template-columns: 2fr 3fr;
		background-color: var(--main-content-bg);
		color: var(--text-primary);
	}

	/* ---------- Left panel ---------- */
	.panel {
		display: grid;
		grid-template-rows: auto 1fr auto;
		padding: 3em 4.5em;
		min-height: 100vh;
	}

	.brand {
		display: flex;
		align-items: center;
		gap: 0.65rem;
	}

	.mark {
		width: 32px;
		height: 32px;
		display: grid;
		place-items: center;
		border-radius: 9px;
		background: linear-gradient(135deg, var(--accent), var(--accent-dark));
		color: var(--main-content-bg);
		box-shadow: 0 8px 20px -10px var(--accent);
	}

	.wordmark {
		font-size: 1rem;
		font-weight: 700;
		letter-spacing: 0.18em;
		color: var(--text-bright);
	}

	.body {
		align-self: center;
		max-width: 480px;
		display: flex;
		flex-direction: column;
		gap: 1.25rem;
	}

	.eyebrow {
		margin: 0;
		font-size: 0.72rem;
		font-weight: 600;
		letter-spacing: 0.2em;
		text-transform: uppercase;
		color: var(--accent);
	}

	h1 {
		margin: 0;
		font-size: clamp(2rem, 3vw, 2.75rem);
		line-height: 1.1;
		font-weight: 700;
		letter-spacing: -0.02em;
		color: var(--text-bright);
	}

	.lede {
		margin: 0;
		font-size: 0.95rem;
		line-height: 1.6;
		color: var(--text-tertiary);
	}

	.cta {
		align-self: flex-start;
		margin-top: 0.5rem;
		padding: 0.7rem 1.25rem;
	}

	.hint {
		margin: 0;
		font-size: 0.78rem;
		line-height: 1.55;
		color: var(--text-muted);
	}

	.meta {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.75rem;
		color: var(--text-muted);
	}

	.dot-sep {
		opacity: 0.55;
	}

	/* ---------- Right hero ---------- */
	.hero {
		position: relative;
		overflow: hidden;
		background:
			radial-gradient(
				ellipse at 75% 15%,
				color-mix(in srgb, var(--accent) 22%, transparent) 0%,
				transparent 55%
			),
			radial-gradient(
				ellipse at 20% 90%,
				color-mix(in srgb, var(--warning) 14%, transparent) 0%,
				transparent 50%
			),
			linear-gradient(135deg, var(--card-bg) 0%, var(--main-content-bg) 60%);
	}

	.hero-glow {
		position: absolute;
		inset: -20% -10% auto auto;
		width: 60%;
		aspect-ratio: 1;
		background: radial-gradient(
			circle,
			color-mix(in srgb, var(--accent) 30%, transparent) 0%,
			transparent 65%
		);
		filter: blur(40px);
		pointer-events: none;
	}

	.hero-grid {
		position: absolute;
		inset: 0;
		background-image: radial-gradient(
			circle at 1px 1px,
			color-mix(in srgb, var(--text-bright) 8%, transparent) 1px,
			transparent 0
		);
		background-size: 28px 28px;
		mask-image: radial-gradient(ellipse at center, black 0%, transparent 75%);
		-webkit-mask-image: radial-gradient(ellipse at center, black 0%, transparent 75%);
		pointer-events: none;
	}

	.hero-art {
		position: absolute;
		top: 50%;
		left: 50%;
		width: min(70%, 640px);
		transform: translate(-50%, -52%);
		animation: float 18s ease-in-out infinite;
		filter: drop-shadow(0 24px 60px rgba(0, 0, 0, 0.35));
	}

	@keyframes float {
		0%,
		100% {
			transform: translate(-50%, -52%);
		}
		50% {
			transform: translate(-50%, -55%);
		}
	}

	.hero-caption {
		position: absolute;
		left: 2.5rem;
		bottom: 2rem;
		font-size: 0.72rem;
		font-weight: 500;
		letter-spacing: 0.2em;
		text-transform: uppercase;
		color: var(--text-quaternary);
	}

	.caption-line {
		margin: 0;
	}

	/* ---------- Responsive ---------- */
	@media (max-width: 960px) {
		.page {
			grid-template-columns: 1fr;
		}

		.hero {
			display: none;
		}

		.panel {
			padding: 2.5em 2em;
		}
	}

	@media (prefers-reduced-motion: reduce) {
		.hero-art {
			animation: none;
		}
	}
</style>
