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

	// ---- Procedural 3D dependency graph (right panel) ----
	type WorldNode = {
		id: number;
		x: number;
		y: number;
		z: number;
		bornMs: number;
		removedAt: number | null;
	};
	type WorldEdge = {
		id: number;
		from: number;
		to: number;
		startMs: number;
	};

	const SPAWN_INTERVAL = 700; // ms — new edge appears every 0.7s
	const EDGE_DURATION = 1800; // ms — each edge takes 1.8s to draw
	const NODE_CAP = 60; // recycle when graph reaches this size
	const RECYCLE_FADE = 900; // ms fade-out for recycled leaves
	const COMFORT_PX = 230; // target screen radius for the graph
	const ROTATION_SPEED = 0.00009; // rad/ms around Y axis
	const TILT = 0.32; // X-axis tilt (radians)
	const FOCAL = 6; // perspective focal — larger = flatter

	let nextNodeId = 1;
	let nextEdgeId = 0;
	let worldNodes = $state<WorldNode[]>([
		{ id: 0, x: 0, y: 0, z: 0, bornMs: 0, removedAt: null }
	]);
	let worldEdges = $state<WorldEdge[]>([]);

	let elapsed = $state(0);
	let zoom = $state(180);
	let lastSpawnMs = -SPAWN_INTERVAL;
	let reduced = $state(false);

	$effect(() => {
		if (typeof window === 'undefined') return;
		const mq = window.matchMedia('(prefers-reduced-motion: reduce)');
		reduced = mq.matches;
		const onChange = () => (reduced = mq.matches);
		mq.addEventListener('change', onChange);
		return () => mq.removeEventListener('change', onChange);
	});

	$effect(() => {
		if (reduced) {
			seedStaticGraph();
			return;
		}
		let raf = 0;
		let start: number | null = null;
		const tick = (t: number) => {
			if (start === null) start = t;
			const e = t - start;
			elapsed = e;

			if (e - lastSpawnMs >= SPAWN_INTERVAL) {
				spawn(e);
				lastSpawnMs = e;
			}
			sweep(e);

			const target = computeTargetZoom();
			zoom += (target - zoom) * 0.04;

			raf = requestAnimationFrame(tick);
		};
		raf = requestAnimationFrame(tick);
		return () => cancelAnimationFrame(raf);
	});

	function easeOutCubic(x: number) {
		return 1 - Math.pow(1 - x, 3);
	}

	function spawn(t: number) {
		if (worldNodes.filter((n) => n.removedAt === null).length >= NODE_CAP) {
			recycleOldestLeaf(t);
		}
		const parent = pickParent();
		const theta = Math.random() * Math.PI * 2;
		const phi = Math.acos(2 * Math.random() - 1);
		const r = 0.55 + Math.random() * 0.45;
		const dx = r * Math.sin(phi) * Math.cos(theta);
		const dy = r * Math.sin(phi) * Math.sin(theta);
		const dz = r * Math.cos(phi);
		const node: WorldNode = {
			id: nextNodeId++,
			x: parent.x + dx,
			y: parent.y + dy,
			z: parent.z + dz,
			bornMs: t,
			removedAt: null
		};
		worldNodes.push(node);
		worldEdges.push({ id: nextEdgeId++, from: parent.id, to: node.id, startMs: t });
	}

	function pickParent(): WorldNode {
		const childCount = new Map<number, number>();
		for (const e of worldEdges) {
			const from = worldNodes.find((n) => n.id === e.from);
			if (!from || from.removedAt !== null) continue;
			childCount.set(e.from, (childCount.get(e.from) ?? 0) + 1);
		}
		const candidates = worldNodes.filter(
			(n) => n.removedAt === null && (childCount.get(n.id) ?? 0) < 3
		);
		if (candidates.length === 0) return worldNodes[0];
		// Light bias toward newer nodes so growth keeps pushing outward
		const weights = candidates.map((n) => 1 + n.bornMs / 8000);
		const total = weights.reduce((a, b) => a + b, 0);
		let pick = Math.random() * total;
		for (let i = 0; i < candidates.length; i++) {
			pick -= weights[i];
			if (pick <= 0) return candidates[i];
		}
		return candidates[candidates.length - 1];
	}

	function recycleOldestLeaf(t: number) {
		const hasChildren = new Set<number>();
		for (const e of worldEdges) {
			const to = worldNodes.find((n) => n.id === e.to);
			if (to && to.removedAt === null) hasChildren.add(e.from);
		}
		const leaves = worldNodes
			.filter((n) => n.id !== 0 && n.removedAt === null && !hasChildren.has(n.id))
			.sort((a, b) => a.bornMs - b.bornMs);
		if (leaves.length > 0) leaves[0].removedAt = t;
	}

	function sweep(t: number) {
		for (let i = worldNodes.length - 1; i >= 0; i--) {
			const n = worldNodes[i];
			if (n.removedAt !== null && t - n.removedAt > RECYCLE_FADE) {
				const id = n.id;
				worldNodes.splice(i, 1);
				for (let j = worldEdges.length - 1; j >= 0; j--) {
					if (worldEdges[j].from === id || worldEdges[j].to === id) {
						worldEdges.splice(j, 1);
					}
				}
			}
		}
	}

	function computeTargetZoom(): number {
		let maxR = 0.5;
		for (const n of worldNodes) {
			if (n.removedAt !== null) continue;
			const r = Math.sqrt(n.x * n.x + n.y * n.y + n.z * n.z);
			if (r > maxR) maxR = r;
		}
		return COMFORT_PX / maxR;
	}

	function seedStaticGraph() {
		const layout = [
			{ x: 1, y: -0.8, z: 0.2 },
			{ x: -1, y: -0.5, z: -0.4 },
			{ x: 0.6, y: 0.9, z: 0.5 },
			{ x: -0.7, y: 0.7, z: -0.3 },
			{ x: 1.6, y: -1.2, z: 0.9 },
			{ x: -1.5, y: -0.9, z: -0.7 }
		];
		for (let i = 0; i < layout.length; i++) {
			const parent = i < 4 ? worldNodes[0] : worldNodes[i - 3];
			worldNodes.push({
				id: nextNodeId++,
				x: parent.x + layout[i].x,
				y: parent.y + layout[i].y,
				z: parent.z + layout[i].z,
				bornMs: 0,
				removedAt: null
			});
			worldEdges.push({
				id: nextEdgeId++,
				from: parent.id,
				to: nextNodeId - 1,
				startMs: -EDGE_DURATION
			});
		}
		zoom = computeTargetZoom();
	}

	type Projected = { id: number; sx: number; sy: number; depth: number; z: number };

	const projected = $derived.by<Projected[]>(() => {
		const ay = elapsed * ROTATION_SPEED;
		const cosY = Math.cos(ay);
		const sinY = Math.sin(ay);
		const cosX = Math.cos(TILT);
		const sinX = Math.sin(TILT);
		const out: Projected[] = [];
		for (const n of worldNodes) {
			const x1 = n.x * cosY + n.z * sinY;
			const z1 = -n.x * sinY + n.z * cosY;
			const y1 = n.y * cosX - z1 * sinX;
			const z2 = n.y * sinX + z1 * cosX;
			const depth = FOCAL / (FOCAL + z2);
			out.push({
				id: n.id,
				sx: x1 * depth * zoom + 300,
				sy: y1 * depth * zoom + 300,
				depth,
				z: z2
			});
		}
		return out;
	});

	const projMap = $derived.by(() => {
		const m = new Map<number, Projected>();
		for (const p of projected) m.set(p.id, p);
		return m;
	});

	const sortedNodes = $derived.by(() => {
		const indexed = worldNodes.map((n, i) => ({ n, p: projected[i] }));
		indexed.sort((a, b) => b.p.z - a.p.z); // far first
		return indexed;
	});

	function edgeProgress(edge: WorldEdge, t: number): number {
		const local = t - edge.startMs;
		if (local <= 0) return 0;
		if (local >= EDGE_DURATION) return 1;
		return easeOutCubic(local / EDGE_DURATION);
	}

	function nodeAlpha(n: WorldNode, t: number): number {
		if (n.removedAt !== null) {
			return Math.max(0, 1 - (t - n.removedAt) / RECYCLE_FADE);
		}
		if (n.id === 0) return 1;
		const incoming = worldEdges.find((e) => e.to === n.id);
		if (!incoming) return 0;
		return 0.2 + 0.8 * edgeProgress(incoming, t);
	}

	function edgeAlpha(e: WorldEdge, t: number): number {
		const from = worldNodes.find((n) => n.id === e.from);
		const to = worldNodes.find((n) => n.id === e.to);
		if (!from || !to) return 0;
		const fromFade =
			from.removedAt !== null ? Math.max(0, 1 - (t - from.removedAt) / RECYCLE_FADE) : 1;
		const toFade = to.removedAt !== null ? Math.max(0, 1 - (t - to.removedAt) / RECYCLE_FADE) : 1;
		return Math.min(fromFade, toFade);
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

	<div class="hero" aria-hidden="true">
		<div class="hero-glow"></div>
		<div class="hero-grid"></div>

		<svg
			class="hero-art"
			viewBox="0 0 600 600"
			preserveAspectRatio="xMidYMid meet"
			fill="none"
			xmlns="http://www.w3.org/2000/svg"
		>
			<!-- Edges (drawn behind nodes). Each line traces from its parent toward the child as edgeProgress climbs from 0→1. -->
			<g stroke="var(--accent)" stroke-width="1.25" stroke-linecap="round">
				{#each worldEdges as edge (edge.id)}
					{@const a = projMap.get(edge.from)}
					{@const b = projMap.get(edge.to)}
					{#if a && b}
						{@const p = edgeProgress(edge, elapsed)}
						{@const alpha = edgeAlpha(edge, elapsed)}
						{@const avgDepth = (a.depth + b.depth) / 2}
						<line
							x1={a.sx}
							y1={a.sy}
							x2={a.sx + (b.sx - a.sx) * p}
							y2={a.sy + (b.sy - a.sy) * p}
							stroke-opacity={0.65 * alpha * (0.55 + 0.45 * avgDepth)}
						/>
					{/if}
				{/each}
			</g>

			<!-- Nodes: back-to-front depth-sorted; size and brightness scale with perspective factor -->
			<g fill="var(--accent)">
				{#each sortedNodes as item (item.n.id)}
					{@const n = item.n}
					{@const p = item.p}
					{@const isRoot = n.id === 0}
					{@const baseR = isRoot ? 5 : 3.2}
					{@const r = baseR * (0.55 + 0.45 * p.depth)}
					<circle
						cx={p.sx}
						cy={p.sy}
						{r}
						opacity={nodeAlpha(n, elapsed) * (0.55 + 0.45 * p.depth)}
					/>
				{/each}
			</g>

			<!-- Soft halo at the root, follows its projected position -->
			{#if projMap.get(0)}
				{@const root = projMap.get(0)!}
				<circle cx={root.sx} cy={root.sy} r={12 * root.depth} fill="var(--accent)" opacity="0.18" />
			{/if}
		</svg>

		<div class="hero-caption">
			<p class="caption-line">Inventory · Advisories · Provenance</p>
		</div>
	</div>
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
		min-height: 100vh;
		margin: 0;
		padding: 0;
		border: none;
		box-shadow: none;
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
		width: min(72%, 680px);
		aspect-ratio: 1;
		transform: translate(-50%, -50%);
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
</style>
