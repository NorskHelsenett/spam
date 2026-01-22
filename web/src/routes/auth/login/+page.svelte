<script lang="ts">
	import { onMount } from 'svelte';
	import { Lock, ArrowRight, Shield } from 'lucide-svelte';
	
	onMount(async () => {
		try {
			// Check if already authenticated
			const response = await fetch('/api/auth/me', {
				credentials: 'include'
			});
			
			if (response.ok) {
				// Already logged in, redirect to app
				window.location.href = '/app';
			}
		} catch (error) {
			// Not logged in, stay on login page
		}
	});
	
	function handleLogin() {
		// Initiate OIDC flow via backend
		window.location.href = '/api/auth/login';
	}
</script>

<svelte:head>
	<title>Sign In - SPAM Dashboard</title>
</svelte:head>

<div class="login-page">
	<div class="login-container">
		<div class="login-left">
			<div class="login-content">
				<div class="logo">
					<Shield size={32} />
					<span>SPAM Dashboard</span>
				</div>
				
				<h1 class="login-title">Welcome Back</h1>
				<p class="login-description">
					Sign in with your organization's identity provider to access your monitoring dashboard.
				</p>
				
				<button class="login-button" on:click={handleLogin}>
					<Lock size={20} />
					<span>Sign In with OIDC</span>
					<ArrowRight size={20} />
				</button>
				
				<div class="login-footer">
					<Shield size={16} />
					<span>Secured by enterprise authentication</span>
				</div>
			</div>
		</div>
		
		<div class="login-right">
			<div class="login-image">
				<div class="image-content">
					<div class="code-block">
						<div class="code-header">
							<div class="dot red"></div>
							<div class="dot yellow"></div>
							<div class="dot green"></div>
						</div>
						<div class="code-body">
							<div class="code-line">
								<span class="keyword">package</span> main
							</div>
							<div class="code-line empty"></div>
							<div class="code-line">
								<span class="keyword">import</span> (
							</div>
							<div class="code-line indent">
								<span class="string">"github.com/spam/monitor"</span>
							</div>
							<div class="code-line indent">
								<span class="string">"github.com/spam/auth"</span>
							</div>
							<div class="code-line">)
							</div>
							<div class="code-line empty"></div>
							<div class="code-line">
								<span class="keyword">func</span> <span class="function">main</span>() {'{'} 
							</div>
							<div class="code-line indent">
								<span class="comment">// Initialize secure monitoring</span>
							</div>
							<div class="code-line indent">
								auth.<span class="function">EnableOIDC</span>()
							</div>
							<div class="code-line indent">
								monitor.<span class="function">Start</span>()
							</div>
							<div class="code-line">{'}'}
							</div>
						</div>
					</div>
					
					<div class="stats-grid">
						<div class="stat-card">
							<div class="stat-value">99.9%</div>
							<div class="stat-label">Uptime</div>
						</div>
						<div class="stat-card">
							<div class="stat-value">&lt; 50ms</div>
							<div class="stat-label">Response Time</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>

<style>
	.login-page {
		min-height: 100vh;
		background-color: var(--main-content-bg);
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 2rem;
	}

	.login-container {
		width: 100%;
		max-width: 1200px;
		display: grid;
		grid-template-columns: 1fr 1fr;
		background-color: var(--card-bg);
		border: 1px solid var(--border-color);
		border-radius: 16px;
		overflow: hidden;
		min-height: 600px;
	}

	.login-left {
		padding: 4rem 3rem;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.login-content {
		width: 100%;
		max-width: 400px;
		display: flex;
		flex-direction: column;
		gap: 2rem;
	}

	.logo {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		color: var(--accent);
		font-size: 1.25rem;
		font-weight: 700;
	}

	.login-title {
		font-size: 2.5rem;
		font-weight: 800;
		color: var(--text-bright);
		margin: 0;
		line-height: 1.2;
	}

	.login-description {
		font-size: 1rem;
		line-height: 1.6;
		color: var(--text-secondary);
		margin: 0;
	}

	.login-button {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.75rem;
		padding: 1.25rem 2rem;
		background-color: var(--accent);
		color: var(--main-content-bg);
		font-size: 1.125rem;
		font-weight: 600;
		border: none;
		border-radius: 8px;
		cursor: pointer;
		transition: all 0.2s ease;
		width: 100%;
	}

	.login-button:hover {
		background-color: var(--accent-dark);
		transform: translateY(-2px);
	}

	.login-button:active {
		transform: translateY(0);
	}

	.login-footer {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.875rem;
		color: var(--text-tertiary);
		padding-top: 1rem;
		border-top: 1px solid var(--border-color);
	}

	.login-right {
		background-color: var(--hover-bg);
		padding: 4rem 3rem;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.login-image {
		width: 100%;
		height: 100%;
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.image-content {
		display: flex;
		flex-direction: column;
		gap: 2rem;
		width: 100%;
	}

	.code-block {
		background-color: var(--card-bg);
		border: 1px solid var(--border-color);
		border-radius: 12px;
		overflow: hidden;
	}

	.code-header {
		display: flex;
		gap: 0.5rem;
		padding: 1rem 1.25rem;
		background-color: var(--hover-bg);
		border-bottom: 1px solid var(--border-color);
	}

	.dot {
		width: 12px;
		height: 12px;
		border-radius: 50%;
	}

	.dot.red {
		background-color: var(--error);
	}

	.dot.yellow {
		background-color: var(--warning);
	}

	.dot.green {
		background-color: var(--success);
	}

	.code-body {
		padding: 1.5rem 1.25rem;
		font-family: 'Fira Code', 'Monaco', 'Courier New', monospace;
		font-size: 0.875rem;
		line-height: 1.8;
	}

	.code-line {
		color: var(--text-secondary);
	}

	.code-line.empty {
		height: 1.8em;
	}

	.code-line.indent {
		padding-left: 2rem;
	}

	.keyword {
		color: var(--error);
		font-weight: 600;
	}

	.function {
		color: var(--accent);
	}

	.string {
		color: var(--success);
	}

	.comment {
		color: var(--text-muted);
		font-style: italic;
	}

	.stats-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 1rem;
	}

	.stat-card {
		background-color: var(--card-bg);
		border: 1px solid var(--border-color);
		border-radius: 10px;
		padding: 1.5rem;
		text-align: center;
	}

	.stat-value {
		font-size: 1.75rem;
		font-weight: 700;
		color: var(--accent);
		margin-bottom: 0.5rem;
	}

	.stat-label {
		font-size: 0.875rem;
		color: var(--text-tertiary);
	}

	/* Responsive Design */
	@media (max-width: 1024px) {
		.login-container {
			grid-template-columns: 1fr;
		}

		.login-right {
			display: none;
		}

		.login-left {
			padding: 3rem 2rem;
		}
	}

	@media (max-width: 640px) {
		.login-page {
			padding: 1rem;
		}

		.login-left {
			padding: 2rem 1.5rem;
		}

		.login-title {
			font-size: 2rem;
		}

		.login-button {
			font-size: 1rem;
			padding: 1rem 1.5rem;
		}
	}
</style>
