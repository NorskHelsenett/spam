import { redirect } from '@sveltejs/kit';
import { browser } from '$app/environment';
import { get } from 'svelte/store';
import { hasOnlyClusters, loadSession } from '$lib/stores/session';

// SvelteKit runs `load` before the page renders. Awaiting
// loadSession() here means a cluster-only user lands on /secrets
// (via deep link or back-button) and SvelteKit short-circuits to /
// without ever painting the secrets dashboard, instead of the
// onMount-wait-then-goto dance that briefly rendered the empty
// state. The cluster-feasible Images tab still lives at /secrets in
// the routing tree but the redirect is appropriate while there's no
// repo grants for these users to access the Repositories tab.
export const load = async () => {
	if (!browser) return {};
	await loadSession();
	if (get(hasOnlyClusters)) {
		throw redirect(307, '/');
	}
	return {};
};
