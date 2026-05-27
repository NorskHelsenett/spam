import { redirect } from '@sveltejs/kit';
import { browser } from '$app/environment';
import { get } from 'svelte/store';
import { hasOnlyClusters, loadSession } from '$lib/stores/session';

// Same pattern as /secrets/+page.ts: keep cluster-only users from
// hitting /inventory at all. /api/app/summary 404s for them anyway
// (requireUnrestrictedRepos), so deep-linking here would otherwise
// just show a broken state until the in-page redirect fired.
export const load = async () => {
	if (!browser) return {};
	await loadSession();
	if (get(hasOnlyClusters)) {
		throw redirect(307, '/');
	}
	return {};
};
