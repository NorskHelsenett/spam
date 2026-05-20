import { writable, derived } from 'svelte/store';

// SessionSnapshot mirrors the /api/auth/me payload that SPAM cares
// about for UX decisions. Empty when the fetch fails — pages should
// branch on `isAdmin` and `loaded` so a still-loading session doesn't
// flash admin-targeted messaging at a regular user.
//
// `capabilities` is the ACL-derived reveal hint: which surfaces the
// frontend should show. `repos` covers SBOM/secrets/manifest surfaces
// that need git-source grants; `clusters` covers ROR-driven cluster
// inventory. Admins and global_readers come back with both true.
export type Capabilities = {
	repos: boolean;
	clusters: boolean;
};

export type SessionSnapshot = {
	loaded: boolean;
	role: string;
	approved: boolean;
	email?: string;
	name?: string;
	capabilities: Capabilities;
};

const empty: SessionSnapshot = {
	loaded: false,
	role: '',
	approved: false,
	capabilities: { repos: false, clusters: false },
};

export const session = writable<SessionSnapshot>(empty);

// isAdmin is the common UX gate — used to hide admin-targeted empty
// states from non-admin users (clusters / providers pages today).
export const isAdmin = derived(session, ($s) => $s.role === 'admin');

// hasOnlyClusters identifies the cluster-only persona: a user whose
// ACL gives them cluster reads but no repo grants and no admin role.
// Used to hide repo-side surfaces (Secrets, Inventory, Dependencies,
// Providers) from the nav and short-circuit repo-only widgets on
// pages that mix both. Returns false until the session has loaded so
// nothing flashes during the initial /api/auth/me roundtrip.
export const hasOnlyClusters = derived(session, ($s) =>
	$s.loaded && $s.role !== 'admin' && $s.capabilities.clusters && !$s.capabilities.repos,
);

let inflight: Promise<void> | null = null;

// loadSession fetches /api/auth/me once and updates the store. Repeat
// calls share the same in-flight promise so multiple components on
// the same page don't race. Resets `loaded=false` on failure rather
// than throwing — callers that care about errors should check the
// store contents.
export function loadSession(): Promise<void> {
	if (inflight) return inflight;
	inflight = (async () => {
		try {
			const res = await fetch('/api/auth/me', { credentials: 'include' });
			if (!res.ok) {
				session.set(empty);
				return;
			}
			const data = await res.json();
			const caps = data?.capabilities ?? {};
			session.set({
				loaded: true,
				role: typeof data?.role === 'string' ? data.role : '',
				approved: Boolean(data?.approved),
				email: typeof data?.email === 'string' ? data.email : undefined,
				name: typeof data?.name === 'string' ? data.name : undefined,
				capabilities: {
					repos: Boolean(caps?.repos),
					clusters: Boolean(caps?.clusters),
				},
			});
		} catch {
			session.set(empty);
		} finally {
			inflight = null;
		}
	})();
	return inflight;
}
