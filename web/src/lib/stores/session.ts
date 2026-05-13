import { writable, derived } from 'svelte/store';

// SessionSnapshot mirrors the /api/auth/me payload that SPAM cares
// about for UX decisions. Empty when the fetch fails — pages should
// branch on `isAdmin` and `loaded` so a still-loading session doesn't
// flash admin-targeted messaging at a regular user.
export type SessionSnapshot = {
	loaded: boolean;
	role: string;
	approved: boolean;
	email?: string;
	name?: string;
};

const empty: SessionSnapshot = { loaded: false, role: '', approved: false };

export const session = writable<SessionSnapshot>(empty);

// isAdmin is the common UX gate — used to hide admin-targeted empty
// states from non-admin users (clusters / providers pages today).
export const isAdmin = derived(session, ($s) => $s.role === 'admin');

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
			session.set({
				loaded: true,
				role: typeof data?.role === 'string' ? data.role : '',
				approved: Boolean(data?.approved),
				email: typeof data?.email === 'string' ? data.email : undefined,
				name: typeof data?.name === 'string' ? data.name : undefined,
			});
		} catch {
			session.set(empty);
		} finally {
			inflight = null;
		}
	})();
	return inflight;
}
