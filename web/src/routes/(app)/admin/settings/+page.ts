import { redirect } from '@sveltejs/kit';

// /admin/settings has no content of its own — land on the first tab.
export const load = () => {
	redirect(307, '/admin/settings/providers');
};
