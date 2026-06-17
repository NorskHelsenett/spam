import { redirect } from '@sveltejs/kit';

// Moved into the consolidated settings hub; keep old links working.
export const load = () => {
	redirect(307, '/admin/settings/ai');
};
