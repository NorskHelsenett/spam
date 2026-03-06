import { writable } from 'svelte/store';

export type NewUserPayload = {
	id: string;
	subject: string;
	email?: string;
	name?: string;
	approved: boolean;
	hidden: boolean;
	role: string;
	groups: string[];
	created_at: string;
};

export const newUserCount = writable(0);
export const newUserEvent = writable<NewUserPayload | null>(null);
