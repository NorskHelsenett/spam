import { writable } from 'svelte/store';

export type SyncStatus = 'running' | 'done' | 'failed';

export type ProviderSyncState = {
	provider_id: string;
	provider_name?: string;
	status: SyncStatus;
	started_at?: string;
	finished_at?: string;
	result?: {
		provider_id: string;
		provider_name: string;
		health_status: string;
		health_message?: string;
		total_repos: number;
		queued: number;
		skipped_same: number;
		skipped_pending: number;
	};
	error?: string;
};

export const providerSyncStates = writable<Record<string, ProviderSyncState>>({});

export function updateSyncState(state: ProviderSyncState) {
	providerSyncStates.update((states) => ({ ...states, [state.provider_id]: state }));
}

export function initSyncStates(states: Record<string, ProviderSyncState>) {
	providerSyncStates.set(states);
}
