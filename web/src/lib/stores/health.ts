import { writable } from 'svelte/store';

export type HealthSnapshot = {
    status: 'idle' | 'loading' | 'ok' | 'error';
    message?: string;
    details?: unknown;
    timestamp?: string;
    statusCode?: number;
};

export type HealthStore = {
    subscribe: ReturnType<typeof writable<HealthSnapshot>>['subscribe'];
    refresh: () => Promise<void>;
};

const defaultSnapshot: HealthSnapshot = { status: 'idle' };

export function createHealthStore(endpoint = '/api/healthz', fetcher: typeof fetch = fetch): HealthStore {
    const { subscribe, set } = writable<HealthSnapshot>(defaultSnapshot);

    async function refresh(): Promise<void> {
        set({ status: 'loading' });

        try {
            const response = await fetcher(endpoint, {
                headers: {
                    Accept: 'application/json'
                }
            });

            const timestamp = new Date().toISOString();

            if (!response.ok) {
                set({
                    status: 'error',
                    message: `backend responded with ${response.status}`,
                    timestamp,
                    statusCode: response.status
                });
                return;
            }

            let payload: unknown;
            try {
                payload = await response.json();
            } catch (parseError) {
                set({
                    status: 'error',
                    message: 'invalid JSON payload',
                    details: parseError,
                    timestamp,
                    statusCode: response.status
                });
                return;
            }

            const status = typeof (payload as { status?: unknown })?.status === 'string' ? (payload as { status: string }).status : 'ok';

            set({
                status: 'ok',
                message: status,
                details: payload,
                timestamp,
                statusCode: response.status
            });
        } catch (error) {
            set({
                status: 'error',
                message: error instanceof Error ? error.message : 'request failed',
                details: error,
                timestamp: new Date().toISOString()
            });
        }
    }

    return { subscribe, refresh };
}
