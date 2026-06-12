// Shared types and mapping for the git provider admin UI
// (providers settings page + add-provider form).

export type ProviderType = 'github' | 'gitlab' | 'gitea' | 'forgejo';
export type ProviderTypeMode = ProviderType | 'auto';

export type ProviderRow = {
	id: string;
	providerUrl: string;
	baseUrl: string;
	ownerPath: string;
	type: ProviderType;
	displayName: string;
	tokenFingerprint?: string;
	enabled: boolean;
	pollInterval?: number | null;
	healthStatus: string;
	healthMessage?: string;
	lastHealthCheck?: string;
	createdAt: string;
	updatedAt?: string;
	lastRotatedAt?: string;
};

export type ApiProvider = {
	id: string;
	provider_url: string;
	base_url: string;
	owner_path: string;
	type: ProviderType;
	display_name: string;
	token_fingerprint?: string;
	enabled: boolean;
	poll_interval?: number | null;
	health_status?: string;
	health_message?: string;
	last_health_check?: string;
	created_at: string;
	updated_at?: string;
	last_rotated_at?: string;
};

export const mapProvider = (entry: ApiProvider): ProviderRow => ({
	id: entry.id,
	providerUrl: entry.provider_url,
	baseUrl: entry.base_url,
	ownerPath: entry.owner_path || '',
	type: entry.type,
	displayName: entry.display_name,
	tokenFingerprint: entry.token_fingerprint,
	enabled: entry.enabled,
	pollInterval: entry.poll_interval,
	healthStatus: entry.health_status || 'UNKNOWN',
	healthMessage: entry.health_message,
	lastHealthCheck: entry.last_health_check,
	createdAt: entry.created_at,
	updatedAt: entry.updated_at,
	lastRotatedAt: entry.last_rotated_at
});

export const providerTag = (type: ProviderType | undefined) => {
	switch (type) {
		case 'github':
			return 'GitHub';
		case 'gitlab':
			return 'GitLab';
		case 'gitea':
			return 'Gitea';
		case 'forgejo':
			return 'Forgejo';
		default:
			return 'Unknown';
	}
};
