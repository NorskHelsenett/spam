import { writable } from 'svelte/store';

type RepoData = {
	external_id: string;
	name: string;
	full_path: string;
	description: string;
	html_url: string;
	default_branch: string;
	language: string;
	is_private: boolean;
	is_archived: boolean;
	is_fork: boolean;
	topics: string[];
	created_at: string;
	updated_at: string;
	pushed_at: string;
};

type GroupData = {
	external_id: string;
	name: string;
	path: string;
	full_path: string;
	description: string;
	html_url: string;
	parent_id: string;
	visibility: string;
};

type CustomProvider = {
	id: string;
	name: string;
	type: 'gitlab' | 'gitea' | 'forgejo';
	baseUrl: string;
};

export type ProvidersState = {
	activeTab: string;

	// GitHub state
	ghOwner: string;
	ghRepos: RepoData[];
	ghPage: number;
	ghHasNextPage: boolean;
	ghTotalCount: number;

	// GitLab state
	glGroup: string;
	glProjects: RepoData[];
	glSubgroups: GroupData[];
	glPage: number;
	glHasNextPage: boolean;
	glTotalCount: number;
	glIncludeSubgroups: boolean;
	glGroupPath: string[];

	// Custom provider state
	cpGroup: string;
	cpProjects: RepoData[];
	cpSubgroups: GroupData[];
	cpPage: number;
	cpHasNextPage: boolean;
	cpTotalCount: number;
	cpIncludeSubgroups: boolean;
	cpGroupPath: string[];

	// Custom providers list
	customProviders: CustomProvider[];

	// Timestamp of last update
	lastUpdated: number;
};

const initialState: ProvidersState = {
	activeTab: 'github',

	ghOwner: 'NorskHelsenett',
	ghRepos: [],
	ghPage: 1,
	ghHasNextPage: false,
	ghTotalCount: 0,

	glGroup: 'gitlab-org',
	glProjects: [],
	glSubgroups: [],
	glPage: 1,
	glHasNextPage: false,
	glTotalCount: 0,
	glIncludeSubgroups: false,
	glGroupPath: [],

	cpGroup: '',
	cpProjects: [],
	cpSubgroups: [],
	cpPage: 1,
	cpHasNextPage: false,
	cpTotalCount: 0,
	cpIncludeSubgroups: false,
	cpGroupPath: [],

	customProviders: [],

	lastUpdated: 0
};

export const providersState = writable<ProvidersState>(initialState);

export const resetProvidersState = () => {
	providersState.set(initialState);
};
