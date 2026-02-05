export type RepoData = {
	external_id: string;
	name: string;
	full_path: string;
	description: string;
	html_url: string;
	default_branch: string;
	languages: string[];
	is_private: boolean;
	is_archived: boolean;
	is_fork: boolean;
	topics: string[];
	created_at: string;
	updated_at: string;
	pushed_at: string;
};

export type GroupData = {
	external_id: string;
	name: string;
	path: string;
	full_path: string;
	description: string;
	html_url: string;
	parent_id: string;
	visibility: string;
};

export type GitHubResponse = {
	repos: RepoData[];
	total_count: number;
	page: number;
	page_size: number;
	has_next_page: boolean;
	next_page: number;
};

export type GitLabProjectsResponse = {
	projects: RepoData[];
	total_count: number;
	page: number;
	page_size: number;
	has_next_page: boolean;
	next_page: number;
};

export type GitLabGroupsResponse = {
	groups: GroupData[];
	total_count: number;
	page: number;
	page_size: number;
	has_next_page: boolean;
	next_page: number;
};

export type CustomProvider = {
	id: string;
	name: string;
	type: 'github' | 'gitlab' | 'gitea' | 'forgejo';
	baseUrl: string;
	ownerPath?: string;
	isPublic?: boolean;
};
