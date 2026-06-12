// Status badge helpers shared by the job-backed admin sections (OSV
// scan, SBOM scan, secret probe). Status strings come from the jobs
// queue; only the terminal/never-run wording differs per section.

export const isJobActive = (status?: string) =>
	status === 'QUEUED' || status === 'RUNNING' || status === 'RETRY';

export const jobStatusLabel = (
	status: string | undefined,
	labels: { succeeded?: string; never?: string } = {}
) => {
	switch (status) {
		case 'QUEUED':
			return 'Queued';
		case 'RUNNING':
			return 'Running…';
		case 'RETRY':
			return 'Retrying';
		case 'SUCCEEDED':
			return labels.succeeded ?? 'Completed';
		case 'FAILED':
			return 'Failed';
		default:
			return labels.never ?? 'Never run';
	}
};

export const jobStatusClass = (status?: string) => {
	switch (status) {
		case 'RUNNING':
		case 'QUEUED':
		case 'RETRY':
			return 'text-amber-400 border-amber-400/40';
		case 'SUCCEEDED':
			return 'text-green-400 border-green-400/40';
		case 'FAILED':
			return 'text-[var(--error)] border-[var(--error)]/40';
		default:
			return 'text-[var(--text-tertiary)] border-[var(--border-color)]';
	}
};
