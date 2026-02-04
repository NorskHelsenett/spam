package jobs

// JobType represents the type of a job.
type JobType = string

const (
	JobTypeParseSBOM        JobType = "PARSE_SBOM"
	JobTypeCreateRun        JobType = "CREATE_RUN"
	JobTypeRefreshSBOMViews JobType = "REFRESH_SBOM_VIEWS"
)
