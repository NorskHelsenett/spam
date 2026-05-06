package dephealth

import (
	"net/url"
	"regexp"
	"strings"
)

// NormalizeRepoURL turns the wildly inconsistent repository URL
// strings registries publish into a canonical https://host/org/repo
// form, plus the host's provider name ("github" | "gitlab" | "").
//
// npm's `repository.url` field is the worst offender: it can be a
// plain string, an object with {url, type}, or shorthand like
// "github:foo/bar". Go modules sometimes embed the URL inside a
// longer path. PyPI varies by maintainer. We normalise once here so
// the GitHub/GitLab fetchers downstream don't each carry their own
// quirks.
//
// Returns ("", "") when the input doesn't resolve to a recognised
// provider — caller treats that as "no source repo, leave activity
// fields blank".
func NormalizeRepoURL(raw string) (string, string) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ""
	}

	// npm shorthand: "github:foo/bar" or "gitlab:foo/bar"
	if strings.HasPrefix(s, "github:") {
		return "https://github.com/" + strings.TrimPrefix(s, "github:"), "github"
	}
	if strings.HasPrefix(s, "gitlab:") {
		return "https://gitlab.com/" + strings.TrimPrefix(s, "gitlab:"), "gitlab"
	}

	// Strip git+ prefix and trailing .git suffix.
	s = strings.TrimPrefix(s, "git+")
	s = strings.TrimSuffix(s, ".git")

	// SCP-style git URL ("git@github.com:foo/bar") — convert to https.
	if scpMatch := scpGitRE.FindStringSubmatch(s); len(scpMatch) > 0 {
		s = "https://" + scpMatch[1] + "/" + scpMatch[2]
	}

	// ssh:// → https:// — same trust boundary; we only read public
	// metadata so https is the right scheme.
	s = strings.Replace(s, "git://", "https://", 1)
	s = strings.Replace(s, "ssh://git@", "https://", 1)

	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", ""
	}

	// Trim a leading / and any trailing slash on the path.
	path := strings.Trim(u.Path, "/")
	if path == "" {
		return "", ""
	}

	// Reduce to the first two segments — registries sometimes append
	// /tree/main or /blob/HEAD/README.md to the URL.
	parts := strings.Split(path, "/")
	if len(parts) >= 2 {
		path = parts[0] + "/" + parts[1]
	}

	host := strings.ToLower(u.Host)
	provider := ""
	switch {
	case host == "github.com" || strings.HasSuffix(host, ".github.com"):
		provider = "github"
		host = "github.com"
	case host == "gitlab.com" || strings.HasSuffix(host, ".gitlab.com"):
		provider = "gitlab"
		host = "gitlab.com"
	default:
		// Unknown host — return the URL anyway so admins can see it
		// in the row, but with empty provider so we don't try to
		// hit it as if it were GitHub.
		return "https://" + host + "/" + path, ""
	}
	return "https://" + host + "/" + path, provider
}

// scpGitRE matches git's SCP-style URL form, e.g. "git@github.com:foo/bar".
var scpGitRE = regexp.MustCompile(`^git@([^:]+):(.+)$`)
