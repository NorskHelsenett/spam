package providerconfig

import (
	"testing"
)

func TestMatchProvider(t *testing.T) {
	p := func(id, ownerPath string) ProviderInstance {
		return ProviderInstance{ID: id, OwnerPath: ownerPath}
	}

	tests := []struct {
		name         string
		providerType string
		repoPath     string
		candidates   []ProviderInstance
		wantID       string
	}{
		// GitLab: exact group match
		{
			name:         "gitlab exact match",
			providerType: "gitlab",
			repoPath:     "group/project",
			candidates:   []ProviderInstance{p("a", "group")},
			wantID:       "a",
		},
		// GitLab: subgroup match — should pick the longer (more specific) prefix
		{
			name:         "gitlab subgroup prefers longer match",
			providerType: "gitlab",
			repoPath:     "group/subgroup/project",
			candidates:   []ProviderInstance{p("a", "group"), p("b", "group/subgroup")},
			wantID:       "b",
		},
		// GitLab: no false prefix collision — "org" must NOT match "org2/project"
		{
			name:         "gitlab no false prefix match",
			providerType: "gitlab",
			repoPath:     "org2/project",
			candidates:   []ProviderInstance{p("a", "org")},
			wantID:       "",
		},
		// GitLab: empty OwnerPath matches anything (fallback)
		{
			name:         "gitlab empty owner path is fallback",
			providerType: "gitlab",
			repoPath:     "anything/project",
			candidates:   []ProviderInstance{p("fallback", "")},
			wantID:       "fallback",
		},
		// GitLab: specific match beats empty-owner fallback
		{
			name:         "gitlab specific beats fallback",
			providerType: "gitlab",
			repoPath:     "group/project",
			candidates:   []ProviderInstance{p("fallback", ""), p("specific", "group")},
			wantID:       "specific",
		},
		// GitHub: matches only first path segment
		{
			name:         "github exact owner",
			providerType: "github",
			repoPath:     "myorg/repo",
			candidates:   []ProviderInstance{p("a", "myorg")},
			wantID:       "a",
		},
		{
			name:         "github no match",
			providerType: "github",
			repoPath:     "otherorg/repo",
			candidates:   []ProviderInstance{p("a", "myorg")},
			wantID:       "",
		},
		// GitLab: exact OwnerPath (no slash) matches project directly under it
		{
			name:         "gitlab owner path exact repo",
			providerType: "gitlab",
			repoPath:     "group",
			candidates:   []ProviderInstance{p("a", "group")},
			wantID:       "a",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchProvider(tt.providerType, tt.repoPath, tt.candidates)
			gotID := ""
			if got != nil {
				gotID = got.ID
			}
			if gotID != tt.wantID {
				t.Errorf("matchProvider(%q, %q) = %q, want %q", tt.providerType, tt.repoPath, gotID, tt.wantID)
			}
		})
	}
}
