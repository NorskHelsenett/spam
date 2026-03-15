package manifests

import "testing"

func TestBuildDependencyPURL(t *testing.T) {
	tests := []struct {
		name string
		dep  ManifestDependency
		want string
	}{
		{
			name: "npm scoped package",
			dep: ManifestDependency{
				Name:       "@fontsource/inter",
				Version:    "5.2.8",
				Constraint: "5.2.8",
				Ecosystem:  "npm",
			},
			want: "pkg:npm/%40fontsource/inter@5.2.8",
		},
		{
			name: "golang module",
			dep: ManifestDependency{
				Name:      "github.com/spf13/cobra",
				Version:   "v1.8.1",
				Ecosystem: "golang",
			},
			want: "pkg:golang/github.com/spf13/cobra@v1.8.1",
		},
		{
			name: "maven package",
			dep: ManifestDependency{
				Name:       "org.springframework:spring-core",
				Version:    "6.1.1",
				Constraint: "6.1.1",
				Ecosystem:  "maven",
			},
			want: "pkg:maven/org.springframework/spring-core@6.1.1",
		},
		{
			name: "requirements exact pin",
			dep: ManifestDependency{
				Name:       "requests",
				Version:    "2.32.0",
				Constraint: "==2.32.0",
				Ecosystem:  "pypi",
			},
			want: "pkg:pypi/requests@2.32.0",
		},
		{
			name: "range version skipped",
			dep: ManifestDependency{
				Name:       "react",
				Version:    "18.2.0",
				Constraint: "^18.2.0",
				Ecosystem:  "npm",
			},
			want: "",
		},
		{
			name: "unsupported ecosystem skipped",
			dep: ManifestDependency{
				Name:       "org.springframework.boot",
				Version:    "3.4.0",
				Constraint: "3.4.0",
				Ecosystem:  "gradle-plugin",
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := BuildDependencyPURL(tt.dep); got != tt.want {
				t.Fatalf("BuildDependencyPURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
