package manifests

import (
	"testing"
)

func TestParseCsproj(t *testing.T) {
	content := `<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net9.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <!-- <PublishAot>true</PublishAot> -->
    <!-- <OptimizationPreference>Size</OptimizationPreference> -->
  </PropertyGroup>
  <PropertyGroup>
    <!-- <TreatWarningsAsErrors>true</TreatWarningsAsErrors> -->
    <Nullable>enable</Nullable>
    <Deterministic>true</Deterministic>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Markdig" Version="0.41.0" />
    <PackageReference Include="Microsoft.Data.Sqlite" Version="9.0.4" />
    <PackageReference Include="SixLabors.ImageSharp.Web" Version="3.1.4" />
    <PackageReference Include="SharpCompress" Version="0.39.0" />
    <!-- <PackageReference Include="LigerShark.WebOptimizer.Core" Version="3.0.391" /> -->
  </ItemGroup>
</Project>
`

	manifestID := "test-manifest-1"
	deps := parseCsproj(manifestID, content)

	// Should extract 4 packages (one is commented out)
	if len(deps) != 4 {
		t.Errorf("Expected 4 dependencies, got %d", len(deps))
	}

	// Check specific packages
	expectedDeps := map[string]string{
		"Markdig":                  "0.41.0",
		"Microsoft.Data.Sqlite":    "9.0.4",
		"SixLabors.ImageSharp.Web": "3.1.4",
		"SharpCompress":            "0.39.0",
	}

	for _, dep := range deps {
		expectedVersion, ok := expectedDeps[dep.Name]
		if !ok {
			t.Errorf("Unexpected dependency: %s", dep.Name)
			continue
		}
		if dep.Version != expectedVersion {
			t.Errorf("Wrong version for %s: expected %s, got %s", dep.Name, expectedVersion, dep.Version)
		}
		if dep.Ecosystem != "nuget" {
			t.Errorf("Wrong ecosystem for %s: expected nuget, got %s", dep.Name, dep.Ecosystem)
		}
		if !dep.Direct {
			t.Errorf("Expected %s to be marked as direct dependency", dep.Name)
		}
	}
}

func TestParseGoMod(t *testing.T) {
	content := `module picoblog

go 1.23

require (
	github.com/manifoldco/promptui v0.9.0
	github.com/spf13/cobra v1.8.1
)

require (
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	golang.org/x/sys v0.1.0 // indirect
)
`

	manifestID := "test-manifest-2"
	deps := parseGoMod(manifestID, content)

	// Should extract 6 dependencies
	if len(deps) != 6 {
		t.Errorf("Expected 6 dependencies, got %d", len(deps))
	}

	// Check direct dependencies
	directDeps := map[string]string{
		"github.com/manifoldco/promptui": "v0.9.0",
		"github.com/spf13/cobra":         "v1.8.1",
	}

	// Check indirect dependencies
	indirectDeps := map[string]string{
		"github.com/chzyer/readline":           "v0.0.0-20180603132655-2972be24d48e",
		"github.com/inconshreveable/mousetrap": "v1.1.0",
		"github.com/spf13/pflag":               "v1.0.5",
		"golang.org/x/sys":                     "v0.1.0",
	}

	directCount := 0
	indirectCount := 0

	for _, dep := range deps {
		if dep.Ecosystem != "golang" {
			t.Errorf("Wrong ecosystem for %s: expected golang, got %s", dep.Name, dep.Ecosystem)
		}

		if expectedVersion, ok := directDeps[dep.Name]; ok {
			if dep.Version != expectedVersion {
				t.Errorf("Wrong version for %s: expected %s, got %s", dep.Name, expectedVersion, dep.Version)
			}
			if !dep.Direct {
				t.Errorf("Expected %s to be marked as direct dependency", dep.Name)
			}
			directCount++
		} else if expectedVersion, ok := indirectDeps[dep.Name]; ok {
			if dep.Version != expectedVersion {
				t.Errorf("Wrong version for %s: expected %s, got %s", dep.Name, expectedVersion, dep.Version)
			}
			if dep.Direct {
				t.Errorf("Expected %s to be marked as indirect dependency", dep.Name)
			}
			indirectCount++
		} else {
			t.Errorf("Unexpected dependency: %s", dep.Name)
		}
	}

	if directCount != 2 {
		t.Errorf("Expected 2 direct dependencies, got %d", directCount)
	}
	if indirectCount != 4 {
		t.Errorf("Expected 4 indirect dependencies, got %d", indirectCount)
	}
}

func TestExtractDotNetVersion(t *testing.T) {
	content := `<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net9.0</TargetFramework>
  </PropertyGroup>
</Project>`

	version := extractDotNetVersion(content)
	if version != "net9.0" {
		t.Errorf("Expected net9.0, got %s", version)
	}
}

func TestExtractGoVersion(t *testing.T) {
	content := `module picoblog

go 1.23

require (
	github.com/manifoldco/promptui v0.9.0
)`

	version := extractGoVersion(content)
	if version != "1.23" {
		t.Errorf("Expected 1.23, got %s", version)
	}
}
