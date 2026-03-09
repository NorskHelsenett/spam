package manifests

import (
	"path/filepath"
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

func TestDetectManifestTypeSupportedSet(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{path: "package.json", want: "package.json"},
		{path: "go.mod", want: "go.mod"},
		{path: "Pipfile", want: "Pipfile"},
		{path: "pom.xml", want: "pom.xml"},
		{path: "package-lock.json", want: "package-lock.json"},
		{path: "yarn.lock", want: "yarn.lock"},
		{path: "bun.lock", want: "bun.lock"},
		{path: "bun.lockb", want: "bun.lockb"},
		{path: "build.gradle", want: "gradle"},
		{path: "gradle.lock", want: "gradle.lock"},
		{path: "settings.gradle.kts", want: "settings.gradle"},
		{path: "gradle/libs.versions.toml", want: "libs.versions.toml"},
		{path: "build.sbt", want: "build.sbt"},
		{path: "project/plugins.sbt", want: "project/plugins.sbt"},
		{path: "pyproject.toml", want: "pyproject.toml"},
		{path: "unknown.file", want: ""},
	}

	for _, tt := range tests {
		got := detectManifestType(filepath.ToSlash(tt.path))
		if got != tt.want {
			t.Errorf("detectManifestType(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestParsePackageLockJSON(t *testing.T) {
	content := `{
  "name": "demo",
  "lockfileVersion": 2,
  "packages": {
    "": {"name":"demo","version":"1.0.0"},
    "node_modules/lodash": {"version":"4.17.21"},
    "node_modules/chalk": {"version":"5.3.0","dev":true}
  }
}`
	deps := parsePackageLockJSON("m1", content)
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	found := map[string]string{}
	for _, d := range deps {
		found[d.Name] = d.Version
	}
	if found["lodash"] != "4.17.21" {
		t.Fatalf("missing lodash version: %#v", found)
	}
	if found["chalk"] != "5.3.0" {
		t.Fatalf("missing chalk version: %#v", found)
	}
}

func TestParseYarnLock(t *testing.T) {
	content := `"left-pad@^1.3.0":
  version "1.3.0"

"@scope/pkg@^2.0.0":
  version "2.1.0"
`
	deps := parseYarnLock("m2", content)
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
	found := map[string]string{}
	for _, d := range deps {
		found[d.Name] = d.Version
	}
	if found["left-pad"] != "1.3.0" {
		t.Fatalf("left-pad missing: %#v", found)
	}
	if found["@scope/pkg"] != "2.1.0" {
		t.Fatalf("@scope/pkg missing: %#v", found)
	}
}

func TestParseBunLock(t *testing.T) {
	content := `"react@^18.0.0":
  version "18.2.0"
`
	deps := parseBunLock("m-bun", content)
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Name != "react" || deps[0].Version != "18.2.0" {
		t.Fatalf("unexpected dep: %#v", deps[0])
	}
}

func TestParsePnpmLockYAML(t *testing.T) {
	content := `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        version: 18.2.0
    devDependencies:
      typescript:
        version: 5.4.5
packages:
  /react@18.2.0: {}
  /typescript@5.4.5: {}
`
	deps := parsePnpmLockYAML("m3", content)
	if len(deps) < 2 {
		t.Fatalf("expected at least 2 deps, got %d", len(deps))
	}
}

func TestParsePoetryLock(t *testing.T) {
	content := `[[package]]
name = "requests"
version = "2.32.0"
category = "main"

[[package]]
name = "pytest"
version = "8.2.0"
category = "dev"
`
	deps := parsePoetryLock("m4", content)
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
}

func TestParseGradle(t *testing.T) {
	content := `
dependencies {
  implementation("org.springframework:spring-core:6.1.1")
  testImplementation 'junit:junit:4.13.2'
}`
	deps := parseGradle("m5", content)
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
}

func TestParseGradleLock(t *testing.T) {
	content := `
# This is a Gradle generated file
org.slf4j:slf4j-api:2.0.9=compileClasspath
ch.qos.logback:logback-classic:1.4.14=runtimeClasspath
`
	deps := parseGradleLock("m-gradle-lock", content)
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
}

func TestParseGradleSettings(t *testing.T) {
	content := `
plugins {
  id("org.springframework.boot") version "3.4.0"
}
`
	deps := parseGradleSettings("m-settings", content)
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
	if deps[0].Name != "org.springframework.boot" || deps[0].Version != "3.4.0" {
		t.Fatalf("unexpected dep: %#v", deps[0])
	}
}

func TestParseBuildSbt(t *testing.T) {
	content := `
libraryDependencies ++= Seq(
  "com.typesafe.akka" %% "akka-actor" % "2.8.5",
  "org.scalatest" %% "scalatest" % "3.2.18" % Test
)
`
	deps := parseBuildSbt("m-build-sbt", content)
	if len(deps) != 2 {
		t.Fatalf("expected 2 deps, got %d", len(deps))
	}
}

func TestParseSbtPlugins(t *testing.T) {
	content := `
addSbtPlugin("com.eed3si9n" % "sbt-assembly" % "2.3.0")
`
	deps := parseSbtPlugins("m-plugins-sbt", content)
	if len(deps) != 1 {
		t.Fatalf("expected 1 dep, got %d", len(deps))
	}
}

func TestParseGradleVersionCatalog(t *testing.T) {
	content := `
[versions]
spring = "6.1.1"
boot = "3.4.0"

[libraries]
spring-core = { module = "org.springframework:spring-core", version.ref = "spring" }
slf4j = { group = "org.slf4j", name = "slf4j-api", version = "2.0.9" }

[plugins]
spring-boot = { id = "org.springframework.boot", version.ref = "boot" }
`
	deps := parseGradleVersionCatalog("m-catalog", content)
	if len(deps) != 3 {
		t.Fatalf("expected 3 deps, got %d", len(deps))
	}
}

func TestParseManifestsStoresUnknownType(t *testing.T) {
	data := []byte(`[{"path":"docs/custom.dep","content":"x"}]`)
	manifests, deps, err := ParseManifests("r1", "repo1", data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(manifests))
	}
	if manifests[0].Type != "unknown" {
		t.Fatalf("expected unknown type, got %q", manifests[0].Type)
	}
	if len(deps) != 0 {
		t.Fatalf("expected 0 deps for unknown manifest, got %d", len(deps))
	}
}
