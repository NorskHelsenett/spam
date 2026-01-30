package inventory

import (
	"encoding/json"
	"strings"
)

type ParsedComponent struct {
	Name    string
	Version string
	PURL    string
	Scope   string
}

type ParsedDependency struct {
	Ref       string   // PURL of the component that has dependencies
	DependsOn []string // PURLs of components it depends on
}

type ParsedSBOM struct {
	Components   []ParsedComponent
	Dependencies []ParsedDependency
}

func ParseSBOM(format string, payload []byte) ([]ParsedComponent, error) {
	result, err := ParseSBOMFull(format, payload)
	if err != nil {
		return nil, err
	}
	return result.Components, nil
}

func ParseSBOMFull(format string, payload []byte) (*ParsedSBOM, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "cyclonedx-json":
		return parseCycloneDX(payload)
	case "spdx-json":
		return parseSPDX(payload)
	default:
		return &ParsedSBOM{}, nil
	}
}

func parseCycloneDX(payload []byte) (*ParsedSBOM, error) {
	var raw struct {
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
			Scope   string `json:"scope"`
		} `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}

	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, err
	}

	result := &ParsedSBOM{
		Components:   make([]ParsedComponent, 0, len(raw.Components)),
		Dependencies: make([]ParsedDependency, 0, len(raw.Dependencies)),
	}

	for _, component := range raw.Components {
		if component.Name == "" {
			continue
		}
		// Skip components without PURL (e.g., file references from Syft)
		// These are not actual software dependencies
		if component.PURL == "" {
			continue
		}
		result.Components = append(result.Components, ParsedComponent{
			Name:    component.Name,
			Version: component.Version,
			PURL:    component.PURL,
			Scope:   component.Scope,
		})
	}

	for _, dep := range raw.Dependencies {
		if dep.Ref == "" || len(dep.DependsOn) == 0 {
			continue
		}
		result.Dependencies = append(result.Dependencies, ParsedDependency{
			Ref:       dep.Ref,
			DependsOn: dep.DependsOn,
		})
	}

	return result, nil
}

func parseSPDX(payload []byte) (*ParsedSBOM, error) {
	var raw struct {
		Packages []struct {
			SPDXID       string `json:"SPDXID"`
			Name         string `json:"name"`
			VersionInfo  string `json:"versionInfo"`
			ExternalRefs []struct {
				ReferenceType    string `json:"referenceType"`
				ReferenceLocator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
		Relationships []struct {
			SpdxElementID      string `json:"spdxElementId"`
			RelationshipType   string `json:"relationshipType"`
			RelatedSpdxElement string `json:"relatedSpdxElement"`
		} `json:"relationships"`
	}

	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, err
	}

	result := &ParsedSBOM{
		Components: make([]ParsedComponent, 0, len(raw.Packages)),
	}

	// Build SPDXID -> PURL map for dependency resolution
	spdxToPURL := make(map[string]string)

	for _, pkg := range raw.Packages {
		if pkg.Name == "" {
			continue
		}
		purl := ""
		for _, ref := range pkg.ExternalRefs {
			if strings.EqualFold(ref.ReferenceType, "purl") {
				purl = ref.ReferenceLocator
				break
			}
		}
		// Skip components without PURL (e.g., file references from Syft)
		if purl == "" {
			continue
		}
		result.Components = append(result.Components, ParsedComponent{
			Name:    pkg.Name,
			Version: pkg.VersionInfo,
			PURL:    purl,
		})
		if pkg.SPDXID != "" {
			spdxToPURL[pkg.SPDXID] = purl
		}
	}

	// Convert SPDX relationships to dependencies
	// DEPENDS_ON relationship: spdxElementId depends on relatedSpdxElement
	depMap := make(map[string][]string)
	for _, rel := range raw.Relationships {
		if rel.RelationshipType != "DEPENDS_ON" {
			continue
		}
		fromPURL := spdxToPURL[rel.SpdxElementID]
		toPURL := spdxToPURL[rel.RelatedSpdxElement]
		if fromPURL != "" && toPURL != "" {
			depMap[fromPURL] = append(depMap[fromPURL], toPURL)
		}
	}

	for ref, deps := range depMap {
		result.Dependencies = append(result.Dependencies, ParsedDependency{
			Ref:       ref,
			DependsOn: deps,
		})
	}

	return result, nil
}
