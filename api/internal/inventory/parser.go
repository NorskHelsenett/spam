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

func ParseSBOM(format string, payload []byte) ([]ParsedComponent, error) {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "cyclonedx-json":
		return parseCycloneDX(payload)
	case "spdx-json":
		return parseSPDX(payload)
	default:
		return []ParsedComponent{}, nil
	}
}

func parseCycloneDX(payload []byte) ([]ParsedComponent, error) {
	var raw struct {
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			PURL    string `json:"purl"`
			Scope   string `json:"scope"`
		} `json:"components"`
	}

	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, err
	}

	components := make([]ParsedComponent, 0, len(raw.Components))
	for _, component := range raw.Components {
		if component.Name == "" {
			continue
		}
		components = append(components, ParsedComponent{
			Name:    component.Name,
			Version: component.Version,
			PURL:    component.PURL,
			Scope:   component.Scope,
		})
	}
	return components, nil
}

func parseSPDX(payload []byte) ([]ParsedComponent, error) {
	var raw struct {
		Packages []struct {
			Name         string `json:"name"`
			VersionInfo  string `json:"versionInfo"`
			ExternalRefs []struct {
				ReferenceType    string `json:"referenceType"`
				ReferenceLocator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
	}

	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, err
	}

	components := make([]ParsedComponent, 0, len(raw.Packages))
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
		components = append(components, ParsedComponent{
			Name:    pkg.Name,
			Version: pkg.VersionInfo,
			PURL:    purl,
		})
	}
	return components, nil
}
