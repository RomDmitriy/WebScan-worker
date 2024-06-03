package models

import (
	"slices"
	"strings"
)

type VulnerabilityResults struct {
	Results []PackageSource `json:"results"`
}

func (vulns *VulnerabilityResults) Flatten() []VulnerabilityFlattened {
	results := []VulnerabilityFlattened{}
	for _, res := range vulns.Results {
		for _, pkg := range res.Packages {
			for _, v := range pkg.Vulnerabilities {
				results = append(results, VulnerabilityFlattened{
					Source:        res.Source,
					Package:       pkg.Package,
					DepGroups:     pkg.DepGroups,
					Vulnerability: v,
					GroupInfo:     getGroupInfoForVuln(pkg.Groups, v.ID),
				})
			}
		}
	}

	return results
}

func getGroupInfoForVuln(groups []GroupInfo, vulnID string) GroupInfo {
	groupIdx := slices.IndexFunc(groups, func(g GroupInfo) bool { return slices.Contains(g.IDs, vulnID) })
	return groups[groupIdx]
}

type VulnerabilityFlattened struct {
	Source            SourceInfo
	Package           PackageInfo
	DepGroups         []string
	Vulnerability     Vulnerability
	GroupInfo         GroupInfo
	Licenses          []License
	LicenseViolations []License
}

type SourceInfo struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type Metadata struct {
	RepoURL   string   `json:"repo_url"`
	DepGroups []string `json:"-"`
}

func (s SourceInfo) String() string {
	return s.Type + ":" + s.Path
}

type PackageSource struct {
	Source   SourceInfo     `json:"source"`
	Packages []PackageVulns `json:"packages"`
}

type License string

type PackageVulns struct {
	Package         PackageInfo     `json:"package"`
	DepGroups       []string        `json:"dependency_groups,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	Groups          []GroupInfo     `json:"groups,omitempty"`
}

type GroupInfo struct {
	IDs         []string `json:"ids"`
	Aliases     []string `json:"aliases"`
	MaxSeverity string   `json:"max_severity"`
}

func (groupInfo *GroupInfo) IsCalled() bool {
	if len(groupInfo.IDs) == 0 {
		return false
	}

	return false
}

func (groupInfo *GroupInfo) IndexString() string {
	return strings.Join(groupInfo.IDs, ",")
}

func (v *Vulnerability) FixedVersions() map[Package][]string {
	output := map[Package][]string{}
	for _, a := range v.Affected {
		packageKey := a.Package
		for _, r := range a.Ranges {
			for _, e := range r.Events {
				if e.Fixed != "" {
					output[packageKey] = append(output[packageKey], e.Fixed)
					if strings.Contains(string(packageKey.Ecosystem), ":") {
						packageKey.Ecosystem = Ecosystem(strings.Split(string(packageKey.Ecosystem), ":")[0])
					}
					output[packageKey] = append(output[packageKey], e.Fixed)
				}
			}
		}
	}

	return output
}

type PackageInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}
