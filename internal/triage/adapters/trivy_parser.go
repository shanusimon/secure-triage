package adapters

import (
	"encoding/json"
	"io"
)

type RawFinding struct {
	VulnerabilityID  string
	PkgName          string
	InstalledVersion string
	FixedVersion     string
	Severity         string
	CVSSScore        float64
	PrimaryURL       string
}

type TrivyReport struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	Results       []TrivyResult `json:"Results"`
}

type TrivyResult struct {
	Target          string               `json:"Target"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

type TrivyVulnerability struct {
	VulnerabilityID  string               `json:"VulnerabilityID"`
	PkgName          string               `json:"PkgName"`
	InstalledVersion string               `json:"InstalledVersion"`
	FixedVersion     string               `json:"FixedVersion"`
	Severity         string               `json:"Severity"`
	PrimaryURL       string               `json:"PrimaryURL"`
	CVSS             map[string]TrivyCVSS `json:"CVSS"`
}

type TrivyCVSS struct {
	V3Score float64 `json:"V3Score"`
}

func ParseTrivyReport(r io.Reader) ([]RawFinding, error) {
	var report TrivyReport

	// 1. Create a streaming decoder
	decoder := json.NewDecoder(r)

	if err := decoder.Decode(&report); err != nil {
		return nil, err
	}

	var findings []RawFinding

	//Loop over Results and Vulnerabilities
	for _, res := range report.Results {
		for _, vuln := range res.Vulnerabilities {
			var maxCVSS float64
			for _, cvssObj := range vuln.CVSS {
				if cvssObj.V3Score > maxCVSS {
					maxCVSS = cvssObj.V3Score
				}
			}

			findings = append(findings, RawFinding{
				VulnerabilityID:  vuln.VulnerabilityID,
				PkgName:          vuln.PkgName,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
				Severity:         vuln.Severity,
				CVSSScore:        maxCVSS,
				PrimaryURL:       vuln.PrimaryURL,
			})
		}
	}

	return findings,nil
}

