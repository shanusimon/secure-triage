package domain

import (
	"errors"
	"strings"
)

type Priority string

const (
	PriorityFixNow   Priority = "NOW"
	PriorityThisWeek Priority = "THIS_WEEK"
	PriorityLater    Priority = "LATER"
)

type Finding struct {
	id               string
	cveID            string
	packageName      string
	installedVersion string
	fixedVersion     string
	severity         string
	cvssScore        float64

	// Threat Intelligence (Enrichment)
	inCisaKEV bool
	epssScore float64

	// AI Analysis
	priority      Priority
	aiExplanation string
	suggestedFix  string
	draftedTicket string
}

func NewFinding(
	id string,
	cveID string,
	packageName string,
	installedVersion string,
	fixedVersion string,
	severity string,
	cvssScore float64,
) (*Finding, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("finding ID cannot be empty")
	}

	if strings.TrimSpace(cveID) == "" {
		return nil, errors.New("CVE ID cannot be empty")
	}

	if cvssScore < 0.0 || cvssScore > 10.0 {
		return nil, errors.New("CVSS score must be between 0.0 and 10.0")
	}

	return &Finding{
		id:               id,
		cveID:            cveID,
		packageName:      packageName,
		installedVersion: installedVersion,
		fixedVersion:     fixedVersion,
		severity:         severity,
		cvssScore:        cvssScore,
		priority:         PriorityLater,
	}, nil
}

func (f *Finding) Enrich(inCisa bool, epss float64) {
	f.inCisaKEV = inCisa
	f.epssScore = epss

	if inCisa || (epss > 0.5 && f.cvssScore >= 7.0) {
		f.priority = PriorityFixNow
	} else if f.cvssScore >= 7.0 || epss > 0.2 {
		f.priority = PriorityThisWeek
	} else {
		f.priority = PriorityLater
	}
}

func (f *Finding) ApplyAITriage(priority Priority, explanation, fix, ticket string) error{
	if priority != PriorityFixNow && priority != PriorityThisWeek && priority != PriorityLater {
		return errors.New("invalid priority value")
	}

	f.priority = priority
	f.aiExplanation = explanation
	f.suggestedFix = fix
	f.draftedTicket = ticket

	return nil
}

func (f *Finding) ID() string               { return f.id }
func (f *Finding) CVEID() string            { return f.cveID }
func (f *Finding) PackageName() string      { return f.packageName }
func (f *Finding) InstalledVersion() string { return f.installedVersion }
func (f *Finding) FixedVersion() string     { return f.fixedVersion }
func (f *Finding) CVSSScore() float64       { return f.cvssScore }
func (f *Finding) InCisaKEV() bool          { return f.inCisaKEV }
func (f *Finding) EPSSScore() float64       { return f.epssScore }
func (f *Finding) Priority() Priority       { return f.priority }
func (f *Finding) AIExplanation() string    { return f.aiExplanation }
func (f *Finding) SuggestedFix() string     { return f.suggestedFix }
func (f *Finding) DraftedTicket() string    { return f.draftedTicket }
