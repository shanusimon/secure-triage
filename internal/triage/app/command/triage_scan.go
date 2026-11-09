package command

import (
	"context"
	"fmt"
	"io"
	"secure-triage/internal/triage/adapters"
	"secure-triage/internal/triage/domain"
)

type CISAClient interface {
	IsExploited(cveID string) bool
}

type EPSSClient interface {
	GetEPSSScore(ctx context.Context, cveID string) (float64, error)
}

// AIClient is an interface so tomorrow you could swap Gemini for Claude/OpenAI without changing this code!
type AIClient interface {
	AnalyzeFinding(
		ctx context.Context,
		cveID string,
		pkg string,
		installedVer string,
		fixedVer string,
		severity string,
		cvss float64,
		inCisa bool,
		epss float64,
	) (*adapters.AITriageResult, error)
}

type TriageScan struct {
	ScanReader io.Reader // The uploaded scan.json stream
}

type TriageScanHandler struct {
	aiClient   AIClient
	cisaClient CISAClient
	epssClient EPSSClient
}

func NewTriageScanHandler(
	aiClient AIClient,
	cisaClient CISAClient,
	epssClient EPSSClient,
) TriageScanHandler {
	return TriageScanHandler{
		aiClient:   aiClient,
		cisaClient: cisaClient,
		epssClient: epssClient,
	}
}

func (h TriageScanHandler) Handle(ctx context.Context, cmd TriageScan) ([]*domain.Finding, error) {
	// Step 1: Parse the raw scan with our parser adapter
	rawFindings, err := adapters.ParseTrivyReport(cmd.ScanReader)
	if err != nil {
		return nil, fmt.Errorf("failed to parse scan: %w", err)
	}
	var triagedFindings []*domain.Finding
	// Step 2: Loop through parsed findings (limit to top urgent for now to save API calls)
	for i, raw := range rawFindings {
		// Only analyze High and Critical findings with the AI
		if raw.Severity != "CRITICAL" && raw.Severity != "HIGH" {
			continue
		}
		// Create pure Domain entity
		findingID := fmt.Sprintf("finding-%d", i+1)
		finding, err := domain.NewFinding(
			findingID,
			raw.VulnerabilityID,
			raw.PkgName,
			raw.InstalledVersion,
			raw.FixedVersion,
			raw.Severity,
			raw.CVSSScore,
		)
		if err != nil {
			continue // Skip invalid entries
		}
		// For demo/triage: evaluate if it needs urgent AI analysis
		inCisa := h.cisaClient.IsExploited(raw.VulnerabilityID)
		epss, _ := h.epssClient.GetEPSSScore(ctx, raw.VulnerabilityID)
		// Enrich in domain
		finding.Enrich(inCisa, epss)
		// Step 3: Ask Gemini AI to triage and draft tickets
		aiResult, err := h.aiClient.AnalyzeFinding(
			ctx,
			finding.CVEID(),
			finding.PackageName(),
			finding.InstalledVersion(),
			finding.FixedVersion(),
			raw.Severity,
			finding.CVSSScore(),
			inCisa,
			epss,
		)
		if err == nil && aiResult != nil {
			// Apply AI outcome to our domain model
			var p domain.Priority
			switch aiResult.Priority {
			case "NOW":
				p = domain.PriorityFixNow
			case "THIS_WEEK":
				p = domain.PriorityThisWeek
			default:
				p = domain.PriorityLater
			}
			finding.ApplyAITriage(p, aiResult.Explanation, aiResult.SuggestedFix, aiResult.DraftedTicket)
		}
		triagedFindings = append(triagedFindings, finding)
		// Limit to first 3 urgent items for fast testing
		if len(triagedFindings) >= 3 {
			break
		}
	}
	return triagedFindings, nil
}
