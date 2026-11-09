package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type AITriageResult struct {
	Priority      string `json:"priority"`
	Explanation   string `json:"explanation"`
	SuggestedFix  string `json:"suggested_fix"`
	DraftedTicket string `json:"drafted_ticket"`
}

type GeminiClient struct {
	apiKey     string
	httpClient *http.Client
}

func NewGeminiClient(apiKey string) (*GeminiClient, error) {
	if apiKey == "" {
		return nil, errors.New("gemini API key is required")
	}

	return &GeminiClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 15 * time.Second, // Timeout protects against hung requests
		},
	}, nil
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContext struct {
	Parts []geminiPart `json:"parts"`
}

type genConfig struct {
	ResponseMIMEType string `json:"responseMimeType"`
}

type geminiRequest struct {
	Contents []geminiContext `json:"contents"`
	GenerationConfig genConfig       `json:"generationConfig"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

func (c *GeminiClient) AnalyzeFinding(
	ctx context.Context,
	cveID string,
	pkg string,
	installedVer string,
	fixedVer string,
	severity string,
	cvss float64,
	inCisa bool,
	epss float64,
) (*AITriageResult, error) {

	prompt := fmt.Sprintf(`You are a senior Application Security Engineer.
				Analyze this vulnerability finding:
				- CVE ID: %s
				- Package: %s
				- Installed Version: %s
				- Fixed in Version: %s
				- Severity: %s (CVSS: %.1f)
				- Actively Exploited in Wild (CISA KEV): %t
				- Exploit Probability (EPSS): %.2f
				Respond ONLY with a JSON object with these exact keys:
				1. "priority": MUST be one of "NOW", "THIS_WEEK", or "LATER"
				2. "explanation": A 2-sentence plain English summary of what an attacker can do with this bug.
				3. "suggested_fix": Concrete action (e.g. 'Upgrade package X to version Y in package.json').
				4. "drafted_ticket": A formatted ticket ready to paste into Jira/GitHub Issues.`,
		cveID, pkg, installedVer, fixedVer, severity, cvss, inCisa, epss,
	)

	reqBody := geminiRequest{
		Contents: []geminiContext{
			{
				Parts: []geminiPart{{Text: prompt}},
			},
		},
		GenerationConfig: genConfig{
			ResponseMIMEType: "application/json",
		},
	}

	payloadBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	// 3. Create HTTP POST request to Gemini 2.5 Flash
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=%s", c.apiKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// 4. Send request using our protected httpClient
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gemini API request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gemini returned status %d: %s", resp.StatusCode, string(body))
	}
	// 5. Decode Gemini's API wrapper
	var geminiResp geminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
		return nil, fmt.Errorf("failed to decode gemini response: %w", err)
	}
	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return nil, errors.New("empty response from gemini")
	}
	// 6. Decode the AI's inner JSON text into our AITriageResult
	rawJSONText := geminiResp.Candidates[0].Content.Parts[0].Text
	var result AITriageResult
	if err := json.Unmarshal([]byte(rawJSONText), &result); err != nil {
		return nil, fmt.Errorf("failed to parse AI JSON: %w (raw output: %s)", err, rawJSONText)
	}
	return &result, nil
}
