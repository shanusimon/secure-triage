package adapters

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

type CISACatalog struct {
	Count           int                 `json:"count"`
	Vulnerabilities []CISAVulnerability `json:"vulnerabilities"`
}

type CISAVulnerability struct {
	CveID string `json:"cveID"`
}

type CISAClient struct {
	httpClient *http.Client
	mu         sync.RWMutex
	cveMap     map[string]bool
}

func NewCISAClient() *CISAClient {
	c := &CISAClient{
		httpClient: &http.Client{Timeout: 8 * time.Second},
		cveMap:     make(map[string]bool),
	}

	// Seed with well-known active exploits as a built-in fallback
	c.cveMap["CVE-2023-4911"] = true  // Looney Tunables
	c.cveMap["CVE-2021-44228"] = true // Log4Shell
	c.cveMap["CVE-2022-22965"] = true // Spring4Shell
	return c
}

func (c *CISAClient) LoadCatalog(ctx context.Context) error {
	url := "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecureTriage/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		log.Printf("⚠️ [CISA] Remote feed timed out or unreachable (%v). Using built-in cache.", err)
		return nil // Graceful degradation: don't crash the microservice!
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("⚠️ [CISA] Remote returned status %d. Using built-in cache.", resp.StatusCode)
		return nil
	}

	var catalog CISACatalog
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		log.Printf("⚠️ [CISA] Could not decode remote JSON: %v. Using built-in cache.", err)
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, v := range catalog.Vulnerabilities {
		c.cveMap[v.CveID] = true
	}
	log.Printf("✅ [CISA] Successfully updated %d active exploits from live feed!", len(catalog.Vulnerabilities))

	return nil
}

func (c *CISAClient) IsExploited(cveID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cveMap[cveID]
}
