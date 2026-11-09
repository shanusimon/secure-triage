package adapters

import (
	"context"
	"fmt"
	"net/http"
	"encoding/json"
	"sync"
	"time"
)

type CISACatalog struct {
	Count           int                 `json:"count"`
	Vulnerabilities []CISAVulnerability `json:"vulnerabilities"`
}

type CISAVulnerability struct {
	CveID string `json:"cveID"` // e.g. "CVE-2023-4911"
}

type CISAClient struct {
	httpClient *http.Client
	mu         sync.RWMutex
	cveMap     map[string]bool // Hash Set for instant O(1) lookups
}

func NewCISAClient() *CISAClient{
	return &CISAClient{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cveMap: make(map[string]bool),
	}
}

// 3. Downloads the CISA catalog and fills the in-memory map
func (c *CISAClient) LoadCatalog(ctx context.Context) error {
	url := "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	
	if err != nil {
		return err
	}
	
	resp, err := c.httpClient.Do(req)
	
	if err != nil {
		return fmt.Errorf("failed to fetch CISA KEV catalog: %w", err)
	}

	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cisa returned status %d", resp.StatusCode)
	}

	var catalog CISACatalog
	
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return fmt.Errorf("failed to decode CISA catalog: %w", err)
	}
	// Lock and populate the map for O(1) lookups
	c.mu.Lock()
	
	defer c.mu.Unlock()
	
	for _, v := range catalog.Vulnerabilities {
		c.cveMap[v.CveID] = true
	}
	
	return nil
}

// 4. Instant memory lookup (returns true if CVE is on CISA KEV)
func (c *CISAClient) IsExploited(cveID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cveMap[cveID]
}