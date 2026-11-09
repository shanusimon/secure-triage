package adapters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

type EPSSResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status-code"`
	Version    string `json:"version"`
	Access     string `json:"access"`
	Total      int    `json:"total"`
	Offset     int    `json:"offset"`
	Limit      int    `json:"limit"`
	Data       []struct {
		Cve        string `json:"cve"`
		Epss       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

type EPSSClient struct {
	httpClient *http.Client
}

func NewEPSSClient() *EPSSClient {
	return &EPSSClient{
		httpClient: &http.Client{
			Timeout: 10 * time.Second, // Set a timeout for the HTTP client
		},
	}
}

func (c *EPSSClient) GetEPSSScore(ctx context.Context, cveID string) (float64, error) {
	url := fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s", cveID) 

	req,err := http.NewRequestWithContext(ctx,http.MethodGet,url,nil)
	if err != nil{
		return 0,err
	}

	resp,err := c.httpClient.Do(req)
	if err != nil{
		return 0 ,err
	}

	defer resp.Body.Close()

	var epssResp EPSSResponse
	if err := json.NewDecoder(resp.Body).Decode(&epssResp); err != nil{
		return 0,err
	}

	if len(epssResp.Data) == 0 {
		return 0, nil // No score found, default to 0
	}
	// Convert string "0.85430" to float64
	return strconv.ParseFloat(epssResp.Data[0].Epss, 64)
}
