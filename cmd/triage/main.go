package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"secure-triage/internal/triage/adapters"
	"secure-triage/internal/triage/app/command"
)

func main() {

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		log.Fatal("GEMINI_API_KEY environment variable is not set")
	}

	ctx := context.Background()

	fmt.Println("📡 Initializing Threat Intel and AI...")

	cisaClient := adapters.NewCISAClient()

	if err := cisaClient.LoadCatalog(ctx); err != nil {
		log.Fatalf("❌ Failed to load CISA catalog: %v", err)
	}

	epssClient := adapters.NewEPSSClient()

	geminiClient, err := adapters.NewGeminiClient(apiKey)
	if err != nil {
		log.Fatalf("❌ Failed to initialize Gemini: %v", err)
	}

	handler := command.NewTriageScanHandler(geminiClient, cisaClient, epssClient)

	scanPath := filepath.Join("testdata", "scan.json")
	scanFile, err := os.Open(scanPath)
	if err != nil {
		log.Fatalf("❌ Failed to open scan file: %v", err)
	}
	defer scanFile.Close()

	// 4. Run Triage
	fmt.Println("🚀 Processing scan findings...")
	start := time.Now()
	findings, err := handler.Handle(ctx, command.TriageScan{
		ScanReader: scanFile,
	})
	if err != nil {
		log.Fatalf("❌ Triage execution failed: %v", err)
	}

	// 5. Output Results
	fmt.Printf("\n✨ Triage Completed in %v! Displaying %d Urgent Findings:\n", time.Since(start).Round(time.Millisecond), len(findings))
	for i, f := range findings {
		fmt.Printf("\n=======================================================\n")
		fmt.Printf("Finding [%d]: %s (%s %s)\n", i+1, f.CVEID(), f.PackageName(), f.InstalledVersion())
		fmt.Printf("CVSS: %.1f | In CISA KEV: %t | EPSS: %.2f\n", f.CVSSScore(), f.InCisaKEV(), f.EPSSScore())
		fmt.Printf("PRIORITY: %s\n", f.Priority())
		fmt.Printf("EXPLANATION: %s\n", f.AIExplanation())
		fmt.Printf("SUGGESTED FIX: %s\n", f.SuggestedFix())
		fmt.Printf("-------------------------------------------------------\n")
		fmt.Printf("DRAFTED TICKET:\n%s\n", f.DraftedTicket())
		fmt.Printf("=======================================================\n")
	}
}
