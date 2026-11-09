package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"secure-triage/internal/triage/app/command"
	"secure-triage/internal/triage/service"
)

func main() {
	fmt.Println("🚀 Starting SecureTriage...")
	ctx := context.Background()

	// 1. Composition Root: Wire the entire application in one clean call!
	application := service.NewApplication(ctx)

	// 2. Open scan file
	scanPath := filepath.Join("testdata", "scan.json")
	scanFile, err := os.Open(scanPath)
	if err != nil {
		log.Fatalf("❌ Failed to open scan file: %v", err)
	}
	defer scanFile.Close()

	// 3. Trigger the Use Case Command
	fmt.Println("🔍 Processing Juice Shop scan through threat intelligence & Gemini AI...")
	start := time.Now()

	findings, err := application.Commands.TriageScan.Handle(ctx, command.TriageScan{
		ScanReader: scanFile,
	})
	if err != nil {
		log.Fatalf("❌ Triage execution failed: %v", err)
	}

	// 4. Output Results
	fmt.Printf("\n✨ Triage Completed in %v! Found %d Urgent Findings:\n",
		time.Since(start).Round(time.Millisecond), len(findings))

	for i, f := range findings {
		fmt.Printf("\n=======================================================\n")
		fmt.Printf("Finding [%d]: %s (%s %s)\n", i+1, f.CVEID(), f.PackageName(), f.InstalledVersion())
		fmt.Printf("CVSS: %.1f | In CISA KEV: %t | EPSS: %.4f\n", f.CVSSScore(), f.InCisaKEV(), f.EPSSScore())
		fmt.Printf("PRIORITY: %s\n", f.Priority())
		fmt.Printf("EXPLANATION: %s\n", f.AIExplanation())
		fmt.Printf("SUGGESTED FIX: %s\n", f.SuggestedFix())
		fmt.Printf("-------------------------------------------------------\n")
		fmt.Printf("DRAFTED TICKET:\n%s\n", f.DraftedTicket())
		fmt.Printf("=======================================================\n")
	}
}
