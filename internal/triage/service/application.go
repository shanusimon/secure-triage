package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"secure-triage/internal/triage/adapters"
	"secure-triage/internal/triage/app"
	"secure-triage/internal/triage/app/command"
)

func getAPIKey() string {
	key := os.Getenv("GEMINI_API_KEY")
	if key == "" {
		data, err := os.ReadFile(".env")
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "GEMINI_API_KEY=") {
					key = strings.TrimPrefix(line, "GEMINI_API_KEY=")
					key = strings.Trim(key, `"' `)
					break
				}
			}
		}
	}
	return key
}

func NewApplication(ctx context.Context) app.Application {
	apiKey := getAPIKey()
	if apiKey == "" {
		log.Fatal("❌ GEMINI_API_KEY environment variable is required")
	}

	fmt.Println("📡 [Service] Initializing Threat Intel & AI Adapters...")

	// 1. Initialize CISA KEV
	cisaClient := adapters.NewCISAClient()
	if err := cisaClient.LoadCatalog(ctx); err != nil {
		log.Fatalf("❌ Failed to load CISA catalog: %v", err)
	}
	fmt.Println("✅ [Service] CISA KEV Catalog loaded into memory!")

	// 2. Initialize EPSS Client
	epssClient := adapters.NewEPSSClient()

	// 3. Initialize Gemini Client
	geminiClient, err := adapters.NewGeminiClient(apiKey)
	if err != nil {
		log.Fatalf("❌ Failed to initialize Gemini: %v", err)
	}
	fmt.Println("✅ [Service] Gemini AI client initialized!")

	// 4. Wire CQRS Commands into Application Container
	return app.Application{
		Commands: app.Commands{
			TriageScan: command.NewTriageScanHandler(geminiClient, cisaClient, epssClient),
		},
	}
}
