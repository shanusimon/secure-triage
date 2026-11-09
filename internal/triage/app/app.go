package app

import "secure-triage/internal/triage/app/command"

type Application struct {
	Commands Commands
	Queries  Queries
}

type Commands struct {
	TriageScan command.TriageScanHandler
}

type Queries struct {
	// Queries (read-only use cases) will go here
}
