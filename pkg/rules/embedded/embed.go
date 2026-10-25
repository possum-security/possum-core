package embedded

import "embed"

// RulesFS contains the embedded index.json.
//
//go:embed index.json
var RulesFS embed.FS
