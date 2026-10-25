package version

import "fmt"

var (
	// Version is the current release version of Possum Core.
	Version = "v0.1.0-dev"
	// GitCommit is the git commit SHA injected at build time.
	GitCommit = "none"
	// BuildDate is the RFC3339 date injected at build time.
	BuildDate = "unknown"
)

// String returns formatted version details.
func String() string {
	return fmt.Sprintf("possum %s (commit: %s, built: %s)", Version, GitCommit, BuildDate)
}
