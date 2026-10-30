package version

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVersion_String(t *testing.T) {
	origVer, origCommit, origDate := Version, GitCommit, BuildDate
	defer func() {
		Version, GitCommit, BuildDate = origVer, origCommit, origDate
	}()

	Version = "v1.2.3"
	GitCommit = "abc1234"
	BuildDate = "2026-10-30T12:00:00Z"

	str := String()
	assert.True(t, strings.HasPrefix(str, "possum v1.2.3"))
	assert.Contains(t, str, "commit: abc1234")
	assert.Contains(t, str, "built: 2026-10-30T12:00:00Z")
}
