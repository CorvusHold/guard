package version

// Tag holds the build version for the Guard binary. It can be overridden at
// build time via: go build -ldflags "-X github.com/corvusHold/guard/internal/version.Tag=v1.2.3".
var Tag = "dev"

// String returns the current Guard version, defaulting to "dev" when Tag is
// unset.
func String() string {
	if Tag == "" {
		return "dev"
	}
	return Tag
}
