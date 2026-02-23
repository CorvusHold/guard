package version

import "testing"

func TestString_DefaultsToDevWhenEmpty(t *testing.T) {
	original := Tag
	defer func() { Tag = original }()

	Tag = ""
	if got := String(); got != "dev" {
		t.Fatalf("expected dev when tag is empty, got %q", got)
	}
}

func TestString_ReturnsTagWhenSet(t *testing.T) {
	original := Tag
	defer func() { Tag = original }()

	Tag = "v1.2.3"
	if got := String(); got != "v1.2.3" {
		t.Fatalf("expected tag value, got %q", got)
	}
}
