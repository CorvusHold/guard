package main

import "testing"

func TestMatchCORSOrigin_Exact(t *testing.T) {
	patterns := []string{"https://app.example.com"}

	if !matchCORSOrigin("https://app.example.com", patterns) {
		t.Fatalf("expected exact origin match to be allowed")
	}

	if matchCORSOrigin("https://other.example.com", patterns) {
		t.Fatalf("did not expect different subdomain to be allowed for exact pattern")
	}
}

func TestMatchCORSOrigin_Star(t *testing.T) {
	patterns := []string{"*"}

	for _, origin := range []string{
		"https://app.example.com",
		"https://example.com",
		"http://localhost:3000",
	} {
		if !matchCORSOrigin(origin, patterns) {
			t.Fatalf("expected '*' pattern to allow origin %q", origin)
		}
	}
}

func TestMatchCORSOrigin_WildcardSubdomain(t *testing.T) {
	patterns := []string{"https://*.example.com"}

	for _, origin := range []string{
		"https://app.example.com",
		"https://foo.bar.example.com",
	} {
		if !matchCORSOrigin(origin, patterns) {
			t.Fatalf("expected wildcard pattern to allow origin %q", origin)
		}
	}

	if matchCORSOrigin("https://example.com", patterns) {
		t.Fatalf("did not expect bare domain to be allowed by wildcard pattern")
	}

	if matchCORSOrigin("https://example.com", patterns) {
		t.Fatalf("did not expect different domain to be allowed by wildcard pattern")
	}

	if matchCORSOrigin("http://app.example.com", patterns) {
		t.Fatalf("did not expect different scheme to be allowed by wildcard pattern")
	}
}

func TestMatchCORSOrigin_InvalidPatternDoesNotPanic(t *testing.T) {
	patterns := []string{"https://%gh&%ij"}

	if matchCORSOrigin("https://origin.example.com", patterns) {
		t.Fatalf("did not expect invalid URL pattern to match origin")
	}
}
