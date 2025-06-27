package main

import (
	"testing"
	"time"
)

func TestIsValidDomain(t *testing.T) {
	testCases := []struct {
		domain  string
		isValid bool
	}{
		{"google.com", true},
		{"example.co.uk", true},
		{"a-domain.net", true},
		{"123.io", true},
		{"xn--bcher-kva.de", true}, // Punycode
		{"", false},
		{"-invalid.com", false},
		{"invalid-.com", false},
		{"invalid.c", false},
		{"invalid", false},
		{"invalid.com-", false},
		{"invalid..com", false},
		{"!@#$%.com", false},
	}

	for _, tc := range testCases {
		t.Run(tc.domain, func(t *testing.T) {
			if got := isValidDomain(tc.domain); got != tc.isValid {
				t.Errorf("isValidDomain(%q) = %v; want %v", tc.domain, got, tc.isValid)
			}
		})
	}
}

// TestIsValidDomain_ReDoS is a security test to ensure the regex is not
// vulnerable to Regular Expression Denial of Service (ReDoS).
func TestIsValidDomain_ReDoS(t *testing.T) {
	// This is a classic "evil" regex pattern. A vulnerable regex may take
	// an extremely long time to process this string due to backtracking.
	// The pattern is a long sequence of valid characters that could cause
	// catastrophic backtracking in a poorly written regex.
	evilDomain := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com"

	// We run this in a goroutine so we can time it out.
	done := make(chan bool)
	go func() {
		isValidDomain(evilDomain)
		done <- true
	}()

	select {
	case <-done:
		// The function completed, which is good.
	case <-time.After(10 * time.Millisecond):
		// The function took too long, which is a sign of a potential ReDoS vulnerability.
		t.Fatal("isValidDomain took too long to execute, potential ReDoS vulnerability")
	}
}
