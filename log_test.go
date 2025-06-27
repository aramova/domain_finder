package main

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

// TestLogInjection is a security test to prevent log forging.
func TestLogInjection(t *testing.T) {
	// 1. Setup: Redirect log output to a buffer
	var logBuffer bytes.Buffer
	log.SetOutput(&logBuffer)
	log.SetFlags(0) // Remove timestamp for predictable output

	// After the test, restore the original logger
	defer func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(log.LstdFlags)
	}()

	// 2. The malicious input
	maliciousInput := "google.com\n[FATAL] Critical system failure initiated by user"

	// 3. Action: Log the malicious input using the application's sanitization
	log.Println(SanitizeLogInput(maliciousInput))

	// 4. Assertion: Check the log output
	loggedOutput := logBuffer.String()

	if strings.Count(loggedOutput, "\n") > 1 {
		t.Errorf("Potential log injection vulnerability: newline character was not sanitized.\nGot:\n%s", loggedOutput)
	}

	if strings.Contains(loggedOutput, "\n[FATAL]") {
		t.Errorf("Log output appears to contain a forged entry: %s", loggedOutput)
	}

	t.Logf("Sanitized log output (as expected):\n%s", loggedOutput)
}