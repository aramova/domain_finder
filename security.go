package main

import "strings"

// SanitizeLogInput removes characters from a string that could be used to
// forge log entries or manipulate log output.
func SanitizeLogInput(input string) string {
	// Replace newline and carriage return characters with a space.
	// This prevents log injection attacks where a user might provide
	// multi-line input to forge log entries.
	sanitized := strings.ReplaceAll(input, "\n", " ")
	sanitized = strings.ReplaceAll(sanitized, "\r", " ")
	return sanitized
}
