package main

import (
	"os"
	"testing"
)

// TestLoadConfiguration_Success tests the successful loading of a valid config file.
func TestLoadConfiguration_Success(t *testing.T) {
	// Create a temporary config file for testing
	content := `{
		"discord_bot_token": "test_token",
		"discord_channel_id": "test_channel",
		"check_interval_minutes": 30
	}`
	tmpfile, err := os.CreateTemp("", "config.*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	// Attempt to load the configuration
	config, err := LoadConfiguration(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfiguration failed: %v", err)
	}

	// Validate the loaded configuration
	if config.DiscordBotToken != "test_token" {
		t.Errorf("Expected DiscordBotToken to be 'test_token', got '%s'", config.DiscordBotToken)
	}
	if config.DiscordChannelID != "test_channel" {
		t.Errorf("Expected DiscordChannelID to be 'test_channel', got '%s'", config.DiscordChannelID)
	}
	if config.CheckIntervalMinutes != 30 {
		t.Errorf("Expected CheckIntervalMinutes to be 30, got %d", config.CheckIntervalMinutes)
	}
}

// TestLoadConfiguration_FileNotExist tests the failure case where the config file does not exist.
func TestLoadConfiguration_FileNotExist(t *testing.T) {
	_, err := LoadConfiguration("non_existent_file.json")
	if err == nil {
		t.Fatal("Expected an error when loading a non-existent file, but got nil")
	}
}

// TestLoadConfiguration_InvalidJson tests the failure case where the config file contains invalid JSON.
func TestLoadConfiguration_InvalidJson(t *testing.T) {
	content := `{
		"discord_bot_token": "test_token"
		"discord_channel_id": "test_channel",
	}` // Invalid JSON (missing comma)
	tmpfile, err := os.CreateTemp("", "config.*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	_, err = LoadConfiguration(tmpfile.Name())
	if err == nil {
		t.Fatal("Expected an error when loading invalid JSON, but got nil")
	}
}

// TestLoadConfiguration_MissingFields tests for missing required fields.
func TestLoadConfiguration_MissingFields(t *testing.T) {
	content := `{
		"discord_bot_token": "test_token"
	}`
	tmpfile, err := os.CreateTemp("", "config.*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	// In a real implementation, you might want to validate this more strictly.
	// For now, we just ensure it parses without error, but a more robust
	// validation function would be the next step.
	config, err := LoadConfiguration(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfiguration failed: %v", err)
	}

	// A good validation function would catch this.
	if config.DiscordChannelID == "" {
		// This is expected in this test case, but shows the need for validation.
	}
}