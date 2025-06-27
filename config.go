package main

import (
	"encoding/json"
	"os"
)

// Configuration holds all the settings for the application.
// The list of domains to monitor is now stored in the database.
type Configuration struct {
	DiscordBotToken      string `json:"discord_bot_token"`
	DiscordChannelID     string `json:"discord_channel_id"`
	CheckIntervalMinutes int    `json:"check_interval_minutes"`
}

// LoadConfiguration reads a configuration file from the given path and decodes it
// into a Configuration struct.
func LoadConfiguration(filePath string) (*Configuration, error) {
	// Read the file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Decode the JSON content into the struct
	var config Configuration
	err = json.Unmarshal(content, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// createDefaultConfiguration creates a new config.json with default values.
func createDefaultConfiguration(filePath string) error {
	defaultConfig := Configuration{
		DiscordBotToken:      "", // PLEASE FILL IN YOUR DISCORD BOT TOKEN
		DiscordChannelID:     "", // PLEASE FILL IN YOUR DISCORD CHANNEL ID
		CheckIntervalMinutes: 60,
	}

	// Marshal the struct into a nicely formatted JSON string
	content, err := json.MarshalIndent(defaultConfig, "", "  ")
	if err != nil {
		return err
	}

	// Write the content to the file
	return os.WriteFile(filePath, content, 0644)
}
