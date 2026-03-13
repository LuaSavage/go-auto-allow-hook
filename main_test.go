package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	configJSON := `{
		"allowed-list": [
			{
				"type": "Shell",
				"pattern": "^ls.*$"
			},
			{
				"type": "Git",
				"pattern": "^git\\s+status.*$"
			}
		],
		"ask-message": "Allow?",
		"agent-ask-message": "Need approval"
	}`

	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// Load config
	engine, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Check number of patterns
	if len(engine.patterns) != 2 {
		t.Errorf("Expected 2 patterns, got %d", len(engine.patterns))
	}

	// Test allowed commands
	tests := []struct {
		cmd      string
		expected string
	}{
		{"ls -la", "allow"},
		{"ls", "allow"},
		{"git status", "allow"},
		{"git status -s", "allow"},
		{"rm -rf /", "ask"},
		{"unknown", "ask"},
	}

	for _, tt := range tests {
		resp := engine.CheckCommand(tt.cmd)
		if resp.Permission != tt.expected {
			t.Errorf("Command %q: expected %q, got %q", tt.cmd, tt.expected, resp.Permission)
		}
	}

	// Check custom messages
	resp := engine.CheckCommand("bad command")
	if resp.UserMessage != "Allow?" {
		t.Errorf("Expected custom user message, got %q", resp.UserMessage)
	}
	if resp.AgentMessage != "Need approval" {
		t.Errorf("Expected custom agent message, got %q", resp.AgentMessage)
	}
}

func TestConfigNotFound(t *testing.T) {
	// Try to load non-existent config
	_, err := LoadConfig("/path/that/does/not/exist.json")
	if err == nil {
		t.Error("Expected error for non-existent config")
	}
}

func TestInvalidRegexInConfig(t *testing.T) {
	// Create config with invalid regex
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.json")

	configJSON := `{
		"allowed-list": [
			{
				"type": "Invalid",
				"pattern": "["
			}
		]
	}`

	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatal(err)
	}

	// Should still load (invalid regex is skipped)
	engine, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(engine.patterns) != 0 {
		t.Errorf("Expected 0 patterns (invalid regex skipped), got %d", len(engine.patterns))
	}
}
