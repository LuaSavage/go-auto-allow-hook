package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"regexp"
)

// Request describes the structure of the input from Cursor.
type Request struct {
	Command string `json:"command"`
}

// Response describes the structure of the output to Cursor.
type Response struct {
	Permission   string `json:"permission"` // "allow" or "ask"
	UserMessage  string `json:"userMessage,omitempty"`
	AgentMessage string `json:"agentMessage,omitempty"`
}

// AllowedItem represents a single allowed command pattern
type AllowedItem struct {
	Type        string `json:"type"`                  // для информации, не используется в regexp
	Pattern     string `json:"pattern"`               // регулярное выражение
	Description string `json:"description,omitempty"` // опционально
}

// Config represents the configuration file structure
type Config struct {
	AllowedList     []AllowedItem `json:"allowed-list"`
	AskMessage      string        `json:"ask-message,omitempty"`
	AgentAskMessage string        `json:"agent-ask-message,omitempty"`
}

// SecurityEngine holds the configuration and compiled patterns
type SecurityEngine struct {
	patterns        []*regexp.Regexp
	askMessage      string
	agentAskMessage string
}

// LoadConfig reads and parses the configuration file
func LoadConfig(path string) (*SecurityEngine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Set default messages if not provided
	if config.AskMessage == "" {
		config.AskMessage = "❓ Эта команда не разрешена. Разрешить выполнение?"
	}
	if config.AgentAskMessage == "" {
		config.AgentAskMessage = "Эта команда не в списке разрешенных. Нужно подтверждение пользователя."
	}

	engine := &SecurityEngine{
		patterns:        make([]*regexp.Regexp, 0, len(config.AllowedList)),
		askMessage:      config.AskMessage,
		agentAskMessage: config.AgentAskMessage,
	}

	// Compile all patterns
	for i, item := range config.AllowedList {
		if item.Pattern == "" {
			log.Printf("Warning: empty pattern at index %d", i)
			continue
		}

		re, err := regexp.Compile(item.Pattern)
		if err != nil {
			log.Printf("Warning: invalid regex pattern '%s': %v", item.Pattern, err)
			continue
		}
		engine.patterns = append(engine.patterns, re)
		log.Printf("Loaded pattern [%s]: %s", item.Type, item.Pattern)
	}

	log.Printf("Loaded %d allowed patterns", len(engine.patterns))
	return engine, nil
}

// CheckCommand evaluates a command against allowed patterns
func (e *SecurityEngine) CheckCommand(command string) Response {
	log.Printf("Checking command: %s", command)

	// Check if command matches any allowed pattern
	for _, pattern := range e.patterns {
		if pattern.MatchString(command) {
			log.Printf("Command allowed (matches pattern: %s)", pattern.String())
			return Response{Permission: "allow"}
		}
	}

	// No patterns matched - command is not allowed, ask user
	log.Printf("Command not in allowlist, asking user")
	return Response{
		Permission:   "ask",
		UserMessage:  e.askMessage,
		AgentMessage: e.agentAskMessage,
	}
}

func main() {
	// Determine config path
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = "."
	}

	// Try multiple possible config locations
	possiblePaths := []string{
		filepath.Join(homeDir, ".cursor", "hooks", "config.json"),
		"config.json", // current directory
	}

	var engine *SecurityEngine
	var loaded bool

	for _, path := range possiblePaths {
		engine, err = LoadConfig(path)
		if err == nil {
			log.Printf("Loaded config from %s", path)
			loaded = true
			break
		}
		log.Printf("Failed to load config from %s: %v", path, err)
	}

	if !loaded {
		log.Fatal("No valid config file found. Please create config.json")
	}

	// Read command from stdin
	var req Request
	decoder := json.NewDecoder(os.Stdin)
	if err := decoder.Decode(&req); err != nil {
		log.Printf("Error parsing input: %v", err)
		// On parse error, ask user to be safe
		resp := Response{
			Permission:   "ask",
			UserMessage:  "❓ Разрешить выполнение?",
			AgentMessage: "Требуется подтверждение.",
		}
		json.NewEncoder(os.Stdout).Encode(resp)
		return
	}

	// Check command against allowlist
	response := engine.CheckCommand(req.Command)

	// Send response back to Cursor
	if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}
