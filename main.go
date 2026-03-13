package main

import (
	"encoding/json"
	"log"
	"os"
	"regexp"
)

// Request describes the structure of the input from Cursor.
type Request struct {
	Command string `json:"command"`
}

// Response describes the structure of the output to Cursor.
type Response struct {
	Permission  string `json:"permission"` // "allow" or "deny"
	UserMessage string `json:"userMessage,omitempty"`
	AgentMessage string `json:"agentMessage,omitempty"`
}

// Rule defines a single security rule.
type Rule struct {
	Pattern     *regexp.Regexp
	Action      string // "allow" or "deny"
	AgentMessage string
	UserMessage string
}

// SecurityEngine holds all rules.
type SecurityEngine struct {
	Rules []Rule
}

// NewSecurityEngine creates an engine with predefined rules.
// In a more advanced version, you would load these from a config file.
func NewSecurityEngine() *SecurityEngine {
	engine := &SecurityEngine{}

	// --- Block Rules (most specific/important first) ---
	engine.addRule(`rm\s+(-[rf]+\s*)*\/`, "deny", "⛔ Recursive root deletion blocked", "Blocked dangerous command: rm -rf /")
	engine.addRule(`dd\s+if=.*of=`, "deny", "⛔ DD disk operation blocked", "Blocked dangerous command: dd")
	engine.addRule(`mkfs\s+|fdisk\s+|parted\s+`, "deny", "⛔ Filesystem format blocked", "Blocked dangerous command: mkfs/fdisk/parted")
	engine.addRule(`kubectl\s+(apply|delete|create|edit|patch|scale|rollout)`, "deny", "⛔ Kubectl write operation blocked", "Blocked: kubectl write command")
	engine.addRule(`git\s+(push|commit|rebase|reset|merge|pull|fetch|add|rm)`, "deny", "⛔ Git write operation blocked", "Blocked: git write command")
	// Add more block rules from the original Python script and cli-config.json

	// --- Allow Rules (for safe commands, often using negative lookahead) ---
	// Allow specific git read commands
	engine.addRule(`git\s+(status|log|diff|show|blame|branch\s*$|remote\s*$)`, "allow", "", "")
	// Allow specific kubectl read commands
	engine.addRule(`kubectl\s+(get|describe|logs|explain|version|top)`, "allow", "", "")
	// Allow basic safe system commands
	engine.addRule(`^(ls|cat|echo|pwd|whoami|date|which|head|tail|grep)\b`, "allow", "", "")
	// Add more allow rules

	return engine
}

func (e *SecurityEngine) addRule(pattern string, action, agentMsg, userMsg string) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		log.Printf("Warning: invalid regex pattern '%s': %v", pattern, err)
		return
	}
	e.Rules = append(e.Rules, Rule{
		Pattern:     re,
		Action:      action,
		AgentMessage: agentMsg,
		UserMessage: userMsg,
	})
}

// CheckCommand evaluates a command against all rules.
// It returns the first matching rule's action and messages.
// If no rules match, it defaults to "allow" (fail open) or could default to "deny".
// In this example, we default to "allow" to be safe for development, but you can change it.
func (e *SecurityEngine) CheckCommand(command string) Response {
	for _, rule := range e.Rules {
		if rule.Pattern.MatchString(command) {
			if rule.Action == "deny" {
				return Response{
					Permission:  "deny",
					UserMessage: rule.UserMessage,
					AgentMessage: rule.AgentMessage,
				}
			}
			// If it's an "allow" rule, we allow it immediately
			return Response{Permission: "allow"}
		}
	}
	// Default behavior: allow (fail open) - matches original hook's safe default
	// Consider changing to "deny" for a strict "default-deny" policy
	return Response{Permission: "allow"}
}

func main() {
	var req Request
	decoder := json.NewDecoder(os.Stdin)
	if err := decoder.Decode(&req); err != nil {
		log.Printf("Error parsing input: %v", err)
		resp := Response{Permission: "allow"}
		json.NewEncoder(os.Stdout).Encode(resp)
		return
	}

	engine := NewSecurityEngine()
	response := engine.CheckCommand(req.Command)

	if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
		log.Printf("Error encoding response: %v", err)
	}
}