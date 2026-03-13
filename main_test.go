package main

import (
	"os"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRequestParsing(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantCmd  string
		wantErr  bool
	}{
		{
			name:    "valid json with command",
			input:   `{"command": "git status"}`,
			wantCmd: "git status",
			wantErr: false,
		},
		{
			name:    "valid json with empty command",
			input:   `{"command": ""}`,
			wantCmd: "",
			wantErr: false,
		},
		{
			name:    "invalid json",
			input:   `{"command": "test"`,
			wantCmd: "",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   ``,
			wantCmd: "",
			wantErr: true,
		},
		{
			name:    "missing command field",
			input:   `{"other": "value"}`,
			wantCmd: "",
			wantErr: false, // Decoder doesn't require field to exist, it will be zero value
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.input)
			decoder := json.NewDecoder(reader)
			
			var req Request
			err := decoder.Decode(&req)
			
			if (err != nil) != tt.wantErr {
				t.Errorf("Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			
			if !tt.wantErr && req.Command != tt.wantCmd {
				t.Errorf("req.Command = %q, want %q", req.Command, tt.wantCmd)
			}
		})
	}
}

func TestResponseEncoding(t *testing.T) {
	tests := []struct {
		name     string
		response Response
		wantJSON string
	}{
		{
			name: "allow response without messages",
			response: Response{
				Permission: "allow",
			},
			wantJSON: `{"permission":"allow"}`,
		},
		{
			name: "deny response with both messages",
			response: Response{
				Permission:  "deny",
				UserMessage: "Blocked",
				AgentMessage: "Command is not allowed",
			},
			wantJSON: `{"permission":"deny","userMessage":"Blocked","agentMessage":"Command is not allowed"}`,
		},
		{
			name: "deny response with only agent message",
			response: Response{
				Permission:  "deny",
				AgentMessage: "Use another command",
			},
			wantJSON: `{"permission":"deny","agentMessage":"Use another command"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			encoder := json.NewEncoder(&buf)
			
			err := encoder.Encode(tt.response)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			
			got := strings.TrimSpace(buf.String())
			if got != tt.wantJSON {
				t.Errorf("JSON = %q, want %q", got, tt.wantJSON)
			}
		})
	}
}

func TestMainFunctionality(t *testing.T) {
	// This is more of an integration test, but we can test the main logic
	// by capturing stdout and providing stdin
	
	tests := []struct {
		name       string
		inputJSON  string
		wantOutput string
	}{
		{
			name:       "safe command",
			inputJSON:  `{"command": "ls -la"}`,
			wantOutput: `{"permission":"allow"}`,
		},
		{
			name:       "dangerous command",
			inputJSON:  `{"command": "rm -rf /"}`,
			wantOutput: `{"permission":"deny","userMessage":"Blocked dangerous command: rm -rf /","agentMessage":"⛔ Recursive root deletion blocked"}`,
		},
		{
			name:       "invalid json",
			inputJSON:  `{invalid}`,
			wantOutput: `{"permission":"allow"}`, // Fail open behavior
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save original stdin/stdout
			oldStdin := os.Stdin
			oldStdout := os.Stdout
			defer func() {
				os.Stdin = oldStdin
				os.Stdout = oldStdout
			}()
			
			// Create pipe for stdin
			r, w, _ := os.Pipe()
			os.Stdin = r
			
			// Write input to stdin
			go func() {
				w.Write([]byte(tt.inputJSON))
				w.Close()
			}()
			
			// Capture stdout
			outR, outW, _ := os.Pipe()
			os.Stdout = outW
			
			// Run main
			main()
			
			// Read captured stdout
			outW.Close()
			var buf bytes.Buffer
			buf.ReadFrom(outR)
			
			got := strings.TrimSpace(buf.String())
			if got != tt.wantOutput {
				t.Errorf("main() output = %q, want %q", got, tt.wantOutput)
			}
		})
	}
}