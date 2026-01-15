// Package core provides the core XSS scanning engine
package core

import (
	"time"
)

// Config holds the scanner configuration
type Config struct {
	Timeout         time.Duration
	Concurrency     int
	Verbose         bool
	AutoDiscover    bool
	MaxPages        int
	MaxDepth        int
	BlindXSS        bool
	CallbackDomain  string
	CallbackPort    int
	ContextAware    bool
	Interception    bool
}

// ContextAwareConfig holds context-aware scanning configuration
type ContextAwareConfig struct {
	ProbeTimeout        time.Duration
	CompilationTimeout  time.Duration
	MaxBypassAttempts   int
	EnableInterception  bool
}

// DefaultConfig returns default scanner configuration
func DefaultConfig() Config {
	return Config{
		Timeout:      30 * time.Second,
		Concurrency:  5,
		Verbose:      false,
		AutoDiscover: false,
		MaxPages:     100,
		MaxDepth:     3,
		BlindXSS:     false,
		CallbackPort: 8080,
	}
}

// DefaultContextAwareConfig returns default context-aware configuration
func DefaultContextAwareConfig() ContextAwareConfig {
	return ContextAwareConfig{
		ProbeTimeout:        2 * time.Second,
		CompilationTimeout:  100 * time.Millisecond,
		MaxBypassAttempts:   5,
		EnableInterception:  false,
	}
}

// ScanResult represents the result of a scan
type ScanResult struct {
	URL              string            `json:"url"`
	Vulnerable       bool              `json:"vulnerable"`
	Payload          string            `json:"payload,omitempty"`
	Sink             string            `json:"sink,omitempty"`
	Evidence         *ExecutionEvidence `json:"evidence,omitempty"`
	Error            error             `json:"error,omitempty"`
	Timestamp        time.Time         `json:"timestamp"`
	AdvancedFindings []interface{}     `json:"advanced_findings,omitempty"`
}

// ExecutionEvidence captures proof of XSS execution
type ExecutionEvidence struct {
	Canary       string    `json:"canary"`
	Sink         string    `json:"sink"`
	StackTrace   string    `json:"stack_trace,omitempty"`
	Screenshot   []byte    `json:"screenshot,omitempty"`
	DOMState     string    `json:"dom_state,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

// ReflectionPoint represents a point where input is reflected
type ReflectionPoint struct {
	Parameter    string
	Position     DOMPosition
	Context      ContextType
	Surrounding  SurroundingContext
	IsExecutable bool
}

// DOMPosition represents a position in the DOM
type DOMPosition struct {
	TagName     string
	AttributeName string
	InScript    bool
	InAttribute bool
	InComment   bool
}

// SurroundingContext captures the context around reflection
type SurroundingContext struct {
	Before string
	After  string
	Full   string
}

// ContextType represents the injection context
type ContextType int

const (
	ContextUnknown ContextType = iota
	ContextHTML
	ContextJavaScript
	ContextAttribute
	ContextJSON
	ContextCSS
	ContextURL
	ContextComment
	ContextCDATA
	ContextXML
)

// CompiledPayload represents a context-specific payload
type CompiledPayload struct {
	Value       string
	Context     ContextType
	Canary      string
	Encoding    string
	BypassType  string
}

// ModuleStats holds statistics for a scanning module
type ModuleStats struct {
	ModuleName     string
	ExecutionTime  time.Duration
	FindingsCount  int
	ErrorCount     int
}
