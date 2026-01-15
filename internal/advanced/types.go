// Package advanced provides advanced XSS detection modules
package advanced

import (
	"sync"
	"time"
)

// AdvancedConfig configures advanced detection modules
type AdvancedConfig struct {
	EnableDOMClobber    bool
	EnableMXSS          bool
	EnableCSTI          bool
	EnablePostMessage   bool
	EnableServiceWorker bool
	EnableWebSocket     bool
	EnableGraphQL       bool
	EnableCSPBypass     bool
	ModuleTimeout       time.Duration
	ParallelExecution   bool
}

// DefaultConfig returns default advanced configuration
func DefaultConfig() AdvancedConfig {
	return AdvancedConfig{
		ModuleTimeout:     30 * time.Second,
		ParallelExecution: true,
	}
}

// AllModulesConfig returns config with all modules enabled
func AllModulesConfig() AdvancedConfig {
	return AdvancedConfig{
		EnableDOMClobber:    true,
		EnableMXSS:          true,
		EnableCSTI:          true,
		EnablePostMessage:   true,
		EnableServiceWorker: true,
		EnableWebSocket:     true,
		EnableGraphQL:       true,
		EnableCSPBypass:     true,
		ModuleTimeout:       30 * time.Second,
		ParallelExecution:   true,
	}
}

// IsAnyModuleEnabled checks if any advanced module is enabled
func (c *AdvancedConfig) IsAnyModuleEnabled() bool {
	return c.EnableDOMClobber || c.EnableMXSS || c.EnableCSTI ||
		c.EnablePostMessage || c.EnableServiceWorker || c.EnableWebSocket ||
		c.EnableGraphQL || c.EnableCSPBypass
}

// BaseFinding is the base type for all findings
type BaseFinding struct {
	Type        string    `json:"type"`
	URL         string    `json:"url"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Confidence  float64   `json:"confidence"`
	POC         string    `json:"poc,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
}

// DOMClobberFinding represents a DOM clobbering vulnerability
type DOMClobberFinding struct {
	BaseFinding
	ElementID      string  `json:"element_id"`
	TargetProperty string  `json:"target_property"`
	Exploitability float64 `json:"exploitability"`
}

// MXSSFinding represents a mutation XSS vulnerability
type MXSSFinding struct {
	BaseFinding
	Sanitizer     string         `json:"sanitizer"`
	BypassPayload string         `json:"bypass_payload"`
	MutationSteps []MutationStep `json:"mutation_steps"`
}

// MutationStep represents a step in mXSS mutation chain
type MutationStep struct {
	Input  string `json:"input"`
	Output string `json:"output"`
	Method string `json:"method"`
}

// CSTIFinding represents a client-side template injection vulnerability
type CSTIFinding struct {
	BaseFinding
	Framework       string `json:"framework"`
	FrameworkVersion string `json:"framework_version"`
	InjectionPoint  string `json:"injection_point"`
	Payload         string `json:"payload"`
}

// PostMessageFinding represents a postMessage XSS vulnerability
type PostMessageFinding struct {
	BaseFinding
	Handler          string               `json:"handler"`
	OriginValidation OriginValidationType `json:"origin_validation"`
	VulnerableSink   string               `json:"vulnerable_sink"`
	DataFlow         []DataFlowStep       `json:"data_flow"`
}

// OriginValidationType represents how origin is validated
type OriginValidationType int

const (
	OriginNoValidation OriginValidationType = iota
	OriginWeakCheck
	OriginBypassable
	OriginStrong
)

func (o OriginValidationType) String() string {
	switch o {
	case OriginNoValidation:
		return "No Validation"
	case OriginWeakCheck:
		return "Weak Check"
	case OriginBypassable:
		return "Bypassable"
	case OriginStrong:
		return "Strong"
	default:
		return "Unknown"
	}
}

// DataFlowStep represents a step in data flow analysis
type DataFlowStep struct {
	Source      string `json:"source"`
	Sink        string `json:"sink"`
	Transformer string `json:"transformer,omitempty"`
}

// ServiceWorkerFinding represents a service worker vulnerability
type ServiceWorkerFinding struct {
	BaseFinding
	Scope            string `json:"scope"`
	VulnerabilityType string `json:"vulnerability_type"`
	PersistenceRisk  bool   `json:"persistence_risk"`
}

// WebSocketFinding represents a WebSocket XSS vulnerability
type WebSocketFinding struct {
	BaseFinding
	Endpoint       string `json:"endpoint"`
	MessageType    string `json:"message_type"`
	ReflectionSink string `json:"reflection_sink"`
}

// GraphQLFinding represents a GraphQL XSS vulnerability
type GraphQLFinding struct {
	BaseFinding
	Endpoint      string `json:"endpoint"`
	OperationType string `json:"operation_type"`
	Field         string `json:"field"`
	Query         string `json:"query"`
}

// CSPBypassFinding represents a CSP bypass vulnerability
type CSPBypassFinding struct {
	BaseFinding
	Directive    string `json:"directive"`
	BypassMethod string `json:"bypass_method"`
	Endpoint     string `json:"endpoint,omitempty"`
	Payload      string `json:"payload"`
}

// ModuleStats holds statistics for a module execution
type ModuleStats struct {
	ModuleName    string        `json:"module_name"`
	ExecutionTime time.Duration `json:"execution_time"`
	FindingsCount int           `json:"findings_count"`
	ErrorCount    int           `json:"error_count"`
}

// CacheEntry represents a cached value
type CacheEntry struct {
	Value     interface{}
	ExpiresAt time.Time
}

// ModuleCache provides caching for module results
type ModuleCache struct {
	cache map[string]CacheEntry
	mu    sync.RWMutex
	ttl   time.Duration
}

// NewModuleCache creates a new module cache
func NewModuleCache(ttl time.Duration) *ModuleCache {
	return &ModuleCache{
		cache: make(map[string]CacheEntry),
		ttl:   ttl,
	}
}

// Get retrieves a value from cache
func (c *ModuleCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.cache[key]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	return entry.Value, true
}

// Set stores a value in cache
func (c *ModuleCache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[key] = CacheEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(c.ttl),
	}
}

// MemoryMonitor tracks memory usage
type MemoryMonitor struct {
	threshold uint64
	mu        sync.Mutex
}

// NewMemoryMonitor creates a new memory monitor
func NewMemoryMonitor(threshold uint64) *MemoryMonitor {
	return &MemoryMonitor{
		threshold: threshold,
	}
}

// CheckAndCleanup checks memory and triggers cleanup if needed
func (m *MemoryMonitor) CheckAndCleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Runtime memory check would go here
}
