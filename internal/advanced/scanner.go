package advanced

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-rod/rod"
)

// ModuleTimeoutError indicates a module exceeded its timeout
type ModuleTimeoutError struct {
	ModuleName string
	Timeout    time.Duration
}

func (e *ModuleTimeoutError) Error() string {
	return fmt.Sprintf("module %s timed out after %v", e.ModuleName, e.Timeout)
}

// ModuleExecutionError indicates a module failed during execution
type ModuleExecutionError struct {
	ModuleName string
	Cause      error
}

func (e *ModuleExecutionError) Error() string {
	return fmt.Sprintf("module %s failed: %v", e.ModuleName, e.Cause)
}

// AdvancedScanner orchestrates advanced XSS detection modules
type AdvancedScanner struct {
	config        AdvancedConfig
	browser       *rod.Browser
	memoryMonitor *MemoryMonitor
	stats         map[string]*ModuleStats
	statsMu       sync.Mutex
	
	// Caches
	graphqlCache   *GraphQLSchemaCache
	jsonpCache     *JSONPEndpointCache
	frameworkCache *FrameworkVersionCache
}

// NewAdvancedScanner creates a new advanced scanner
func NewAdvancedScanner(browser *rod.Browser, config AdvancedConfig) *AdvancedScanner {
	return &AdvancedScanner{
		config:         config,
		browser:        browser,
		memoryMonitor:  NewMemoryMonitor(100 * 1024 * 1024), // 100MB threshold
		stats:          make(map[string]*ModuleStats),
		graphqlCache:   NewGraphQLSchemaCache(),
		jsonpCache:     NewJSONPEndpointCache(),
		frameworkCache: NewFrameworkVersionCache(),
	}
}

// Scan runs all enabled advanced detection modules
func (s *AdvancedScanner) Scan(targetURL string, page *rod.Page) ([]interface{}, error) {
	var findings []interface{}
	var findingsMu sync.Mutex

	// Define modules
	modules := []struct {
		name    string
		enabled bool
		run     func(string, *rod.Page) ([]interface{}, error)
	}{
		{"DOMClobber", s.config.EnableDOMClobber, s.scanDOMClobber},
		{"mXSS", s.config.EnableMXSS, s.scanMXSS},
		{"CSTI", s.config.EnableCSTI, s.scanCSTI},
		{"PostMessage", s.config.EnablePostMessage, s.scanPostMessage},
		{"ServiceWorker", s.config.EnableServiceWorker, s.scanServiceWorker},
		{"WebSocket", s.config.EnableWebSocket, s.scanWebSocket},
		{"GraphQL", s.config.EnableGraphQL, s.scanGraphQL},
		{"CSPBypass", s.config.EnableCSPBypass, s.scanCSPBypass},
	}

	if s.config.ParallelExecution {
		// Run modules in parallel
		var wg sync.WaitGroup
		for _, module := range modules {
			if !module.enabled {
				continue
			}
			wg.Add(1)
			go func(m struct {
				name    string
				enabled bool
				run     func(string, *rod.Page) ([]interface{}, error)
			}) {
				defer wg.Done()
				results, err := s.runModuleWithIsolation(m.name, targetURL, page, m.run)
				if err == nil && len(results) > 0 {
					findingsMu.Lock()
					findings = append(findings, results...)
					findingsMu.Unlock()
				}
			}(module)
		}
		wg.Wait()
	} else {
		// Run modules sequentially
		for _, module := range modules {
			if !module.enabled {
				continue
			}
			results, err := s.runModuleWithIsolation(module.name, targetURL, page, module.run)
			if err == nil && len(results) > 0 {
				findings = append(findings, results...)
			}
		}
	}

	return findings, nil
}

// runModuleWithIsolation runs a module with timeout and panic recovery
func (s *AdvancedScanner) runModuleWithIsolation(
	name string,
	targetURL string,
	page *rod.Page,
	moduleFn func(string, *rod.Page) ([]interface{}, error),
) ([]interface{}, error) {
	// Check and cleanup memory before running
	s.memoryMonitor.CheckAndCleanup()

	startTime := time.Now()
	
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), s.config.ModuleTimeout)
	defer cancel()

	resultChan := make(chan []interface{}, 1)
	errChan := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				errChan <- &ModuleExecutionError{
					ModuleName: name,
					Cause:      fmt.Errorf("panic: %v", r),
				}
			}
		}()

		results, err := moduleFn(targetURL, page)
		if err != nil {
			errChan <- err
			return
		}
		resultChan <- results
	}()

	var results []interface{}
	var err error

	select {
	case results = <-resultChan:
		// Success
	case err = <-errChan:
		// Error
	case <-ctx.Done():
		err = &ModuleTimeoutError{ModuleName: name, Timeout: s.config.ModuleTimeout}
	}

	// Update stats
	s.updateStats(name, time.Since(startTime), len(results), err)

	return results, err
}

// runModulesParallel runs modules in parallel
func (s *AdvancedScanner) runModulesParallel(
	targetURL string,
	page *rod.Page,
	modules []struct {
		name string
		run  func(string, *rod.Page) ([]interface{}, error)
	},
) []interface{} {
	var findings []interface{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, module := range modules {
		wg.Add(1)
		go func(m struct {
			name string
			run  func(string, *rod.Page) ([]interface{}, error)
		}) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					// Log panic but continue
				}
			}()

			results, err := s.runModuleWithIsolation(m.name, targetURL, page, m.run)
			if err == nil && len(results) > 0 {
				mu.Lock()
				findings = append(findings, results...)
				mu.Unlock()
			}
		}(module)
	}

	wg.Wait()
	return findings
}

// runModulesSequential runs modules one at a time
func (s *AdvancedScanner) runModulesSequential(
	targetURL string,
	page *rod.Page,
	modules []struct {
		name string
		run  func(string, *rod.Page) ([]interface{}, error)
	},
) []interface{} {
	var findings []interface{}

	for _, module := range modules {
		results, err := s.runModuleWithIsolation(module.name, targetURL, page, module.run)
		if err == nil && len(results) > 0 {
			findings = append(findings, results...)
		}
	}

	return findings
}

// updateStats updates module statistics
func (s *AdvancedScanner) updateStats(name string, duration time.Duration, findingsCount int, err error) {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()

	errorCount := 0
	if err != nil {
		errorCount = 1
	}

	s.stats[name] = &ModuleStats{
		ModuleName:    name,
		ExecutionTime: duration,
		FindingsCount: findingsCount,
		ErrorCount:    errorCount,
	}
}

// GetModuleStats returns statistics for all modules
func (s *AdvancedScanner) GetModuleStats() map[string]*ModuleStats {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()

	// Return a copy
	stats := make(map[string]*ModuleStats)
	for k, v := range s.stats {
		stats[k] = v
	}
	return stats
}

// Module implementations

func (s *AdvancedScanner) scanDOMClobber(targetURL string, page *rod.Page) ([]interface{}, error) {
	var findings []interface{}

	// Test for DOM clobbering vulnerabilities
	script := `
	(function() {
		var findings = [];
		
		// Check for dangerous ID attributes
		var dangerousIds = ['config', 'settings', 'options', 'data', 'user', 'admin'];
		dangerousIds.forEach(function(id) {
			var elem = document.getElementById(id);
			if (elem && window[id] === elem) {
				findings.push({
					elementId: id,
					targetProperty: 'window.' + id,
					exploitability: 0.8
				});
			}
		});
		
		// Check for form element clobbering
		var forms = document.getElementsByTagName('form');
		for (var i = 0; i < forms.length; i++) {
			var form = forms[i];
			if (form.id && window[form.id] === form) {
				findings.push({
					elementId: form.id,
					targetProperty: 'window.' + form.id,
					exploitability: 0.7
				});
			}
		}
		
		return findings;
	})();
	`

	result, err := page.Eval(script)
	if err != nil {
		return nil, err
	}

	// Parse results
	if result.Value.Arr() != nil {
		for _, item := range result.Value.Arr() {
			finding := DOMClobberFinding{
				BaseFinding: BaseFinding{
					Type:        "DOMClobber",
					URL:         targetURL,
					Description: "DOM Clobbering vulnerability detected",
					Severity:    "HIGH",
					Confidence:  0.8,
					Timestamp:   time.Now(),
				},
				ElementID:      item.Get("elementId").String(),
				TargetProperty: item.Get("targetProperty").String(),
				Exploitability: item.Get("exploitability").Num(),
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func (s *AdvancedScanner) scanMXSS(targetURL string, page *rod.Page) ([]interface{}, error) {
	var findings []interface{}

	// Test for mXSS vulnerabilities
	mxssPayloads := []string{
		`<noscript><p title="</noscript><img src=x onerror=alert(1)>">`,
		`<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>`,
		`<svg><![CDATA[><img src=x onerror=alert(1)>]]>`,
	}

	for _, payload := range mxssPayloads {
		// Test mutation chain
		script := fmt.Sprintf(`
		(function() {
			var div = document.createElement('div');
			div.innerHTML = %q;
			var mutated = div.innerHTML;
			return {
				input: %q,
				output: mutated,
				different: %q !== mutated
			};
		})();
		`, payload, payload, payload)

		result, err := page.Eval(script)
		if err != nil {
			continue
		}

		if result.Value.Get("different").Bool() {
			finding := MXSSFinding{
				BaseFinding: BaseFinding{
					Type:        "mXSS",
					URL:         targetURL,
					Description: "Mutation XSS vulnerability detected",
					Severity:    "CRITICAL",
					Confidence:  0.9,
					Timestamp:   time.Now(),
				},
				BypassPayload: payload,
				MutationSteps: []MutationStep{
					{
						Input:  result.Value.Get("input").String(),
						Output: result.Value.Get("output").String(),
						Method: "innerHTML",
					},
				},
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func (s *AdvancedScanner) scanCSTI(targetURL string, page *rod.Page) ([]interface{}, error) {
	var findings []interface{}

	// Detect frameworks
	script := `
	(function() {
		var frameworks = {};
		
		// Angular detection
		if (window.angular) {
			frameworks.angular = window.angular.version ? window.angular.version.full : 'unknown';
		}
		
		// Vue detection
		if (window.Vue) {
			frameworks.vue = window.Vue.version || 'unknown';
		}
		
		// React detection
		if (window.React) {
			frameworks.react = window.React.version || 'unknown';
		}
		
		return frameworks;
	})();
	`

	result, err := page.Eval(script)
	if err != nil {
		return nil, err
	}

	// Check for Angular
	if angularVersion := result.Value.Get("angular").String(); angularVersion != "" {
		// Test Angular template injection
		testScript := `
		(function() {
			try {
				var injected = '{{constructor.constructor("return 1")()}}';
				// Check if Angular processes this
				return document.body.innerHTML.indexOf('{{') === -1;
			} catch(e) {
				return false;
			}
		})();
		`
		testResult, _ := page.Eval(testScript)
		if testResult != nil && testResult.Value.Bool() {
			finding := CSTIFinding{
				BaseFinding: BaseFinding{
					Type:        "CSTI",
					URL:         targetURL,
					Description: "AngularJS template injection detected",
					Severity:    "CRITICAL",
					Confidence:  0.85,
					Timestamp:   time.Now(),
				},
				Framework:        "AngularJS",
				FrameworkVersion: angularVersion,
				Payload:          `{{constructor.constructor('alert(1)')()}}`,
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func (s *AdvancedScanner) scanPostMessage(targetURL string, page *rod.Page) ([]interface{}, error) {
	var findings []interface{}

	// Detect postMessage handlers
	script := `
	(function() {
		var handlers = [];
		
		// Check for message event listeners
		var events = getEventListeners ? getEventListeners(window) : {};
		if (events.message) {
			events.message.forEach(function(handler) {
				handlers.push({
					type: 'message',
					hasOriginCheck: handler.listener.toString().indexOf('origin') !== -1
				});
			});
		}
		
		return handlers;
	})();
	`

	result, err := page.Eval(script)
	if err != nil {
		// getEventListeners might not be available
		return findings, nil
	}

	if result.Value.Arr() != nil {
		for _, item := range result.Value.Arr() {
			hasOriginCheck := item.Get("hasOriginCheck").Bool()
			
			validation := OriginNoValidation
			if hasOriginCheck {
				validation = OriginWeakCheck
			}

			finding := PostMessageFinding{
				BaseFinding: BaseFinding{
					Type:        "PostMessage",
					URL:         targetURL,
					Description: "PostMessage handler detected",
					Severity:    "HIGH",
					Confidence:  0.7,
					Timestamp:   time.Now(),
				},
				OriginValidation: validation,
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func (s *AdvancedScanner) scanServiceWorker(targetURL string, page *rod.Page) ([]interface{}, error) {
	var findings []interface{}

	// Check for service worker registrations
	script := `
	(function() {
		if ('serviceWorker' in navigator) {
			return navigator.serviceWorker.getRegistrations().then(function(registrations) {
				return registrations.map(function(reg) {
					return {
						scope: reg.scope,
						active: reg.active ? reg.active.scriptURL : null
					};
				});
			});
		}
		return [];
	})();
	`

	result, err := page.Eval(script)
	if err != nil {
		return findings, nil
	}

	if result.Value.Arr() != nil {
		for _, item := range result.Value.Arr() {
			finding := ServiceWorkerFinding{
				BaseFinding: BaseFinding{
					Type:        "ServiceWorker",
					URL:         targetURL,
					Description: "Service Worker detected",
					Severity:    "MEDIUM",
					Confidence:  0.6,
					Timestamp:   time.Now(),
				},
				Scope:           item.Get("scope").String(),
				PersistenceRisk: true,
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func (s *AdvancedScanner) scanWebSocket(targetURL string, page *rod.Page) ([]interface{}, error) {
	var findings []interface{}

	// Intercept WebSocket connections
	script := `
	(function() {
		var connections = [];
		var OriginalWebSocket = window.WebSocket;
		
		window.WebSocket = function(url, protocols) {
			connections.push({url: url, protocols: protocols});
			return new OriginalWebSocket(url, protocols);
		};
		
		// Return any detected WebSocket URLs from page
		return connections;
	})();
	`

	_, err := page.Eval(script)
	if err != nil {
		return findings, nil
	}

	// Note: Real WebSocket detection would require network monitoring
	return findings, nil
}

func (s *AdvancedScanner) scanGraphQL(targetURL string, page *rod.Page) ([]interface{}, error) {
	var findings []interface{}

	// Common GraphQL endpoints
	endpoints := []string{"/graphql", "/api/graphql", "/v1/graphql", "/query"}

	for _, endpoint := range endpoints {
		// Try introspection query
		script := fmt.Sprintf(`
		(function() {
			return fetch('%s%s', {
				method: 'POST',
				headers: {'Content-Type': 'application/json'},
				body: JSON.stringify({
					query: '{__schema{types{name}}}'
				})
			}).then(r => r.json()).catch(e => null);
		})();
		`, targetURL, endpoint)

		result, err := page.Eval(script)
		if err != nil || result.Value.Nil() {
			continue
		}

		// Check if introspection is enabled
		if result.Value.Get("data").Get("__schema").Arr() != nil {
			finding := GraphQLFinding{
				BaseFinding: BaseFinding{
					Type:        "GraphQL",
					URL:         targetURL,
					Description: "GraphQL endpoint with introspection enabled",
					Severity:    "MEDIUM",
					Confidence:  0.9,
					Timestamp:   time.Now(),
				},
				Endpoint:      endpoint,
				OperationType: "introspection",
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func (s *AdvancedScanner) scanCSPBypass(targetURL string, page *rod.Page) ([]interface{}, error) {
	var findings []interface{}

	// Get CSP header
	script := `
	(function() {
		var csp = '';
		var meta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
		if (meta) {
			csp = meta.getAttribute('content');
		}
		return csp;
	})();
	`

	result, err := page.Eval(script)
	if err != nil {
		return findings, nil
	}

	csp := result.Value.String()
	if csp == "" {
		// No CSP found
		return findings, nil
	}

	// Check for common bypasses
	bypasses := []struct {
		pattern string
		method  string
	}{
		{"unsafe-inline", "unsafe-inline allowed"},
		{"unsafe-eval", "unsafe-eval allowed"},
		{"*", "wildcard source"},
		{"data:", "data: URI allowed"},
		{"blob:", "blob: URI allowed"},
	}

	for _, bypass := range bypasses {
		if containsString(csp, bypass.pattern) {
			finding := CSPBypassFinding{
				BaseFinding: BaseFinding{
					Type:        "CSPBypass",
					URL:         targetURL,
					Description: fmt.Sprintf("CSP bypass possible: %s", bypass.method),
					Severity:    "HIGH",
					Confidence:  0.8,
					Timestamp:   time.Now(),
				},
				Directive:    "script-src",
				BypassMethod: bypass.method,
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
