package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"

	"github.com/catchmeifyoucaan/neuroxss/internal/generator"
	"github.com/catchmeifyoucaan/neuroxss/internal/utils"
)

// Engine is the core XSS scanning engine
type Engine struct {
	browser      *rod.Browser
	config       Config
	ctxConfig    ContextAwareConfig
	generator    *generator.Generator
	hookScript   string
	mu           sync.Mutex
	isConnected  bool
}

// NewEngine creates a new scanning engine
func NewEngine(config Config) (*Engine, error) {
	// Find Chrome/Chromium
	path, found := launcher.LookPath()
	if !found {
		return nil, &BrowserError{Message: "Chrome/Chromium not found"}
	}

	// Launch browser with security flags disabled for testing
	l := launcher.New().
		Bin(path).
		Headless(true).
		Set("disable-web-security").
		Set("disable-features", "IsolateOrigins,site-per-process").
		Set("no-sandbox").
		Set("disable-setuid-sandbox").
		Set("disable-dev-shm-usage").
		Set("disable-accelerated-2d-canvas").
		Set("disable-gpu").
		Set("disable-background-networking").
		Set("disable-backgrounding-occluded-windows").
		Set("disable-client-side-phishing-detection").
		Set("disable-default-apps").
		Set("disable-extensions").
		Set("disable-hang-monitor").
		Set("disable-ipc-flooding-protection").
		Set("disable-popup-blocking").
		Set("disable-prompt-on-repost").
		Set("disable-sync").
		Set("disable-translate").
		Set("metrics-recording-only").
		Set("no-first-run").
		Set("safebrowsing-disable-auto-update")

	controlURL, err := l.Launch()
	if err != nil {
		return nil, &BrowserError{Message: "failed to launch browser", Cause: err}
	}

	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		return nil, &BrowserError{Message: "failed to connect to browser", Cause: err}
	}

	engine := &Engine{
		browser:     browser,
		config:      config,
		ctxConfig:   DefaultContextAwareConfig(),
		generator:   generator.NewGenerator(),
		hookScript:  loadHookScript(),
		isConnected: true,
	}

	return engine, nil
}

// Close shuts down the engine
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.browser != nil && e.isConnected {
		e.isConnected = false
		return e.browser.Close()
	}
	return nil
}

// IsBrowserAlive checks if the browser is still connected
func (e *Engine) IsBrowserAlive() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.isConnected
}

// RecoverBrowser attempts to recover from browser crashes
func (e *Engine) RecoverBrowser() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.browser != nil {
		e.browser.Close()
	}

	path, found := launcher.LookPath()
	if !found {
		return &BrowserError{Message: "Chrome/Chromium not found during recovery"}
	}

	l := launcher.New().Bin(path).Headless(true)
	controlURL, err := l.Launch()
	if err != nil {
		return &BrowserError{Message: "failed to relaunch browser", Cause: err}
	}

	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		return &BrowserError{Message: "failed to reconnect to browser", Cause: err}
	}

	e.browser = browser
	e.isConnected = true
	return nil
}

// Scan performs XSS scanning on a single URL
func (e *Engine) Scan(targetURL string) (*ScanResult, error) {
	result := &ScanResult{
		URL:       targetURL,
		Timestamp: time.Now(),
	}

	// Parse URL to find injection points
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Error = &NetworkError{Message: "invalid URL", URL: targetURL, Cause: err}
		return result, result.Error
	}

	// Generate canary for this scan
	canary := utils.GenerateCanary()

	// Generate payloads
	payloads := e.generator.Generate(generator.ContextHTML, canary)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), e.config.Timeout)
	defer cancel()

	// Try each payload
	for _, payload := range payloads {
		// Construct injection URL
		injectedURL := injectPayloadIntoURL(parsedURL, payload.Value)

		// Create new page
		page, err := e.browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
		if err != nil {
			continue
		}

		// Inject Ghost Hook before page loads
		if err := e.InjectHook(page, canary); err != nil {
			page.Close()
			continue
		}

		// Navigate with timeout
		err = page.Context(ctx).Navigate(injectedURL)
		if err != nil {
			page.Close()
			continue
		}

		// Wait for page to load
		page.WaitLoad()

		// Check for XSS execution
		evidence, found := e.CheckForEvidence(page, canary)
		if found {
			result.Vulnerable = true
			result.Payload = payload.Value
			result.Evidence = evidence
			result.Sink = evidence.Sink

			// Capture screenshot as evidence
			if e.config.Verbose {
				screenshot, _ := captureScreenshot(page)
				if evidence != nil {
					evidence.Screenshot = screenshot
				}
			}

			page.Close()
			return result, nil
		}

		page.Close()
	}

	return result, nil
}

// ScanBatch scans multiple URLs concurrently
func (e *Engine) ScanBatch(urls []string) []*ScanResult {
	results := make([]*ScanResult, len(urls))
	var wg sync.WaitGroup

	// Create worker pool
	semaphore := make(chan struct{}, e.config.Concurrency)

	for i, targetURL := range urls {
		wg.Add(1)
		go func(idx int, u string) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			result, _ := e.Scan(u)
			results[idx] = result
		}(i, targetURL)
	}

	wg.Wait()
	return results
}

// InjectHook injects the Ghost Hook script into a page
func (e *Engine) InjectHook(page *rod.Page, canary string) error {
	// Replace canary placeholder in hook script
	script := replaceCanary(e.hookScript, canary)

	// Inject script to run before any other scripts
	_, err := page.Eval(script)
	if err != nil {
		return &HookInjectionError{Message: "failed to inject hook", Cause: err}
	}

	return nil
}

// CheckForEvidence checks if XSS was executed
func (e *Engine) CheckForEvidence(page *rod.Page, canary string) (*ExecutionEvidence, bool) {
	// Check if canary was triggered
	script := fmt.Sprintf(`window["%s"] === 1`, canary)
	result, err := page.Eval(script)
	if err != nil {
		return nil, false
	}

	if result.Value.Bool() {
		evidence := &ExecutionEvidence{
			Canary:    canary,
			Timestamp: time.Now(),
		}

		// Try to get sink information from hook
		sinkScript := `window.__NEUROXSS_SINK || "unknown"`
		sinkResult, err := page.Eval(sinkScript)
		if err == nil {
			evidence.Sink = sinkResult.Value.String()
		}

		// Try to get stack trace
		stackScript := `window.__NEUROXSS_STACK || ""`
		stackResult, err := page.Eval(stackScript)
		if err == nil {
			evidence.StackTrace = stackResult.Value.String()
		}

		return evidence, true
	}

	return nil, false
}

// CreateContext analyzes the page and creates context-aware payloads
func (e *Engine) CreateContext(page *rod.Page, targetURL string) ([]ReflectionPoint, error) {
	var reflectionPoints []ReflectionPoint

	// Parse URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// Get query parameters
	params := parsedURL.Query()

	for paramName := range params {
		// Deploy probe canary
		probeCanary := utils.GenerateCanaryWithPrefix("probe")
		probeURL := injectPayloadIntoURLParam(parsedURL, paramName, probeCanary)

		// Navigate and analyze
		err := page.Navigate(probeURL)
		if err != nil {
			continue
		}
		page.WaitLoad()

		// Get page HTML
		html, err := page.HTML()
		if err != nil {
			continue
		}

		// Find reflection points
		if strings.Contains(html, probeCanary) {
			point := ReflectionPoint{
				Parameter: paramName,
			}

			// Analyze context
			point.Context = analyzeContext(html, probeCanary)
			point.Surrounding = extractSurrounding(html, probeCanary)

			reflectionPoints = append(reflectionPoints, point)
		}
	}

	return reflectionPoints, nil
}

// SetupCallback sets up the blind XSS callback server
func (e *Engine) SetupCallback(domain string, port int) error {
	// This would start an HTTP server to receive callbacks
	// Implementation depends on specific requirements
	return nil
}

// DiscoverAndScan performs auto-discovery and scanning
func (e *Engine) DiscoverAndScan(baseURL string) ([]*ScanResult, error) {
	// This would integrate with the discovery engine
	// For now, just scan the base URL
	result, err := e.Scan(baseURL)
	if err != nil {
		return nil, err
	}
	return []*ScanResult{result}, nil
}

// CleanupContext cleans up context-aware scanning resources
func (e *Engine) CleanupContext() {
	// Cleanup any temporary resources
}

// Helper functions

func injectPayloadIntoURL(parsedURL *url.URL, payload string) string {
	// Clone the URL
	newURL := *parsedURL

	// Inject into each query parameter
	params := newURL.Query()
	for key := range params {
		params.Set(key, payload)
	}
	newURL.RawQuery = params.Encode()

	return newURL.String()
}

func injectPayloadIntoURLParam(parsedURL *url.URL, param, payload string) string {
	newURL := *parsedURL
	params := newURL.Query()
	params.Set(param, payload)
	newURL.RawQuery = params.Encode()
	return newURL.String()
}

func replaceCanary(script, canary string) string {
	return strings.ReplaceAll(script, "CANARY_PLACEHOLDER", canary)
}

func analyzeContext(html, canary string) ContextType {
	idx := strings.Index(html, canary)
	if idx == -1 {
		return ContextUnknown
	}

	// Get surrounding context
	start := idx - 100
	if start < 0 {
		start = 0
	}
	end := idx + len(canary) + 100
	if end > len(html) {
		end = len(html)
	}
	context := html[start:end]

	// Check for script context
	if strings.Contains(context, "<script") {
		return ContextJavaScript
	}

	// Check for attribute context
	beforeCanary := html[start:idx]
	if strings.Contains(beforeCanary, "=\"") || strings.Contains(beforeCanary, "='") {
		return ContextAttribute
	}

	// Default to HTML context
	return ContextHTML
}

func extractSurrounding(html, canary string) SurroundingContext {
	idx := strings.Index(html, canary)
	if idx == -1 {
		return SurroundingContext{}
	}

	start := idx - 50
	if start < 0 {
		start = 0
	}
	end := idx + len(canary) + 50
	if end > len(html) {
		end = len(html)
	}

	return SurroundingContext{
		Before: html[start:idx],
		After:  html[idx+len(canary) : end],
		Full:   html[start:end],
	}
}

func captureScreenshot(page *rod.Page) ([]byte, error) {
	return page.Screenshot(true, nil)
}

// loadHookScript returns the Ghost Hook JavaScript
func loadHookScript() string {
	return `
(function() {
	'use strict';
	
	// Ghost Hook - Monitors dangerous sinks before page scripts execute
	var canary = 'CANARY_PLACEHOLDER';
	var originalSinks = {};
	
	// Store sink information
	window.__NEUROXSS_SINK = '';
	window.__NEUROXSS_STACK = '';
	
	// Monitor innerHTML
	var originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
	Object.defineProperty(Element.prototype, 'innerHTML', {
		set: function(value) {
			if (value && value.toString().indexOf(canary) !== -1) {
				window[canary] = 1;
				window.__NEUROXSS_SINK = 'innerHTML';
				window.__NEUROXSS_STACK = new Error().stack;
			}
			return originalInnerHTML.set.call(this, value);
		},
		get: originalInnerHTML.get
	});
	
	// Monitor document.write
	var originalDocWrite = document.write;
	document.write = function(content) {
		if (content && content.toString().indexOf(canary) !== -1) {
			window[canary] = 1;
			window.__NEUROXSS_SINK = 'document.write';
			window.__NEUROXSS_STACK = new Error().stack;
		}
		return originalDocWrite.apply(this, arguments);
	};
	
	// Monitor eval
	var originalEval = window.eval;
	window.eval = function(code) {
		if (code && code.toString().indexOf(canary) !== -1) {
			window[canary] = 1;
			window.__NEUROXSS_SINK = 'eval';
			window.__NEUROXSS_STACK = new Error().stack;
		}
		return originalEval.apply(this, arguments);
	};
	
	// Monitor setTimeout with string
	var originalSetTimeout = window.setTimeout;
	window.setTimeout = function(fn, delay) {
		if (typeof fn === 'string' && fn.indexOf(canary) !== -1) {
			window[canary] = 1;
			window.__NEUROXSS_SINK = 'setTimeout';
			window.__NEUROXSS_STACK = new Error().stack;
		}
		return originalSetTimeout.apply(this, arguments);
	};
	
	// Monitor setInterval with string
	var originalSetInterval = window.setInterval;
	window.setInterval = function(fn, delay) {
		if (typeof fn === 'string' && fn.indexOf(canary) !== -1) {
			window[canary] = 1;
			window.__NEUROXSS_SINK = 'setInterval';
			window.__NEUROXSS_STACK = new Error().stack;
		}
		return originalSetInterval.apply(this, arguments);
	};
	
	// Monitor Function constructor
	var originalFunction = window.Function;
	window.Function = function() {
		var args = Array.prototype.slice.call(arguments);
		var body = args[args.length - 1] || '';
		if (body.toString().indexOf(canary) !== -1) {
			window[canary] = 1;
			window.__NEUROXSS_SINK = 'Function';
			window.__NEUROXSS_STACK = new Error().stack;
		}
		return originalFunction.apply(this, arguments);
	};
	
	// Monitor location.href
	var originalLocation = Object.getOwnPropertyDescriptor(window, 'location');
	
	// Monitor outerHTML
	var originalOuterHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
	if (originalOuterHTML && originalOuterHTML.set) {
		Object.defineProperty(Element.prototype, 'outerHTML', {
			set: function(value) {
				if (value && value.toString().indexOf(canary) !== -1) {
					window[canary] = 1;
					window.__NEUROXSS_SINK = 'outerHTML';
					window.__NEUROXSS_STACK = new Error().stack;
				}
				return originalOuterHTML.set.call(this, value);
			},
			get: originalOuterHTML.get
		});
	}
	
	// Monitor insertAdjacentHTML
	var originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
	Element.prototype.insertAdjacentHTML = function(position, text) {
		if (text && text.toString().indexOf(canary) !== -1) {
			window[canary] = 1;
			window.__NEUROXSS_SINK = 'insertAdjacentHTML';
			window.__NEUROXSS_STACK = new Error().stack;
		}
		return originalInsertAdjacentHTML.apply(this, arguments);
	};
	
	console.log('[GhostHook] Monitoring initialized for canary: ' + canary);
})();
`
}

// ParseExecutionEvidence parses evidence from JSON
func ParseExecutionEvidence(data []byte) (*ExecutionEvidence, error) {
	var evidence ExecutionEvidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		return nil, fmt.Errorf("failed to parse execution evidence: %w", err)
	}
	return &evidence, nil
}
