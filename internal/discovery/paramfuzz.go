package discovery

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// FuzzResult represents the result of parameter fuzzing
type FuzzResult struct {
	Parameter string
	Reflected bool
	Context   int
	Canary    string
}

// ParameterFuzzer fuzzes URL parameters for reflection
type ParameterFuzzer struct {
	httpClient     *http.Client
	commonParams   []string
	timeout        time.Duration
}

// NewParameterFuzzer creates a new parameter fuzzer
func NewParameterFuzzer() *ParameterFuzzer {
	return &ParameterFuzzer{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		timeout: 10 * time.Second,
		commonParams: []string{
			"q", "s", "search", "query", "keyword", "term",
			"id", "page", "p", "cat", "category",
			"name", "title", "text", "msg", "message",
			"comment", "content", "data", "value", "input",
			"url", "link", "redirect", "return", "next", "back", "goto",
			"callback", "jsonp", "cb", "func", "function",
			"file", "path", "template", "include", "view",
			"action", "do", "cmd", "command", "exec",
			"email", "mail", "user", "username", "login",
			"sort", "order", "dir", "type", "format",
			"lang", "language", "locale", "debug", "test",
		},
	}
}

// FuzzParameters fuzzes parameters for a URL
func (f *ParameterFuzzer) FuzzParameters(targetURL string, client *http.Client) ([]FuzzResult, error) {
	var results []FuzzResult

	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	// Get existing parameters
	params := f.buildParameterList(parsedURL)

	// Test each parameter
	for _, param := range params {
		result, err := f.TestParameter(targetURL, param, client)
		if err != nil {
			continue
		}
		if result.Reflected {
			results = append(results, *result)
		}
	}

	return results, nil
}

// buildParameterList builds a list of parameters to test
func (f *ParameterFuzzer) buildParameterList(parsedURL *url.URL) []string {
	params := make(map[string]bool)

	// Add existing query parameters
	for param := range parsedURL.Query() {
		params[param] = true
	}

	// Add common parameters
	for _, param := range f.commonParams {
		params[param] = true
	}

	// Convert to slice
	var paramList []string
	for param := range params {
		paramList = append(paramList, param)
	}

	return paramList
}

// TestParameter tests a single parameter for reflection
func (f *ParameterFuzzer) TestParameter(targetURL, param string, client *http.Client) (*FuzzResult, error) {
	result := &FuzzResult{
		Parameter: param,
	}

	// Generate canary
	canary := f.generateCanary()
	result.Canary = canary

	// Make baseline request first
	baseline, err := f.makeRequest(targetURL, client)
	if err != nil {
		return nil, fmt.Errorf("baseline request failed: %w", err)
	}

	// Make request with canary
	testURL := f.injectParameter(targetURL, param, canary)
	testResponse, err := f.makeRequest(testURL, client)
	if err != nil {
		return nil, fmt.Errorf("test request failed: %w", err)
	}

	// Check for reflection
	if strings.Contains(testResponse, canary) {
		result.Reflected = true
		result.Context = f.determineReflectionContext(testResponse, canary)
	}

	// Check for behavioral change
	if f.detectBehavioralChange(baseline, testResponse) {
		// Might indicate parameter is processed even if not reflected
	}

	return result, nil
}

// generateCanary generates a unique canary string
func (f *ParameterFuzzer) generateCanary() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return "nxss" + hex.EncodeToString(bytes)
}

// makeRequest makes an HTTP request and returns the response body
func (f *ParameterFuzzer) makeRequest(targetURL string, client *http.Client) (string, error) {
	if client == nil {
		client = f.httpClient
	}

	resp, err := client.Get(targetURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read up to 1MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// injectParameter injects a parameter into a URL
func (f *ParameterFuzzer) injectParameter(targetURL, param, value string) string {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}

	query := parsedURL.Query()
	query.Set(param, value)
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String()
}

// determineReflectionContext determines where the canary is reflected
func (f *ParameterFuzzer) determineReflectionContext(response, canary string) int {
	idx := strings.Index(response, canary)
	if idx == -1 {
		return int(ContextUnknown)
	}

	// Get surrounding context (100 chars before and after)
	start := idx - 100
	if start < 0 {
		start = 0
	}
	end := idx + len(canary) + 100
	if end > len(response) {
		end = len(response)
	}
	context := response[start:end]

	// Check for JavaScript context
	if strings.Contains(context, "<script") || strings.Contains(context, "javascript:") {
		return int(ContextJavaScript)
	}

	// Check for attribute context
	beforeCanary := response[start:idx]
	if strings.Contains(beforeCanary, "=\"") || strings.Contains(beforeCanary, "='") {
		// Check if inside an attribute value
		lastQuote := strings.LastIndexAny(beforeCanary, "\"'")
		lastEquals := strings.LastIndex(beforeCanary, "=")
		if lastEquals != -1 && lastQuote > lastEquals {
			return int(ContextAttribute)
		}
	}

	// Check for URL context
	if strings.Contains(context, "href=") || strings.Contains(context, "src=") {
		return int(ContextURL)
	}

	// Default to HTML context
	return int(ContextHTML)
}

// detectBehavioralChange detects if the response changed significantly
func (f *ParameterFuzzer) detectBehavioralChange(baseline, test string) bool {
	// Simple heuristic: check if length changed significantly
	baseLen := len(baseline)
	testLen := len(test)

	if baseLen == 0 {
		return testLen > 0
	}

	diff := float64(testLen-baseLen) / float64(baseLen)
	return diff > 0.1 || diff < -0.1
}
