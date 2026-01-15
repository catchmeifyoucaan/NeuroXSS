package discovery

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// JSAnalyzer analyzes JavaScript files for endpoints
type JSAnalyzer struct {
	httpClient *http.Client
	patterns   []*regexp.Regexp
}

// NewJSAnalyzer creates a new JavaScript analyzer
func NewJSAnalyzer() *JSAnalyzer {
	return &JSAnalyzer{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		patterns: []*regexp.Regexp{
			// API endpoints
			regexp.MustCompile(`["'` + "`" + `](/api/[a-zA-Z0-9/_-]+)["'` + "`" + `]`),
			regexp.MustCompile(`["'` + "`" + `](/v[0-9]+/[a-zA-Z0-9/_-]+)["'` + "`" + `]`),
			
			// Relative paths
			regexp.MustCompile(`["'` + "`" + `](/[a-zA-Z0-9/_-]+)["'` + "`" + `]`),
			
			// fetch() calls
			regexp.MustCompile(`fetch\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`),
			
			// axios calls
			regexp.MustCompile(`axios\.(get|post|put|delete)\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`),
			regexp.MustCompile(`axios\.delete\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`),
			
			// XMLHttpRequest
			regexp.MustCompile(`\.open\s*\(\s*["'][^"']+["']\s*,\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`),
			
			// WebSocket
			regexp.MustCompile(`new\s+WebSocket\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`),
			
			// GraphQL
			regexp.MustCompile(`["'` + "`" + `](/graphql|/api/graphql|/v1/graphql)["'` + "`" + `]`),
		},
	}
}

// ExtractEndpoints extracts API endpoints from a JavaScript file
func (a *JSAnalyzer) ExtractEndpoints(jsURL string) ([]string, error) {
	content, err := a.downloadJS(jsURL)
	if err != nil {
		return nil, err
	}

	endpoints := a.extractEndpointsFromContent(content)

	// Normalize endpoints
	parsedURL, err := url.Parse(jsURL)
	if err != nil {
		return endpoints, nil
	}

	var normalized []string
	seen := make(map[string]bool)

	for _, ep := range endpoints {
		normalizedEP := a.normalizeEndpoint(ep, parsedURL)
		if normalizedEP != "" && !seen[normalizedEP] {
			normalized = append(normalized, normalizedEP)
			seen[normalizedEP] = true
		}
	}

	return normalized, nil
}

// downloadJS downloads JavaScript content
func (a *JSAnalyzer) downloadJS(jsURL string) (string, error) {
	resp, err := a.httpClient.Get(jsURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Limit to 5MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// extractEndpointsFromContent extracts endpoints from JavaScript content
func (a *JSAnalyzer) extractEndpointsFromContent(content string) []string {
	var endpoints []string
	seen := make(map[string]bool)

	for _, pattern := range a.patterns {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			// Get the captured group (endpoint)
			var endpoint string
			if len(match) > 1 {
				endpoint = match[1]
			} else if len(match) > 0 {
				endpoint = match[0]
			}

			if endpoint != "" && !seen[endpoint] {
				// Filter out common non-endpoints
				if a.isValidEndpoint(endpoint) {
					endpoints = append(endpoints, endpoint)
					seen[endpoint] = true
				}
			}
		}
	}

	return endpoints
}

// isValidEndpoint checks if a string looks like a valid endpoint
func (a *JSAnalyzer) isValidEndpoint(ep string) bool {
	// Filter out common false positives
	invalid := []string{
		"http://",
		"https://",
		"//",
		".js",
		".css",
		".png",
		".jpg",
		".gif",
		".svg",
		".ico",
		".woff",
		"data:",
		"javascript:",
		"mailto:",
		"tel:",
	}

	for _, inv := range invalid {
		if strings.HasPrefix(ep, inv) || strings.Contains(ep, inv) {
			return false
		}
	}

	// Must start with /
	if !strings.HasPrefix(ep, "/") {
		return false
	}

	// Must have at least some path
	if len(ep) < 2 {
		return false
	}

	return true
}

// normalizeEndpoint normalizes an endpoint URL
func (a *JSAnalyzer) normalizeEndpoint(endpoint string, baseURL *url.URL) string {
	if endpoint == "" {
		return ""
	}

	// Handle relative URLs
	if strings.HasPrefix(endpoint, "/") {
		return endpoint // Return relative path, let caller resolve
	}

	// Handle WebSocket URLs
	if strings.HasPrefix(endpoint, "ws://") || strings.HasPrefix(endpoint, "wss://") {
		return endpoint
	}

	return endpoint
}
