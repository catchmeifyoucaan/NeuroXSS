package discovery

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/go-rod/rod"
)

// DiscoveryEngine orchestrates attack surface discovery
type DiscoveryEngine struct {
	crawler           *Crawler
	jsAnalyzer        *JSAnalyzer
	paramFuzzer       *ParameterFuzzer
	frameworkDetector *FrameworkDetector
	browser           *rod.Browser
	httpClient        *http.Client
	config            CrawlConfig
}

// NewDiscoveryEngine creates a new discovery engine
func NewDiscoveryEngine(config CrawlConfig) *DiscoveryEngine {
	engine := &DiscoveryEngine{
		crawler:           NewCrawler(config),
		jsAnalyzer:        NewJSAnalyzer(),
		paramFuzzer:       NewParameterFuzzer(),
		frameworkDetector: NewFrameworkDetector(),
		config:            config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}

	engine.frameworkDetector.initializeSignatures()

	return engine
}

// SetBrowser sets the browser instance
func (e *DiscoveryEngine) SetBrowser(browser *rod.Browser) {
	e.browser = browser
	e.crawler.SetBrowser(browser)
}

// Discover performs full attack surface discovery
func (e *DiscoveryEngine) Discover(baseURL string) (*DiscoveryResult, error) {
	result := &DiscoveryResult{
		Timestamp: time.Now(),
	}

	// Parse base URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Phase 1: Crawl the site
	endpoints, forms, err := e.crawlSite(baseURL)
	if err != nil {
		// Continue even if crawling partially fails
		fmt.Printf("Warning: crawling failed: %v\n", err)
	}
	result.Endpoints = endpoints
	result.Forms = forms

	// Phase 2: Parse robots.txt for additional paths
	robotsPaths, _ := e.crawler.ParseRobotsTxt(baseURL)
	for _, path := range robotsPaths {
		fullURL := parsedURL.Scheme + "://" + parsedURL.Host + path
		if !contains(result.Endpoints, fullURL) {
			result.Endpoints = append(result.Endpoints, fullURL)
		}
	}

	// Phase 3: Analyze JavaScript files
	for _, endpoint := range endpoints {
		if strings.HasSuffix(endpoint, ".js") {
			jsEndpoints, _ := e.jsAnalyzer.ExtractEndpoints(endpoint)
			for _, jsEp := range jsEndpoints {
				fullURL := e.normalizeEndpoint(jsEp, parsedURL)
				if fullURL != "" && !contains(result.Endpoints, fullURL) {
					result.Endpoints = append(result.Endpoints, fullURL)
				}
			}
		}
	}

	// Phase 4: Fuzz parameters
	for _, endpoint := range endpoints {
		fuzzResults, _ := e.paramFuzzer.FuzzParameters(endpoint, e.httpClient)
		for _, fr := range fuzzResults {
			point := InjectionPoint{
				URL:       endpoint,
				Parameter: fr.Parameter,
				Type:      InjectionTypeQuery,
				Context:   ReflectionContext(fr.Context),
			}
			result.InjectionPoints = append(result.InjectionPoints, point)
		}
	}

	// Phase 5: Test header reflection
	for _, endpoint := range endpoints {
		reflectedHeaders, _ := e.testHeaderReflectionForURL(endpoint)
		result.ReflectedHeaders = append(result.ReflectedHeaders, reflectedHeaders...)
	}

	// Phase 6: Build injection points from forms
	formPoints := e.buildInjectionPoints(result.Forms)
	result.InjectionPoints = append(result.InjectionPoints, formPoints...)

	// Phase 7: Prioritize targets
	result.InjectionPoints = e.prioritizeTargets(result.InjectionPoints)

	return result, nil
}

// crawlSite crawls the target site
func (e *DiscoveryEngine) crawlSite(baseURL string) ([]string, []Form, error) {
	return e.crawler.Crawl(baseURL)
}

// parseRobotsTxt parses robots.txt
func (e *DiscoveryEngine) parseRobotsTxt(baseURL string) ([]string, error) {
	return e.crawler.ParseRobotsTxt(baseURL)
}

// analyzeJavaScript analyzes JavaScript files
func (e *DiscoveryEngine) analyzeJavaScript(jsURL string) ([]string, error) {
	return e.jsAnalyzer.ExtractEndpoints(jsURL)
}

// fuzzParameters fuzzes URL parameters
func (e *DiscoveryEngine) fuzzParameters(endpoint string) ([]FuzzResult, error) {
	return e.paramFuzzer.FuzzParameters(endpoint, e.httpClient)
}

// testHeaderReflectionForURL tests for header reflection
func (e *DiscoveryEngine) testHeaderReflectionForURL(targetURL string) ([]ReflectedHeader, error) {
	var reflected []ReflectedHeader

	headers := []string{
		"User-Agent",
		"Referer",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"Origin",
	}

	for _, header := range headers {
		canary := e.generateHeaderCanary(header)
		result, err := e.testSingleHeader(targetURL, header, canary)
		if err != nil {
			continue
		}
		if result != nil {
			reflected = append(reflected, *result)
		}
	}

	return reflected, nil
}

// generateHeaderCanary generates a canary for header testing
func (e *DiscoveryEngine) generateHeaderCanary(headerName string) string {
	return fmt.Sprintf("neuroxss_%s_%d", strings.ToLower(headerName), time.Now().UnixNano())
}

// testSingleHeader tests a single header for reflection
func (e *DiscoveryEngine) testSingleHeader(targetURL, headerName, canary string) (*ReflectedHeader, error) {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set(headerName, canary)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read response body
	body := make([]byte, 64*1024) // Read up to 64KB
	n, _ := resp.Body.Read(body)
	bodyStr := string(body[:n])

	// Check if canary is reflected
	if strings.Contains(bodyStr, canary) {
		return &ReflectedHeader{
			HeaderName:  headerName,
			ReflectedIn: "body",
			CanaryValue: canary,
		}, nil
	}

	return nil, nil
}

// testHeaderReflection tests all headers
func (e *DiscoveryEngine) testHeaderReflection(targetURL string) ([]ReflectedHeader, error) {
	return e.testHeaderReflectionForURL(targetURL)
}

// buildInjectionPoints builds injection points from forms
func (e *DiscoveryEngine) buildInjectionPoints(forms []Form) []InjectionPoint {
	var points []InjectionPoint

	for _, form := range forms {
		for _, field := range form.Fields {
			point := InjectionPoint{
				URL:       form.Action,
				Parameter: field.Name,
				Method:    form.Method,
				Type:      InjectionTypeBody,
			}
			if form.Method == "GET" {
				point.Type = InjectionTypeQuery
			}
			points = append(points, point)
		}
	}

	return points
}

// buildInjectionPointsFromHeaders builds injection points from headers
func (e *DiscoveryEngine) buildInjectionPointsFromHeaders(headers []ReflectedHeader, targetURL string) []InjectionPoint {
	var points []InjectionPoint

	for _, h := range headers {
		point := InjectionPoint{
			URL:       targetURL,
			Parameter: h.HeaderName,
			Type:      InjectionTypeHeader,
		}
		points = append(points, point)
	}

	return points
}

// prioritizeTargets sorts injection points by priority
func (e *DiscoveryEngine) prioritizeTargets(points []InjectionPoint) []InjectionPoint {
	for i := range points {
		points[i].Priority = e.calculatePriority(points[i])
	}

	sort.Slice(points, func(i, j int) bool {
		return points[i].Priority > points[j].Priority
	})

	return points
}

// calculatePriority calculates priority for an injection point
func (e *DiscoveryEngine) calculatePriority(point InjectionPoint) int {
	priority := 0

	// Higher priority for reflected parameters
	if point.ReflectionData != nil && point.ReflectionData.Reflected {
		priority += 50
	}

	// Higher priority for parameters in script context
	if point.Context == ContextJavaScript {
		priority += 30
	}

	// Higher priority for common XSS parameter names
	commonNames := []string{"q", "search", "query", "s", "keyword", "term", "name", "title", "msg", "message", "comment", "text", "input", "data", "value", "content", "url", "redirect", "return", "next", "callback"}
	for _, name := range commonNames {
		if strings.EqualFold(point.Parameter, name) {
			priority += 20
			break
		}
	}

	// Higher priority for GET parameters
	if point.Type == InjectionTypeQuery {
		priority += 10
	}

	return priority
}

// normalizeEndpoint normalizes an endpoint URL
func (e *DiscoveryEngine) normalizeEndpoint(endpoint string, baseURL *url.URL) string {
	if endpoint == "" {
		return ""
	}

	// Handle relative URLs
	if strings.HasPrefix(endpoint, "/") {
		return baseURL.Scheme + "://" + baseURL.Host + endpoint
	}

	// Handle protocol-relative URLs
	if strings.HasPrefix(endpoint, "//") {
		return baseURL.Scheme + ":" + endpoint
	}

	// Return as-is if already absolute
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}

	return ""
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// FrameworkDetector detects web frameworks
type FrameworkDetector struct {
	signatures []Signature
}

// NewFrameworkDetector creates a new framework detector
func NewFrameworkDetector() *FrameworkDetector {
	return &FrameworkDetector{}
}

// initializeSignatures initializes detection signatures
func (d *FrameworkDetector) initializeSignatures() {
	d.signatures = []Signature{
		{Pattern: regexp.MustCompile(`angular@([0-9.]+)`), Name: "Angular", Category: "Framework"},
		{Pattern: regexp.MustCompile(`react\.production\.min\.js`), Name: "React", Category: "Framework"},
		{Pattern: regexp.MustCompile(`vue\.min\.js`), Name: "Vue.js", Category: "Framework"},
		{Pattern: regexp.MustCompile(`jquery-([0-9.]+)\.`), Name: "jQuery", Category: "Library"},
		{Pattern: regexp.MustCompile(`bootstrap[.-]([0-9.]+)\.`), Name: "Bootstrap", Category: "CSS"},
		{Pattern: regexp.MustCompile(`wp-content/themes`), Name: "WordPress", Category: "CMS"},
		{Pattern: regexp.MustCompile(`wp-content/plugins`), Name: "WordPress", Category: "CMS"},
		{Pattern: regexp.MustCompile(`WordPress ([0-9.]+)`), Name: "WordPress", Category: "CMS"},
		{Pattern: regexp.MustCompile(`Joomla! ([0-9.]+)`), Name: "Joomla", Category: "CMS"},
		{Pattern: regexp.MustCompile(`X-Generator: Drupal`), Name: "Drupal", Category: "CMS"},
		{Pattern: regexp.MustCompile(`X-Powered-By: PHP`), Name: "PHP", Category: "Language"},
		{Pattern: regexp.MustCompile(`X-Powered-By: Phusion Passenger`), Name: "Passenger", Category: "Server"},
		{Pattern: regexp.MustCompile(`Microsoft-IIS/([0-9.]+)`), Name: "IIS", Category: "Server"},
		{Pattern: regexp.MustCompile(`ASP.NET_SessionId`), Name: "ASP.NET", Category: "Framework"},
		{Pattern: regexp.MustCompile(`data-react-helmet`), Name: "React Helmet", Category: "Library"},
	}
}

// Detect detects technologies in HTML content
func (d *FrameworkDetector) Detect(html string) []Technology {
	var technologies []Technology
	seen := make(map[string]bool)

	for _, sig := range d.signatures {
		matches := sig.Pattern.FindStringSubmatch(html)
		if len(matches) > 0 {
			if !seen[sig.Name] {
				tech := Technology{
					Name:     sig.Name,
					Category: sig.Category,
				}
				if len(matches) > 1 {
					tech.Version = matches[1]
				}
				technologies = append(technologies, tech)
				seen[sig.Name] = true
			}
		}
	}

	return technologies
}
