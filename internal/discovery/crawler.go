package discovery

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// Crawler handles web crawling for attack surface discovery
type Crawler struct {
	config     CrawlConfig
	browser    *rod.Browser
	visited    map[string]bool
	visitedMu  sync.Mutex
	httpClient *http.Client
}

// NewCrawler creates a new crawler
func NewCrawler(config CrawlConfig) *Crawler {
	return &Crawler{
		config:  config,
		visited: make(map[string]bool),
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// SetBrowser sets the browser instance for JavaScript-rendered content
func (c *Crawler) SetBrowser(browser *rod.Browser) {
	c.browser = browser
}

// Crawl performs crawling starting from the base URL
func (c *Crawler) Crawl(baseURL string) ([]string, []Form, error) {
	var endpoints []string
	var forms []Form

	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("crawling failed: %w", err)
	}

	queue := []queueItem{{URL: baseURL, Depth: 0}}

	for len(queue) > 0 && len(endpoints) < c.config.MaxPages {
		// Pop from queue
		item := queue[0]
		queue = queue[1:]

		// Skip if already visited or too deep
		if c.isVisited(item.URL) || item.Depth > c.config.MaxDepth {
			continue
		}
		c.markVisited(item.URL)

		// Fetch page
		page, err := c.fetchPage(item.URL)
		if err != nil {
			continue
		}

		endpoints = append(endpoints, item.URL)

		// Extract links
		links := c.ExtractLinks(page, parsedBase)
		for _, link := range links {
			if !c.isVisited(link) {
				queue = append(queue, queueItem{URL: link, Depth: item.Depth + 1})
			}
		}

		// Extract forms
		pageForms := c.ExtractForms(page, item.URL)
		forms = append(forms, pageForms...)
	}

	return endpoints, forms, nil
}

// fetchPage fetches page content
func (c *Crawler) fetchPage(pageURL string) (string, error) {
	if c.browser != nil {
		// Use browser for JavaScript-rendered content
		page, err := c.browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
		if err != nil {
			return "", err
		}
		defer page.Close()

		err = page.Navigate(pageURL)
		if err != nil {
			return "", err
		}
		page.WaitLoad()

		return page.HTML()
	}

	// Fallback to HTTP client
	resp, err := c.httpClient.Get(pageURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// ExtractLinks extracts all links from HTML content
func (c *Crawler) ExtractLinks(html string, baseURL *url.URL) []string {
	var links []string
	seen := make(map[string]bool)

	// Extract href attributes
	hrefPattern := regexp.MustCompile(`href\s*=\s*["']([^"']+)["']`)
	matches := hrefPattern.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) > 1 {
			link := c.normalizeURL(match[1], baseURL)
			if link != "" && !seen[link] {
				if c.config.FollowExternal || c.isSameHost(link, baseURL) {
					links = append(links, link)
					seen[link] = true
				}
			}
		}
	}

	// Extract src attributes (for JavaScript files)
	srcPattern := regexp.MustCompile(`src\s*=\s*["']([^"']+)["']`)
	srcMatches := srcPattern.FindAllStringSubmatch(html, -1)

	for _, match := range srcMatches {
		if len(match) > 1 && strings.HasSuffix(match[1], ".js") {
			link := c.normalizeURL(match[1], baseURL)
			if link != "" && !seen[link] {
				links = append(links, link)
				seen[link] = true
			}
		}
	}

	return links
}

// ExtractForms extracts all forms from HTML content
func (c *Crawler) ExtractForms(html, pageURL string) []Form {
	var forms []Form

	// Simple form extraction using regex
	formPattern := regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	formMatches := formPattern.FindAllStringSubmatch(html, -1)

	for _, match := range formMatches {
		if len(match) < 2 {
			continue
		}

		formHTML := match[0]
		formContent := match[1]

		form := Form{
			Method: "GET",
		}

		// Extract action
		actionPattern := regexp.MustCompile(`action\s*=\s*["']([^"']*)["']`)
		if actionMatch := actionPattern.FindStringSubmatch(formHTML); len(actionMatch) > 1 {
			form.Action = actionMatch[1]
			if form.Action == "" {
				form.Action = pageURL
			}
		}

		// Extract method
		methodPattern := regexp.MustCompile(`method\s*=\s*["']([^"']*)["']`)
		if methodMatch := methodPattern.FindStringSubmatch(formHTML); len(methodMatch) > 1 {
			form.Method = strings.ToUpper(methodMatch[1])
		}

		// Extract input fields
		inputPattern := regexp.MustCompile(`<input[^>]*>`)
		inputs := inputPattern.FindAllString(formContent, -1)

		for _, input := range inputs {
			field := FormField{Type: "text"}

			// Extract name
			namePattern := regexp.MustCompile(`name\s*=\s*["']([^"']*)["']`)
			if nameMatch := namePattern.FindStringSubmatch(input); len(nameMatch) > 1 {
				field.Name = nameMatch[1]
			}

			// Extract type
			typePattern := regexp.MustCompile(`type\s*=\s*["']([^"']*)["']`)
			if typeMatch := typePattern.FindStringSubmatch(input); len(typeMatch) > 1 {
				field.Type = typeMatch[1]
			}

			// Extract value
			valuePattern := regexp.MustCompile(`value\s*=\s*["']([^"']*)["']`)
			if valueMatch := valuePattern.FindStringSubmatch(input); len(valueMatch) > 1 {
				field.Value = valueMatch[1]
			}

			if field.Name != "" {
				form.Fields = append(form.Fields, field)
			}
		}

		// Extract textarea fields
		textareaPattern := regexp.MustCompile(`<textarea[^>]*name\s*=\s*["']([^"']*)["'][^>]*>`)
		textareas := textareaPattern.FindAllStringSubmatch(formContent, -1)
		for _, ta := range textareas {
			if len(ta) > 1 {
				form.Fields = append(form.Fields, FormField{
					Name: ta[1],
					Type: "textarea",
				})
			}
		}

		if len(form.Fields) > 0 {
			forms = append(forms, form)
		}
	}

	return forms
}

// ParseRobotsTxt parses robots.txt and returns disallowed paths
func (c *Crawler) ParseRobotsTxt(baseURL string) ([]string, error) {
	var disallowed []string

	robotsURL := strings.TrimSuffix(baseURL, "/") + "/robots.txt"

	resp, err := c.httpClient.Get(robotsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to read robots.txt: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return disallowed, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(body), "\n")
	inUserAgent := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.HasPrefix(strings.ToLower(line), "user-agent:") {
			agent := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(line), "user-agent:"))
			inUserAgent = agent == "*" || strings.Contains(agent, "bot")
		}

		if inUserAgent && strings.HasPrefix(strings.ToLower(line), "disallow:") {
			path := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(line), "disallow:"))
			if path != "" {
				disallowed = append(disallowed, path)
			}
		}
	}

	return disallowed, nil
}

// getCommonAdminPaths returns common admin paths to check
func (c *Crawler) getCommonAdminPaths() []string {
	return []string{
		"/admin",
		"/administrator",
		"/admin.php",
		"/wp-admin",
		"/login",
		"/signin",
		"/dashboard",
		"/panel",
		"/cpanel",
		"/manage",
		"/manager",
		"/console",
		"/debug",
		"/api",
		"/api/v1",
		"/graphql",
		"/swagger",
		"/docs",
	}
}

// Helper methods

func (c *Crawler) isVisited(urlStr string) bool {
	c.visitedMu.Lock()
	defer c.visitedMu.Unlock()
	return c.visited[urlStr]
}

func (c *Crawler) markVisited(urlStr string) {
	c.visitedMu.Lock()
	defer c.visitedMu.Unlock()
	c.visited[urlStr] = true
}

func (c *Crawler) normalizeURL(href string, baseURL *url.URL) string {
	if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") {
		return ""
	}

	parsed, err := url.Parse(href)
	if err != nil {
		return ""
	}

	resolved := baseURL.ResolveReference(parsed)
	resolved.Fragment = ""

	return resolved.String()
}

func (c *Crawler) isSameHost(urlStr string, baseURL *url.URL) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return parsed.Host == baseURL.Host
}
