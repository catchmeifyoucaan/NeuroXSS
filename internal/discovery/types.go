// Package discovery provides attack surface discovery functionality
package discovery

import (
	"regexp"
	"time"
)

// InjectionPoint represents a potential injection point
type InjectionPoint struct {
	URL            string            `json:"url"`
	Parameter      string            `json:"parameter"`
	Method         string            `json:"method"`
	Type           InjectionType     `json:"type"`
	Context        ReflectionContext `json:"context"`
	Priority       int               `json:"priority"`
	ReflectionData *ReflectionData   `json:"reflection_data,omitempty"`
}

// InjectionType represents the type of injection point
type InjectionType int

const (
	InjectionTypeQuery InjectionType = iota
	InjectionTypeBody
	InjectionTypeHeader
	InjectionTypeCookie
	InjectionTypeJSON
	InjectionTypeFragment
)

// ReflectionContext represents where input is reflected
type ReflectionContext int

const (
	ContextUnknown ReflectionContext = iota
	ContextHTML
	ContextJavaScript
	ContextAttribute
	ContextURL
	ContextJSON
	ContextCSS
)

// ReflectionData holds information about reflection
type ReflectionData struct {
	Reflected    bool   `json:"reflected"`
	Canary       string `json:"canary"`
	Before       string `json:"before"`
	After        string `json:"after"`
	InTag        bool   `json:"in_tag"`
	InAttribute  bool   `json:"in_attribute"`
	InScript     bool   `json:"in_script"`
}

// FormField represents a form field
type FormField struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Value    string `json:"value,omitempty"`
	Required bool   `json:"required"`
}

// Form represents an HTML form
type Form struct {
	Action  string      `json:"action"`
	Method  string      `json:"method"`
	Fields  []FormField `json:"fields"`
	Enctype string      `json:"enctype,omitempty"`
}

// Technology represents a detected technology
type Technology struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	Category string `json:"category"`
}

// Signature represents a framework detection signature
type Signature struct {
	Pattern  *regexp.Regexp
	Name     string
	Category string
}

// ReflectedHeader represents a header that was reflected
type ReflectedHeader struct {
	HeaderName    string `json:"header_name"`
	ReflectedIn   string `json:"reflected_in"`
	CanaryValue   string `json:"canary_value"`
}

// DiscoveryResult holds the results of discovery
type DiscoveryResult struct {
	Endpoints        []string          `json:"endpoints"`
	InjectionPoints  []InjectionPoint  `json:"injection_points"`
	Forms            []Form            `json:"forms"`
	Technologies     []Technology      `json:"technologies"`
	ReflectedHeaders []ReflectedHeader `json:"reflected_headers"`
	Timestamp        time.Time         `json:"timestamp"`
}

// CrawlConfig configures the crawler
type CrawlConfig struct {
	MaxDepth       int
	MaxPages       int
	RespectRobots  bool
	FollowExternal bool
	Timeout        time.Duration
}

// DefaultCrawlConfig returns default crawler configuration
func DefaultCrawlConfig() CrawlConfig {
	return CrawlConfig{
		MaxDepth:       3,
		MaxPages:       100,
		RespectRobots:  true,
		FollowExternal: false,
		Timeout:        30 * time.Second,
	}
}

// queueItem represents an item in the crawl queue
type queueItem struct {
	URL   string
	Depth int
}
