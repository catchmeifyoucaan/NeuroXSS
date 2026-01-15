package advanced

import (
	"sync"
	"time"
)

// GraphQLSchemaCache caches GraphQL schema information
type GraphQLSchemaCache struct {
	cache map[string]*GraphQLSchema
	mu    sync.RWMutex
	ttl   time.Duration
}

// GraphQLSchema represents a cached GraphQL schema
type GraphQLSchema struct {
	Types      []string
	Queries    []string
	Mutations  []string
	CachedAt   time.Time
}

// NewGraphQLSchemaCache creates a new GraphQL schema cache
func NewGraphQLSchemaCache() *GraphQLSchemaCache {
	return &GraphQLSchemaCache{
		cache: make(map[string]*GraphQLSchema),
		ttl:   1 * time.Hour,
	}
}

// Get retrieves a schema from cache
func (c *GraphQLSchemaCache) Get(endpoint string) (*GraphQLSchema, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	schema, ok := c.cache[endpoint]
	if !ok {
		return nil, false
	}

	if time.Since(schema.CachedAt) > c.ttl {
		return nil, false
	}

	return schema, true
}

// Set stores a schema in cache
func (c *GraphQLSchemaCache) Set(endpoint string, schema *GraphQLSchema) {
	c.mu.Lock()
	defer c.mu.Unlock()

	schema.CachedAt = time.Now()
	c.cache[endpoint] = schema
}

// JSONPEndpointCache caches known JSONP endpoints
type JSONPEndpointCache struct {
	endpoints map[string][]string
	mu        sync.RWMutex
}

// NewJSONPEndpointCache creates a new JSONP endpoint cache
func NewJSONPEndpointCache() *JSONPEndpointCache {
	cache := &JSONPEndpointCache{
		endpoints: make(map[string][]string),
	}

	// Pre-populate with known JSONP endpoints
	cache.endpoints["google.com"] = []string{
		"https://www.google.com/complete/search?callback=",
		"https://accounts.google.com/o/oauth2/iframerpc?callback=",
	}
	cache.endpoints["facebook.com"] = []string{
		"https://www.facebook.com/plugins/like/confirm?callback=",
	}
	cache.endpoints["twitter.com"] = []string{
		"https://api.twitter.com/1/urls/count.json?callback=",
	}

	return cache
}

// GetForDomain returns known JSONP endpoints for a domain
func (c *JSONPEndpointCache) GetForDomain(domain string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.endpoints[domain]
}

// Add adds a new JSONP endpoint
func (c *JSONPEndpointCache) Add(domain, endpoint string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.endpoints[domain] = append(c.endpoints[domain], endpoint)
}

// FrameworkVersionCache caches detected framework versions
type FrameworkVersionCache struct {
	versions map[string]map[string]string
	mu       sync.RWMutex
}

// NewFrameworkVersionCache creates a new framework version cache
func NewFrameworkVersionCache() *FrameworkVersionCache {
	return &FrameworkVersionCache{
		versions: make(map[string]map[string]string),
	}
}

// Get retrieves framework versions for a URL
func (c *FrameworkVersionCache) Get(url string) (map[string]string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	versions, ok := c.versions[url]
	return versions, ok
}

// Set stores framework versions for a URL
func (c *FrameworkVersionCache) Set(url string, versions map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.versions[url] = versions
}
