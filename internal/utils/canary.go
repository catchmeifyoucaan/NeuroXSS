// Package utils provides utility functions for NeuroXSS
package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// GenerateCanary creates a unique canary string for XSS verification
func GenerateCanary() string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to a simple random string using timestamp
		return fmt.Sprintf("neuro_xss_%d", time.Now().UnixNano())
	}
	return "neuro_xss_" + hex.EncodeToString(bytes)
}

// GenerateCanaryWithPrefix creates a canary with a custom prefix
func GenerateCanaryWithPrefix(prefix string) string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	}
	return prefix + "_" + hex.EncodeToString(bytes)
}
