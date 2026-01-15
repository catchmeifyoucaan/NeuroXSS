package core

import (
	"fmt"
)

// BrowserError represents browser automation errors
type BrowserError struct {
	Message string
	Cause   error
}

func (e *BrowserError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("browser error: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("browser error: %s", e.Message)
}

func (e *BrowserError) Unwrap() error {
	return e.Cause
}

// NetworkError represents network-related errors
type NetworkError struct {
	Message string
	URL     string
	Cause   error
}

func (e *NetworkError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("network error: %s for %s: %v", e.Message, e.URL, e.Cause)
	}
	return fmt.Sprintf("network error: %s for %s", e.Message, e.URL)
}

func (e *NetworkError) Unwrap() error {
	return e.Cause
}

// TimeoutError represents timeout errors
type TimeoutError struct {
	Operation string
	Duration  string
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("timeout error: %s exceeded %s", e.Operation, e.Duration)
}

// HookInjectionError represents errors during Ghost Hook injection
type HookInjectionError struct {
	Message string
	Cause   error
}

func (e *HookInjectionError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("hook injection error: %s: %v", e.Message, e.Cause)
	}
	return fmt.Sprintf("hook injection error: %s", e.Message)
}

func (e *HookInjectionError) Unwrap() error {
	return e.Cause
}

// isBrowserError checks if an error is browser-related
func isBrowserError(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*BrowserError)
	return ok
}

// isNetworkError checks if an error is network-related
func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*NetworkError)
	return ok
}
