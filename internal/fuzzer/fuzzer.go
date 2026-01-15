// Package fuzzer provides DOM fuzzing functionality
package fuzzer

import (
	"time"

	"github.com/go-rod/rod"
)

// Fuzzer handles DOM event fuzzing
type Fuzzer struct {
	browser *rod.Browser
	timeout time.Duration
}

// NewFuzzer creates a new DOM fuzzer
func NewFuzzer(browser *rod.Browser) *Fuzzer {
	return &Fuzzer{
		browser: browser,
		timeout: 5 * time.Second,
	}
}

// FuzzDOM triggers various DOM events to discover event-driven XSS
func (f *Fuzzer) FuzzDOM(page *rod.Page) error {
	// Trigger mouse events
	f.triggerMouseEvents(page)

	// Trigger focus events
	f.triggerFocusEvents(page)

	// Trigger keyboard events
	f.triggerKeyboardEvents(page)

	// Trigger form events
	f.triggerFormEvents(page)

	return nil
}

// triggerMouseEvents triggers mouse-related events
func (f *Fuzzer) triggerMouseEvents(page *rod.Page) {
	script := `
	(function() {
		var events = ['mouseover', 'mouseout', 'mouseenter', 'mouseleave', 'mousemove', 'click', 'dblclick'];
		var elements = document.querySelectorAll('*');
		
		elements.forEach(function(el) {
			events.forEach(function(eventType) {
				try {
					var event = new MouseEvent(eventType, {
						bubbles: true,
						cancelable: true,
						view: window
					});
					el.dispatchEvent(event);
				} catch(e) {}
			});
		});
	})();
	`
	page.Eval(script)
}

// triggerFocusEvents triggers focus-related events
func (f *Fuzzer) triggerFocusEvents(page *rod.Page) {
	script := `
	(function() {
		var focusable = document.querySelectorAll('input, textarea, select, a, button, [tabindex]');
		
		focusable.forEach(function(el) {
			try {
				el.focus();
				el.blur();
			} catch(e) {}
		});
	})();
	`
	page.Eval(script)
}

// triggerKeyboardEvents triggers keyboard events
func (f *Fuzzer) triggerKeyboardEvents(page *rod.Page) {
	script := `
	(function() {
		var events = ['keydown', 'keyup', 'keypress'];
		var activeEl = document.activeElement;
		
		if (activeEl) {
			events.forEach(function(eventType) {
				try {
					var event = new KeyboardEvent(eventType, {
						bubbles: true,
						cancelable: true,
						key: 'a',
						code: 'KeyA'
					});
					activeEl.dispatchEvent(event);
				} catch(e) {}
			});
		}
	})();
	`
	page.Eval(script)
}

// triggerFormEvents triggers form-related events
func (f *Fuzzer) triggerFormEvents(page *rod.Page) {
	script := `
	(function() {
		var inputs = document.querySelectorAll('input, textarea, select');
		
		inputs.forEach(function(el) {
			try {
				// Trigger change event
				var changeEvent = new Event('change', { bubbles: true });
				el.dispatchEvent(changeEvent);
				
				// Trigger input event
				var inputEvent = new Event('input', { bubbles: true });
				el.dispatchEvent(inputEvent);
			} catch(e) {}
		});
		
		// Trigger form submit events (without actually submitting)
		var forms = document.querySelectorAll('form');
		forms.forEach(function(form) {
			try {
				var submitEvent = new Event('submit', { bubbles: true, cancelable: true });
				form.dispatchEvent(submitEvent);
			} catch(e) {}
		});
	})();
	`
	page.Eval(script)
}

// TriggerAnimationEvents triggers animation-related events
func (f *Fuzzer) TriggerAnimationEvents(page *rod.Page) {
	script := `
	(function() {
		var elements = document.querySelectorAll('[style*="animation"], .animated');
		
		elements.forEach(function(el) {
			try {
				var events = ['animationstart', 'animationend', 'animationiteration'];
				events.forEach(function(eventType) {
					var event = new AnimationEvent(eventType, { bubbles: true });
					el.dispatchEvent(event);
				});
			} catch(e) {}
		});
	})();
	`
	page.Eval(script)
}

// TriggerTransitionEvents triggers CSS transition events
func (f *Fuzzer) TriggerTransitionEvents(page *rod.Page) {
	script := `
	(function() {
		var elements = document.querySelectorAll('[style*="transition"]');
		
		elements.forEach(function(el) {
			try {
				var events = ['transitionstart', 'transitionend', 'transitioncancel'];
				events.forEach(function(eventType) {
					var event = new TransitionEvent(eventType, { bubbles: true });
					el.dispatchEvent(event);
				});
			} catch(e) {}
		});
	})();
	`
	page.Eval(script)
}

// TriggerLoadEvents triggers load-related events on media elements
func (f *Fuzzer) TriggerLoadEvents(page *rod.Page) {
	script := `
	(function() {
		var mediaElements = document.querySelectorAll('img, video, audio, iframe, script, link');
		
		mediaElements.forEach(function(el) {
			try {
				// Trigger error event (common XSS vector)
				var errorEvent = new Event('error', { bubbles: false });
				el.dispatchEvent(errorEvent);
				
				// Trigger load event
				var loadEvent = new Event('load', { bubbles: false });
				el.dispatchEvent(loadEvent);
			} catch(e) {}
		});
	})();
	`
	page.Eval(script)
}
