/**
 * Ghost Hook - NeuroXSS Runtime Execution Verification
 * 
 * This script is injected before page scripts execute to monitor
 * dangerous DOM sinks and verify XSS execution.
 * 
 * Monitored Sinks:
 * - innerHTML
 * - outerHTML
 * - document.write
 * - document.writeln
 * - eval
 * - setTimeout (with string)
 * - setInterval (with string)
 * - Function constructor
 * - insertAdjacentHTML
 * - location.href
 * - location.assign
 * - location.replace
 */

(function() {
    'use strict';
    
    // Canary placeholder - replaced at runtime
    var canary = 'CANARY_PLACEHOLDER';
    
    // Store execution evidence
    window.__NEUROXSS_SINK = '';
    window.__NEUROXSS_STACK = '';
    window.__NEUROXSS_TRIGGERED = false;
    
    /**
     * Records XSS execution evidence
     */
    function recordExecution(sink, stackTrace) {
        if (!window.__NEUROXSS_TRIGGERED) {
            window[canary] = 1;
            window.__NEUROXSS_SINK = sink;
            window.__NEUROXSS_STACK = stackTrace || new Error().stack;
            window.__NEUROXSS_TRIGGERED = true;
            
            // Optional: Send beacon for blind XSS
            if (window.__NEUROXSS_CALLBACK) {
                try {
                    navigator.sendBeacon(window.__NEUROXSS_CALLBACK, JSON.stringify({
                        canary: canary,
                        sink: sink,
                        url: window.location.href,
                        timestamp: new Date().toISOString()
                    }));
                } catch(e) {}
            }
        }
    }
    
    /**
     * Checks if content contains the canary
     */
    function containsCanary(content) {
        if (content === null || content === undefined) return false;
        return content.toString().indexOf(canary) !== -1;
    }
    
    // ========================================
    // Monitor innerHTML
    // ========================================
    var originalInnerHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
    if (originalInnerHTML) {
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function(value) {
                if (containsCanary(value)) {
                    recordExecution('innerHTML');
                }
                return originalInnerHTML.set.call(this, value);
            },
            get: originalInnerHTML.get
        });
    }
    
    // ========================================
    // Monitor outerHTML
    // ========================================
    var originalOuterHTML = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
    if (originalOuterHTML && originalOuterHTML.set) {
        Object.defineProperty(Element.prototype, 'outerHTML', {
            set: function(value) {
                if (containsCanary(value)) {
                    recordExecution('outerHTML');
                }
                return originalOuterHTML.set.call(this, value);
            },
            get: originalOuterHTML.get
        });
    }
    
    // ========================================
    // Monitor document.write
    // ========================================
    var originalDocWrite = document.write;
    document.write = function() {
        var content = Array.prototype.join.call(arguments, '');
        if (containsCanary(content)) {
            recordExecution('document.write');
        }
        return originalDocWrite.apply(this, arguments);
    };
    
    // ========================================
    // Monitor document.writeln
    // ========================================
    var originalDocWriteln = document.writeln;
    document.writeln = function() {
        var content = Array.prototype.join.call(arguments, '');
        if (containsCanary(content)) {
            recordExecution('document.writeln');
        }
        return originalDocWriteln.apply(this, arguments);
    };
    
    // ========================================
    // Monitor eval
    // ========================================
    var originalEval = window.eval;
    window.eval = function(code) {
        if (containsCanary(code)) {
            recordExecution('eval');
        }
        return originalEval.apply(this, arguments);
    };
    
    // ========================================
    // Monitor setTimeout with string
    // ========================================
    var originalSetTimeout = window.setTimeout;
    window.setTimeout = function(fn, delay) {
        if (typeof fn === 'string' && containsCanary(fn)) {
            recordExecution('setTimeout');
        }
        return originalSetTimeout.apply(this, arguments);
    };
    
    // ========================================
    // Monitor setInterval with string
    // ========================================
    var originalSetInterval = window.setInterval;
    window.setInterval = function(fn, delay) {
        if (typeof fn === 'string' && containsCanary(fn)) {
            recordExecution('setInterval');
        }
        return originalSetInterval.apply(this, arguments);
    };
    
    // ========================================
    // Monitor Function constructor
    // ========================================
    var originalFunction = window.Function;
    window.Function = function() {
        var args = Array.prototype.slice.call(arguments);
        var body = args[args.length - 1] || '';
        if (containsCanary(body)) {
            recordExecution('Function');
        }
        return originalFunction.apply(this, arguments);
    };
    window.Function.prototype = originalFunction.prototype;
    
    // ========================================
    // Monitor insertAdjacentHTML
    // ========================================
    var originalInsertAdjacentHTML = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function(position, text) {
        if (containsCanary(text)) {
            recordExecution('insertAdjacentHTML');
        }
        return originalInsertAdjacentHTML.apply(this, arguments);
    };
    
    // ========================================
    // Monitor location modifications
    // ========================================
    try {
        var locationDescriptor = Object.getOwnPropertyDescriptor(window, 'location');
        if (locationDescriptor && locationDescriptor.set) {
            var originalLocationSetter = locationDescriptor.set;
            Object.defineProperty(window, 'location', {
                get: locationDescriptor.get,
                set: function(value) {
                    if (containsCanary(value)) {
                        recordExecution('location');
                    }
                    return originalLocationSetter.call(this, value);
                },
                configurable: true
            });
        }
    } catch(e) {
        // Some browsers don't allow modifying location
    }
    
    // ========================================
    // Monitor location.assign
    // ========================================
    var originalLocationAssign = window.location.assign;
    if (originalLocationAssign) {
        window.location.assign = function(url) {
            if (containsCanary(url)) {
                recordExecution('location.assign');
            }
            return originalLocationAssign.apply(this, arguments);
        };
    }
    
    // ========================================
    // Monitor location.replace
    // ========================================
    var originalLocationReplace = window.location.replace;
    if (originalLocationReplace) {
        window.location.replace = function(url) {
            if (containsCanary(url)) {
                recordExecution('location.replace');
            }
            return originalLocationReplace.apply(this, arguments);
        };
    }
    
    // ========================================
    // Monitor DOMParser
    // ========================================
    var OriginalDOMParser = window.DOMParser;
    if (OriginalDOMParser) {
        window.DOMParser = function() {
            var parser = new OriginalDOMParser();
            var originalParseFromString = parser.parseFromString;
            parser.parseFromString = function(str, type) {
                if (containsCanary(str)) {
                    recordExecution('DOMParser.parseFromString');
                }
                return originalParseFromString.apply(this, arguments);
            };
            return parser;
        };
    }
    
    // ========================================
    // Monitor Range.createContextualFragment
    // ========================================
    var originalCreateContextualFragment = Range.prototype.createContextualFragment;
    if (originalCreateContextualFragment) {
        Range.prototype.createContextualFragment = function(html) {
            if (containsCanary(html)) {
                recordExecution('createContextualFragment');
            }
            return originalCreateContextualFragment.apply(this, arguments);
        };
    }
    
    // ========================================
    // Monitor jQuery if present
    // ========================================
    if (window.jQuery || window.$) {
        var $ = window.jQuery || window.$;
        var originalHtml = $.fn.html;
        if (originalHtml) {
            $.fn.html = function(value) {
                if (value !== undefined && containsCanary(value)) {
                    recordExecution('jQuery.html');
                }
                return originalHtml.apply(this, arguments);
            };
        }
        
        var originalAppend = $.fn.append;
        if (originalAppend) {
            $.fn.append = function(value) {
                if (containsCanary(value)) {
                    recordExecution('jQuery.append');
                }
                return originalAppend.apply(this, arguments);
            };
        }
    }
    
    // Log initialization
    console.log('[GhostHook] Initialized - Monitoring ' + canary);
    
})();
