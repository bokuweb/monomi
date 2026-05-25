//! Per-package AST cache.
//!
//! Multiple rules want the AST for the same file in one pipeline
//! run. Parsing isn't free; an `AstCache` keeps each parsed
//! `JsAnalysis` keyed by path so the cost is paid once per scan.

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use monomi_core::AstHandle;

use crate::analysis::{analyze_js, JsAnalysis};

pub struct AstCache {
    inner: Mutex<HashMap<String, Arc<JsAnalysis>>>,
}

impl AstCache {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Get the parsed analysis for `path`. Parses on first call,
    /// returns the cached `Arc` on subsequent ones.
    pub fn get_or_parse(&self, path: &str, source: &str) -> Arc<JsAnalysis> {
        if let Some(hit) = self.inner.lock().unwrap().get(path) {
            return hit.clone();
        }
        let parsed = Arc::new(analyze_js(source, Some(path)));
        self.inner
            .lock()
            .unwrap()
            .insert(path.to_string(), parsed.clone());
        parsed
    }
}

impl Default for AstCache {
    fn default() -> Self {
        Self::new()
    }
}

impl AstHandle for AstCache {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Convenience: downcast an `AstHandle` trait object back to the
/// concrete `AstCache`. Returns `None` if the handle was constructed
/// from a different type (currently we have only one impl, but the
/// indirection is what keeps `monomi-core` parser-free).
pub fn downcast(handle: &dyn AstHandle) -> Option<&AstCache> {
    handle.as_any().downcast_ref::<AstCache>()
}
