//! NPM022 — hidden / dangerous Unicode in source.
//!
//! Three distinct sub-patterns share the rule ID because they all
//! mean "the code displayed in your editor is not the code that
//! actually executes":
//!
//! 1. **Bidi override controls** (CVE-2021-42574, "Trojan Source") —
//!    `U+202A`/`U+202B`/`U+202C`/`U+202D`/`U+202E`/`U+2066`–`U+2069`
//!    let the source render differently than it tokenizes. Decisive
//!    Critical; near-zero legitimate use in published code.
//!
//! 2. **Zero-width chars** — `U+200B`/`U+200C`/`U+200D`/`U+FEFF`
//!    smuggled into identifiers create dual-token names that look
//!    identical to the original. Defer to Stage 2 (some markdown
//!    libraries legitimately handle these).
//!
//! 3. **Confusable-script identifiers** — best-effort check that
//!    flags identifiers containing characters from multiple Unicode
//!    scripts (e.g. Cyrillic `а` mixed with Latin), the classic
//!    homoglyph trick. Defer to Stage 2.

use monomi_core::{Capability, AnalysisCtx, Category, EcosystemId, EntryKind, Finding, Location, Rule, Severity,};
use once_cell::sync::Lazy;
use regex::Regex;

pub struct HiddenUnicode;

static BIDI_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new("[\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}\u{2066}-\u{2069}]").expect("BIDI_RE")
});

static ZERO_WIDTH_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new("[\u{200B}\u{200C}\u{200D}\u{2060}\u{FEFF}]").expect("ZW_RE"));

impl Rule for HiddenUnicode {
    fn id(&self) -> &'static str {
        "NPM022"
    }

    fn applies_to(&self, eco: EcosystemId) -> bool {
        matches!(
            eco,
            EcosystemId::Npm | EcosystemId::Cargo | EcosystemId::Pypi | EcosystemId::Nuget
        )
    }

    fn evaluate(&self, ctx: &AnalysisCtx<'_>) -> Vec<Finding> {
        let mut out = Vec::new();
        for entry in ctx.entries {
            // Bidi-override and zero-width checks are language-
            // agnostic: any source/text/config file is fair game.
            if !entry.kind.is_scannable_source() {
                continue;
            }
            let Some(text) = entry.text() else { continue };

            if let Some(m) = BIDI_RE.find(text) {
                out.push(Finding {
                    rule_id: "NPM022".into(),
                    severity: Severity::Critical,
                    category: Category::Obfuscation,
                    locations: vec![Location {
                        path: entry.path.clone(),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(format!(
                        "bidi override U+{:04X} at offset {}",
                        m.as_str().chars().next().unwrap() as u32,
                        m.start()
                    )),
                    message: "bidi-override control in source — Trojan Source attack \
                              (rendered code does not match executed code)"
                        .into(),
                    defers_to_stage2: false,
                    capabilities: [Capability::TrojanSource].into_iter().collect(),
                });
            }
            if let Some(m) = ZERO_WIDTH_RE.find(text) {
                out.push(Finding {
                    rule_id: "NPM022".into(),
                    severity: Severity::High,
                    category: Category::Obfuscation,
                    locations: vec![Location {
                        path: entry.path.clone(),
                        line_start: None,
                        line_end: None,
                    }],
                    excerpt: Some(format!(
                        "zero-width U+{:04X} at offset {}",
                        m.as_str().chars().next().unwrap() as u32,
                        m.start()
                    )),
                    message: "zero-width / invisible character in source — may hide \
                              identifiers or smuggle dual-token names"
                        .into(),
                    defers_to_stage2: true,
                    capabilities: [Capability::TrojanSource].into_iter().collect(),
                });
            }

            // Mixed-script identifier check — only run on JS source
            // since arbitrary text files can legitimately contain
            // Cyrillic/Greek alongside Latin.
            if matches!(entry.kind, EntryKind::JsSource) {
                if let Some(ident) = find_mixed_script_identifier(text) {
                    out.push(Finding {
                        rule_id: "NPM022".into(),
                        severity: Severity::High,
                        category: Category::Obfuscation,
                        locations: vec![Location {
                            path: entry.path.clone(),
                            line_start: None,
                            line_end: None,
                        }],
                        excerpt: Some(ident.clone()),
                        message: format!(
                            "mixed-script identifier `{ident}` — possible homoglyph \
                             impersonation (e.g. Cyrillic `а` vs Latin `a`)"
                        ),
                        defers_to_stage2: true,
                        capabilities: [Capability::TrojanSource].into_iter().collect(),
                    });
                }
            }
        }
        out
    }
}

/// Walks the source looking for an identifier token that contains
/// characters from more than one Unicode script. Returns the first
/// such identifier; honest first-pass implementation, not perfect.
fn find_mixed_script_identifier(src: &str) -> Option<String> {
    let mut ident = String::new();
    let mut in_string = false;
    let mut string_quote = '"';
    let mut prev = '\0';
    for c in src.chars() {
        // Skip string literals — they can legitimately mix scripts.
        if in_string {
            if c == string_quote && prev != '\\' {
                in_string = false;
            }
            prev = c;
            continue;
        }
        if c == '"' || c == '\'' || c == '`' {
            in_string = true;
            string_quote = c;
            prev = c;
            if !ident.is_empty() {
                if let Some(hit) = classify_ident(&ident) {
                    return Some(hit);
                }
                ident.clear();
            }
            continue;
        }
        if is_ident_continue(c) {
            ident.push(c);
        } else {
            if !ident.is_empty() {
                if let Some(hit) = classify_ident(&ident) {
                    return Some(hit);
                }
                ident.clear();
            }
        }
        prev = c;
    }
    classify_ident(&ident)
}

fn is_ident_continue(c: char) -> bool {
    c == '_' || c == '$' || c.is_alphanumeric()
}

fn classify_ident(ident: &str) -> Option<String> {
    if ident.is_empty() || ident.is_ascii() {
        return None;
    }
    let mut latin = false;
    let mut non_latin = false;
    for c in ident.chars() {
        if c.is_ascii_alphabetic() {
            latin = true;
        } else if !c.is_alphanumeric() {
            continue;
        } else if !c.is_ascii() {
            non_latin = true;
        }
    }
    if latin && non_latin {
        Some(ident.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_cyrillic_a_in_ascii_ident() {
        // 2nd "a" is Cyrillic U+0430.
        let id = "Bаnk"; // Latin B, Cyrillic а, ASCII nk
        assert_eq!(classify_ident(id), Some(id.to_string()));
    }

    #[test]
    fn pure_ascii_or_pure_non_latin_does_not_match() {
        assert_eq!(classify_ident("hello"), None);
        assert_eq!(classify_ident("こんにちは"), None);
    }
}
