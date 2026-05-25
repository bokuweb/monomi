use monomi_ast::{analyze_js, ArgShape};

#[test]
fn parses_basic_program() {
    let src = r#"
        const fs = require('fs');
        fs.unlinkSync(__filename);
        // require.cache[mod] = null;   // in a comment — must be flagged as such
        const evil = "process.env.AWS_SECRET_ACCESS_KEY";
    "#;
    let a = analyze_js(src, Some("index.js"));
    assert!(!a.parse_errors);

    // require('fs')
    assert_eq!(a.requires.len(), 1);
    assert_eq!(a.requires[0].target.as_deref(), Some("fs"));

    // fs.unlinkSync(__filename)
    let unlink = a
        .calls
        .iter()
        .find(|c| c.callee_name.as_deref() == Some("fs.unlinkSync"))
        .expect("unlinkSync call");
    assert_eq!(unlink.args.len(), 1);
    assert!(matches!(unlink.args[0], ArgShape::Ident(ref n) if n == "__filename"));

    // The `require.cache[mod] = null` inside the comment must NOT
    // appear as a member access — it's not code.
    assert!(
        !a.member_accesses.iter().any(|m| m.path.starts_with("require.cache")),
        "{:?}",
        a.member_accesses
    );

    // String literal byte position should be flagged.
    let lit_pos = src.find("process.env.AWS").unwrap();
    assert!(a.is_in_string_literal(lit_pos));
    assert!(!a.is_in_string_literal(unlink.span.0));

    // Comment span should cover the cache mutation text.
    let comment_pos = src.find("require.cache[mod]").unwrap();
    assert!(a.is_in_comment(comment_pos));
}

#[test]
fn resolves_computed_member_access() {
    let src = r#"
        delete require.cache[modulePath];
        require.cache[modulePath] = null;
    "#;
    let a = analyze_js(src, Some("x.js"));
    let dyn_hits: Vec<_> = a
        .member_accesses
        .iter()
        .filter(|m| m.path == "require.cache[?]" && m.computed_dynamic)
        .collect();
    assert_eq!(dyn_hits.len(), 2, "{:?}", a.member_accesses);
}

#[test]
fn parse_errors_dont_panic() {
    let a = analyze_js("function (((", Some("broken.js"));
    assert!(a.parse_errors);
    // We still return *something* — rules can decide whether to
    // bail.
}
