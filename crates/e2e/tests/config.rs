//! End-to-end checks for `.ic-assets.json5` handling against the legacy
//! dfx 0.32.0 `assetstorage` canister: per-asset headers, `cache.max_age`,
//! `enable_aliasing`, and the `security_policy` CSP preset are all applied, and
//! the config file itself is never uploaded as an asset.

use e2e::{get_asset_properties, http_fetch, icp_cmd, list_assets, setup_project, LocalNetwork};

#[test]
fn config_applies_properties_headers_and_aliasing() {
    let tmp = setup_project("tests/fixture/config");
    let project = tmp.path();
    let _network = LocalNetwork::start(project);

    icp_cmd(project).arg("deploy").assert().success();

    // The `.ic-assets.json5` file is configuration, not an asset.
    let assets = list_assets(project);
    assert!(
        !assets.iter().any(|a| a.key == "/.ic-assets.json5"),
        "the config file must not be uploaded as an asset; got: {assets:#?}",
    );
    assert!(
        assets.iter().any(|a| a.key == "/index.html"),
        "expected /index.html in asset list; got: {assets:#?}",
    );

    // index.html resolves both rules: max_age 600 + aliasing from the *.html
    // rule, plus the standard security policy + custom header from **/*.
    let props = get_asset_properties(project, "/index.html");
    assert_eq!(props.max_age, Some(600), "max_age from cache config");
    assert_eq!(props.is_aliased, Some(true), "enable_aliasing from config");

    let headers = props.headers.expect("index.html should have headers");
    let has = |name: &str| headers.iter().any(|(k, _)| k.eq_ignore_ascii_case(name));
    assert!(
        headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("X-Custom") && v == "yes"),
        "custom header from config missing; got: {headers:#?}",
    );
    assert!(
        has("Content-Security-Policy"),
        "standard security policy CSP header missing; got: {headers:#?}",
    );

    // style.css gets only the **/* rule: custom header + CSP, but no max_age.
    let css_props = get_asset_properties(project, "/style.css");
    assert_eq!(css_props.max_age, None, "css has no cache rule");
    let css_headers = css_props.headers.unwrap_or_default();
    assert!(
        css_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("X-Custom")),
        "css should still carry the **/* custom header; got: {css_headers:#?}",
    );

    // The certified HTTP response carries the custom header (going through the
    // gateway implicitly validates certification).
    let resp = http_fetch(project, "/index.html");
    assert!(
        resp.status().is_success(),
        "GET /index.html: {}",
        resp.status()
    );
    assert_eq!(
        resp.headers().get("x-custom").and_then(|v| v.to_str().ok()),
        Some("yes"),
        "custom header missing from HTTP response",
    );
}
