//! Build-script half of embedded certified assets.
//!
//! ```ignore
//! // build.rs
//! fn main() {
//!     embedded_certified_assets_build::embed("dist").unwrap();
//! }
//! ```
//!
//! [`embed`] does all the expensive and all the policy work at compile time:
//!
//! 1. **Prepare** `dist/` with `asset-prep` and the canonical compressors — the
//!    same path the synced canister uses, so `_headers`, `_redirects`,
//!    html-handling (`/about` → `about.html`), and the 404 convention all behave
//!    identically.
//! 2. **Resolve routes.** The synced canister scans `_redirects` rules in
//!    declaration order at request time; the HTTP gateway's v2 verification
//!    instead demands "exact path, else the most specific wildcard". Rules have
//!    path-independent responses (no `:splat`), so for each certified location
//!    the declaration-order winner can be computed up front. The resulting table
//!    is served with a plain exact/longest-prefix lookup and agrees with both.
//! 3. **Hash.** Every (route, encoding) response is assembled with its final
//!    headers and its response hash computed here. The runtime only inserts the
//!    precomputed leaves into the certification tree.
//! 4. **Generate** `$OUT_DIR/embedded_certified_assets.rs` defining
//!    `static ASSETS: embedded_certified_assets::Assets`, with every body
//!    `include_bytes!`'d from a content-addressed file in `$OUT_DIR`.

use asset_prep::{Compressors, PreparedAsset, PreparedProject};
use ic_http_certification::{
    CERTIFICATE_EXPRESSION_HEADER_NAME, DefaultCelBuilder, DefaultResponseCertification,
    HttpResponse, StatusCode, response_hash,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use wire_types::{RedirectRule, RulePattern};

/// Prepare `dist_dir` and write the generated code into `$OUT_DIR`. Call from
/// `build.rs`; `dist_dir` is relative to the crate's manifest directory.
pub fn embed(dist_dir: impl AsRef<Path>) -> Result<(), String> {
    let dist_dir = dist_dir.as_ref();
    println!("cargo::rerun-if-changed={}", dist_dir.display());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").map_err(|e| format!("OUT_DIR: {e}"))?);
    let code = generate(dist_dir, &out_dir)?;
    std::fs::write(out_dir.join("embedded_certified_assets.rs"), code)
        .map_err(|e| format!("writing generated code: {e}"))
}

/// Like [`embed`] but with explicit paths, returning the generated source.
/// Body files are written under `out_dir/embedded-assets/`.
pub fn generate(dist_dir: &Path, out_dir: &Path) -> Result<String, String> {
    let dist = dist_dir
        .to_str()
        .ok_or_else(|| format!("non-UTF-8 dist path {}", dist_dir.display()))?;
    let project = asset_prep::prepare_project(dist, &Compressors::canonical())?;
    let routes = resolve_routes(&project)?;
    emit(&routes, &out_dir.join("embedded-assets"))
}

// ---------------------------------------------------------------------------
// Route resolution
// ---------------------------------------------------------------------------

/// A certified location and the (path-independent) response served there.
struct ResolvedRoute<'a> {
    path: String,
    wildcard: bool,
    target: Target<'a>,
}

enum Target<'a> {
    /// Serve an asset's body (any status: a plain asset is 200, a rewrite rule
    /// 200, a custom error page 404/410). `extra` are rule-supplied headers.
    Asset {
        asset: &'a PreparedAsset,
        status: u16,
        extra: &'a [(String, String)],
    },
    /// A 3xx redirect: empty body, `location` header.
    Redirect {
        status: u16,
        location: &'a str,
        extra: &'a [(String, String)],
    },
    /// Last-resort root wildcard when nothing else covers `/`.
    BuiltinNotFound,
}

fn resolve_routes(project: &PreparedProject) -> Result<Vec<ResolvedRoute<'_>>, String> {
    let assets: HashMap<&str, &PreparedAsset> =
        project.assets.iter().map(|a| (a.key.as_str(), a)).collect();

    // A rule whose body-borrowing target doesn't exist is inert (the synced
    // canister skips it too), so drop it before choosing winners.
    let live: Vec<&RedirectRule> = project
        .redirect_rules
        .iter()
        .filter(|r| r.status / 100 == 3 || assets.contains_key(r.to.as_str()))
        .collect();

    let mut routes = vec![];

    // 1. Assets always win at their own path.
    for asset in &project.assets {
        routes.push(ResolvedRoute {
            path: asset.key.clone(),
            wildcard: false,
            target: Target::Asset {
                asset,
                status: 200,
                extra: &[],
            },
        });
    }

    // 2. Every location some rule names, with the declaration-order winner for
    //    requests whose most specific certified location it is.
    //    - exact `p`: first rule that matches `p` itself;
    //    - wildcard `q`: first subtree rule whose prefix contains `q` (exact
    //      rules under `q` get their own exact location above).
    let mut seen = std::collections::HashSet::new();
    for rule in &live {
        let (path, wildcard) = match &rule.from {
            RulePattern::Exact(p) => (p.clone(), false),
            RulePattern::Subtree(q) => (q.clone(), true),
        };
        if !seen.insert((path.clone(), wildcard))
            || (!wildcard && assets.contains_key(path.as_str()))
        {
            continue;
        }
        let winner = live
            .iter()
            .find(|r| match &r.from {
                RulePattern::Exact(p) => !wildcard && *p == path,
                RulePattern::Subtree(prefix) => path.starts_with(prefix.as_str()),
            })
            .expect("the rule itself matches its own location");
        routes.push(ResolvedRoute {
            path,
            wildcard,
            target: rule_target(winner, &assets),
        });
    }

    // 3. Guarantee every request has a certified answer.
    if !routes.iter().any(|r| r.wildcard && r.path == "/") {
        routes.push(ResolvedRoute {
            path: "/".into(),
            wildcard: true,
            target: Target::BuiltinNotFound,
        });
    }
    Ok(routes)
}

fn rule_target<'a>(
    rule: &'a RedirectRule,
    assets: &HashMap<&str, &'a PreparedAsset>,
) -> Target<'a> {
    if rule.status / 100 == 3 {
        Target::Redirect {
            status: rule.status,
            location: &rule.to,
            extra: &rule.headers,
        }
    } else {
        Target::Asset {
            asset: assets[rule.to.as_str()],
            status: rule.status,
            extra: &rule.headers,
        }
    }
}

// ---------------------------------------------------------------------------
// Response assembly + hashing + codegen
// ---------------------------------------------------------------------------

/// One fully-formed response, ready to hash and emit.
struct Built {
    encoding: &'static str,
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn build_responses(target: &Target) -> Result<Vec<Built>, String> {
    let lower = |h: &[(String, String)]| -> Vec<(String, String)> {
        h.iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
            .collect()
    };
    match target {
        Target::Asset {
            asset,
            status,
            extra,
        } => {
            // Server preference order: br, gzip, identity.
            let mut encodings: Vec<_> = asset.encodings.iter().collect();
            encodings.sort_by_key(|e| match e.encoding.label() {
                "br" => 0,
                "gzip" => 1,
                _ => 2,
            });
            let multi = encodings.len() > 1;
            encodings
                .into_iter()
                .map(|enc| {
                    // No streaming in this PoC: a body must fit one query response.
                    if enc.chunks.len() != 1 {
                        return Err(format!(
                            "{} ({}) is {} bytes; bodies over {} bytes need streaming, \
                             which embedded assets don't support",
                            asset.key,
                            enc.encoding.label(),
                            enc.content_len,
                            asset_prep::MAX_CHUNK_SIZE
                        ));
                    }
                    let mut headers =
                        vec![("content-type".to_string(), asset.content_type.clone())];
                    if let Some(ce) = enc.encoding.header_name() {
                        headers.push(("content-encoding".into(), ce.into()));
                    }
                    if multi {
                        headers.push(("vary".into(), "accept-encoding".into()));
                    }
                    headers.extend(
                        lower(&asset.headers)
                            .into_iter()
                            .filter(|(k, _)| k != "content-type"),
                    );
                    headers.extend(lower(extra));
                    Ok(Built {
                        encoding: enc.encoding.label(),
                        status: *status,
                        headers,
                        body: enc.chunks[0].data.clone(),
                    })
                })
                .collect()
        }
        Target::Redirect {
            status,
            location,
            extra,
        } => {
            let mut headers = vec![
                ("content-type".to_string(), "text/plain".to_string()),
                ("location".to_string(), location.to_string()),
            ];
            headers.extend(lower(extra));
            Ok(vec![Built {
                encoding: "identity",
                status: *status,
                headers,
                body: vec![],
            }])
        }
        Target::BuiltinNotFound => Ok(vec![Built {
            encoding: "identity",
            status: 404,
            headers: vec![("content-type".into(), "text/plain".into())],
            body: b"not found".to_vec(),
        }]),
    }
}

fn emit(routes: &[ResolvedRoute], bodies_dir: &Path) -> Result<String, String> {
    std::fs::create_dir_all(bodies_dir).map_err(|e| format!("{}: {e}", bodies_dir.display()))?;

    // One CEL expression for every response: response-only, all headers certified.
    let cel = DefaultCelBuilder::response_only_certification()
        .with_response_certification(DefaultResponseCertification::response_header_exclusions(
            vec![],
        ))
        .build();
    let cel_str = cel.to_string();
    let cel_expr_hash: [u8; 32] = Sha256::digest(cel_str.as_bytes()).into();

    // Content-addressed body statics, deduplicated across routes.
    let mut bodies: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut routes_src = String::new();

    for route in routes {
        let mut responses_src = String::new();
        for mut built in build_responses(&route.target)? {
            built.headers.push((
                CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(),
                cel_str.clone(),
            ));

            let body_hash: [u8; 32] = Sha256::digest(&built.body).into();
            let body_hex = hex(&body_hash);
            let body_ident = body_hex.to_ascii_uppercase();
            if !bodies.contains_key(&body_hex) {
                let file = bodies_dir.join(&body_hex);
                std::fs::write(&file, &built.body)
                    .map_err(|e| format!("{}: {e}", file.display()))?;
                bodies.insert(body_hex.clone(), file);
            }

            // Hash exactly what the runtime will serve (minus IC-Certificate,
            // which `response_hash` excludes).
            let response = HttpResponse::builder()
                .with_status_code(StatusCode::from_u16(built.status).map_err(|e| e.to_string())?)
                .with_headers(built.headers.clone())
                .build();
            let resp_hash = response_hash(&response, &cel.response, Some(body_hash));

            let encoding = match built.encoding {
                "br" => "Brotli",
                "gzip" => "Gzip",
                _ => "Identity",
            };
            let headers_src: String = built
                .headers
                .iter()
                .map(|(k, v)| format!("({k:?}, {v:?}), "))
                .collect();
            writeln!(
                responses_src,
                "::embedded_certified_assets::Response {{ \
                 encoding: ::embedded_certified_assets::Encoding::{encoding}, \
                 status: {status}, headers: &[{headers_src}], body: B_{body_ident}, \
                 cel_expr_hash: {cel_expr_hash:?}, response_hash: {resp_hash:?} }},",
                status = built.status,
            )
            .unwrap();
        }
        write!(
            routes_src,
            "    ::embedded_certified_assets::Route {{ path: {path:?}, wildcard: {wildcard}, \
             responses: &[\n{responses_src}] }},\n",
            path = route.path,
            wildcard = route.wildcard,
        )
        .unwrap();
    }

    let mut src =
        String::from("// @generated by embedded-certified-assets-build. Do not edit.\n\n");
    for (hex, file) in &bodies {
        let ident = hex.to_ascii_uppercase();
        writeln!(
            src,
            "static B_{ident}: &[u8] = include_bytes!({:?});",
            file.display().to_string()
        )
        .unwrap();
    }
    write!(
        src,
        "\npub static ASSETS: ::embedded_certified_assets::Assets = \
         ::embedded_certified_assets::Assets {{ routes: &[\n{routes_src}] }};\n"
    )
    .unwrap();
    Ok(src)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
