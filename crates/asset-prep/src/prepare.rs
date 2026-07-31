//! The single, canister-agnostic preparation path: a `dist/` directory in,
//! prepared assets + final redirect rules out — the exact state a finished sync
//! leaves on the canister, minus the canister diff/upload.
//!
//! Preparation runs in **two phases**, because they cost wildly different
//! amounts:
//!
//! 1. [`plan_project`] — scan, parse `_redirects`/`_headers`, synthesise rules,
//!    load each asset and hash its *uncompressed* bytes. Cheap: a read and a
//!    SHA-256 per file.
//! 2. [`PlannedAsset::encode`] — run the caller's [`Compressors`], chunk, hash.
//!    Expensive: with the canonical registry, brotli q11 dominates a deploy's
//!    local cost.
//!
//! Splitting them lets `sync-core` encode only the assets the canister doesn't
//! already hold (see its `sync()`); [`prepare_project`] is the eager wrapper
//! that runs both phases over everything, which is what the `state-hash-cli`
//! verifier needs — it has no canister to compare against and must do the full
//! work. Both build the [`state_hash::Manifest`] from the *same* output here, so
//! the canister's stored-state hash and the verifier's `dist/`-derived hash
//! agree by construction.

use sha2::{Digest, Sha256};
use std::path::Path;

use wire_types::{Encoding, RedirectRule, RulePattern};

use crate::compressors::Compressors;
use crate::content::{Content, is_compressible};
use crate::headers::{self, HEADERS_FILENAME, HeaderRule};
use crate::redirects::{self, REDIRECTS_FILENAME};
use crate::scan::{self, AssetSource};
use crate::{html_handling, not_found};

/// Maximum bytes per uploaded chunk — the boundary the canister stores content
/// at. **Part of the frozen state-hash contract**: per-chunk hashes depend on
/// it, so a verifier must use a `state-hash-cli` built with this same value.
/// Stays safely under the canister's ~2 MB ingress message limit.
pub const MAX_CHUNK_SIZE: usize = 1_900_000;

/// One chunk of a prepared encoding: its length and SHA-256 (folded into the
/// state hash for multi-chunk encodings) plus the bytes themselves (consumed by
/// `sync-core`'s upload; ignored by the verifier).
#[derive(Clone, Debug)]
pub struct PreparedChunk {
    pub len: u32,
    pub sha256: [u8; 32],
    pub data: Vec<u8>,
}

/// One prepared encoding of an asset: the whole-encoding hash, total length, and
/// the chunks it slices into (always ≥ 1; an empty encoding is one zero-byte
/// chunk, matching how the canister stores it).
#[derive(Clone, Debug)]
pub struct PreparedEncoding {
    pub encoding: Encoding,
    pub sha256: [u8; 32],
    pub content_len: u64,
    pub chunks: Vec<PreparedChunk>,
}

/// One prepared asset, shaped like the canister's stored `AssetMeta`: its key,
/// `content_type` (after any `_headers` override), the resolved per-asset
/// response headers, and the kept encodings.
#[derive(Clone, Debug)]
pub struct PreparedAsset {
    pub key: String,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
    pub encodings: Vec<PreparedEncoding>,
}

/// Everything a sync will install on the canister, derived purely from `dist/`:
/// every asset (including the injected branded 404 when applicable) and the
/// final redirect rules in match order, with 3xx rules' `_headers` already
/// inlined — exactly the canonical stored form.
#[derive(Clone, Debug, Default)]
pub struct PreparedProject {
    pub assets: Vec<PreparedAsset>,
    pub redirect_rules: Vec<RedirectRule>,
}

/// One asset discovered in `dist/`: loaded, its media type and headers
/// resolved, and its **uncompressed** bytes hashed — but not yet encoded.
///
/// Everything here is cheap to derive, and it is enough to decide whether an
/// asset needs encoding at all: a caller that finds the canister already holds
/// this exact content (same `content_type`, same `identity_sha256`, same
/// encoding set) can skip [`encode`](PlannedAsset::encode) entirely, because
/// every compressed encoding is a pure function of the identity bytes for a
/// given set of compressors (see [`Compressors`]'s purity contract, and
/// [`crate::canary`] for how a caller detects that the set changed).
#[derive(Clone, Debug)]
pub struct PlannedAsset {
    pub key: String,
    /// The stored media type, after any `_headers` `Content-Type` override.
    pub content_type: String,
    /// Per-asset response headers resolved from `_headers`.
    pub headers: Vec<(String, String)>,
    /// SHA-256 of the uncompressed bytes — the identity encoding's
    /// whole-encoding hash, and the identity the sync diff matches on.
    pub identity_sha256: [u8; 32],
    /// Length of the uncompressed bytes.
    pub identity_len: u64,
    /// Loaded bytes + resolved media type, consumed by `encode`.
    content: Content,
    /// The compressors to run over it; fixed by the plan.
    compressors: Compressors,
}

impl PlannedAsset {
    /// The encodings preparation will *attempt* for this asset: Identity, plus
    /// one per compressor the caller set — but only for compressible media types.
    /// Whether a compressed encoding is actually kept is decided by the size
    /// check in [`encode`](PlannedAsset::encode).
    pub fn attempted_encodings(&self) -> Vec<Encoding> {
        let mut encodings = vec![Encoding::Identity];
        if is_compressible(&self.content.media_type) {
            encodings.extend(self.compressors.present().map(|(encoding, _)| encoding));
        }
        encodings
    }

    /// Whether any encoding will be stored as more than one chunk. Used to
    /// reject oversized 4xx error-page targets (see `sync-core`).
    ///
    /// Exact without encoding anything: a compressed encoding is only kept when
    /// it is *smaller* than identity, so identity is the longest kept encoding
    /// and its length alone decides this.
    pub fn is_multichunk(&self) -> bool {
        self.identity_len > MAX_CHUNK_SIZE as u64
    }

    /// The expensive half of preparation: run each attempted encoding's
    /// compressor, keep a compressed result only when it actually saves bytes,
    /// then chunk and hash every kept encoding.
    pub fn encode(self) -> Result<PreparedAsset, String> {
        let mut encodings = Vec::new();
        for encoding in self.attempted_encodings() {
            // Identity is stored as-is; every other attempted encoding has a
            // compressor, since `attempted_encodings` derives the set from them.
            let data = match self.compressors.for_encoding(encoding) {
                Some(compress) => compress(&self.content.data)?,
                None => self.content.data.clone(),
            };
            // Identity is always kept. A compressed encoding is only kept if it
            // actually saves bytes vs identity — otherwise storing it just wastes
            // canister space. This also keeps identity the longest kept encoding,
            // which `is_multichunk` relies on, whatever a caller's compressor
            // returns.
            if !encoding.is_identity() && data.len() >= self.content.data.len() {
                continue;
            }
            encodings.push(prepare_encoding(encoding, data));
        }

        Ok(PreparedAsset {
            key: self.key,
            content_type: self.content_type,
            headers: self.headers,
            encodings,
        })
    }
}

/// The cheap half of [`prepare_project`]: every asset located, loaded and
/// identified, plus the final redirect rules — with no encoding done yet.
#[derive(Clone, Debug, Default)]
pub struct ProjectPlan {
    pub assets: Vec<PlannedAsset>,
    pub redirect_rules: Vec<RedirectRule>,
}

/// Prepares a project's `dist/` directory in full: [`plan_project`] followed by
/// [`PlannedAsset::encode`] on every asset.
///
/// This is the canister-agnostic front half of a sync — no canister diff and no
/// uploads. `sync-core` uses the two phases separately so it can skip encoding
/// assets the canister already holds; the `state-hash-cli` verifier calls this,
/// since reproducing the manifest requires every encoding.
pub fn prepare_project(dir: &str, compressors: &Compressors) -> Result<PreparedProject, String> {
    let ProjectPlan {
        assets,
        redirect_rules,
    } = plan_project(dir, compressors)?;

    let assets = assets
        .into_iter()
        .map(PlannedAsset::encode)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(PreparedProject {
        assets,
        redirect_rules,
    })
}

/// Scans assets, parses `_redirects` and `_headers`, synthesizes the
/// html-handling and 404 rules, then loads each asset's content, resolves its
/// media type and headers, and hashes its uncompressed bytes.
///
/// Everything except encoding. Errors carry file paths / line numbers so
/// misconfigurations are caught before any canister round-trip — and before any
/// compression work.
pub fn plan_project(dir: &str, compressors: &Compressors) -> Result<ProjectPlan, String> {
    let sources = scan::scan(dir)?;
    let user_rules = load_redirect_rules(dir)?;

    // Asset-key set drives html-handling synthesis. The branded 404, when
    // injected, is added before synthesis so it picks up the same `/404`
    // clean-URL rules a user-supplied `404.html` would. (See `not_found`.)
    let mut asset_keys: Vec<String> = sources.iter().map(|s| s.key.clone()).collect();
    let not_found_plan = not_found::plan(&asset_keys, &user_rules);
    if not_found_plan.inject_branded_asset {
        asset_keys.push(not_found::ROOT_404_KEY.to_string());
    }

    // Synthesised auto-trailing-slash rules first, then the user's `_redirects`,
    // then the lowest-priority 404 catch-all. Order is semantic (first match
    // wins) — see the long note in `sync-core`'s `sync()`.
    let mut project_rules = html_handling::synthesize(&asset_keys);
    project_rules.extend(user_rules);
    if not_found_plan.append_catchall {
        project_rules.push(not_found::catchall_rule());
    }

    let header_rules = load_header_rules(dir)?;

    let mut assets = Vec::with_capacity(sources.len() + 1);
    for source in sources {
        assets.push(plan_asset(source, &header_rules, compressors)?);
    }
    if not_found_plan.inject_branded_asset {
        assets.push(plan_branded_404(&header_rules, compressors)?);
    }

    // 3xx rules synthesize their own response (no target asset to inherit
    // headers from), so inline `_headers` into them now — the canonical stored
    // form a re-sync diffs cleanly against.
    let redirect_rules = resolve_3xx_rule_headers(&project_rules, &header_rules);

    Ok(ProjectPlan {
        assets,
        redirect_rules,
    })
}

fn plan_asset(
    source: AssetSource,
    header_rules: &[HeaderRule],
    compressors: &Compressors,
) -> Result<PlannedAsset, String> {
    let mut content = Content::load(&source.path)?;
    // Apply a per-glob `Content-Type` override from `_headers` before deciding
    // encoders or the stored media type (e.g. a `.did` declared `text/plain`
    // then picks up gzip and the correct certified `Content-Type`).
    if let Some(override_mime) = headers::content_type_for(&source.key, header_rules) {
        content.media_type = override_mime;
    }
    Ok(plan_content_asset(
        source.key,
        content,
        header_rules,
        compressors,
    ))
}

/// Builds the in-memory branded `/404.html` injected when a project ships no root
/// `404.html`. Treated like any other HTML asset, but its bytes come from a
/// constant and `_headers` content-type overrides are not applied (it is always
/// `text/html`); its per-asset headers are still resolved from `_headers`.
fn plan_branded_404(
    header_rules: &[HeaderRule],
    compressors: &Compressors,
) -> Result<PlannedAsset, String> {
    let content = Content {
        data: not_found::DEFAULT_404_HTML.as_bytes().to_vec(),
        media_type: mime_guess::from_path(not_found::ROOT_404_KEY)
            .first()
            .unwrap_or(mime::TEXT_HTML),
    };
    Ok(plan_content_asset(
        not_found::ROOT_404_KEY.to_string(),
        content,
        header_rules,
        compressors,
    ))
}

/// Shared tail of the planning phase: hash the uncompressed bytes and resolve
/// the asset's stored media type and headers.
fn plan_content_asset(
    key: String,
    content: Content,
    header_rules: &[HeaderRule],
    compressors: &Compressors,
) -> PlannedAsset {
    PlannedAsset {
        content_type: content.media_type.to_string(),
        headers: headers::resolve(&key, header_rules),
        identity_sha256: Sha256::digest(&content.data).into(),
        identity_len: content.data.len() as u64,
        key,
        content,
        compressors: compressors.clone(),
    }
}

/// Slices encoded bytes into ≤ `MAX_CHUNK_SIZE` chunks and hashes each — the
/// per-chunk `(len, sha256)` the canister stores for multi-chunk 206
/// certification — plus the whole-encoding hash. An empty encoding still gets
/// one zero-byte chunk, exactly as the upload path does.
fn prepare_encoding(encoding: Encoding, data: Vec<u8>) -> PreparedEncoding {
    let sha256: [u8; 32] = Sha256::digest(&data).into();
    let content_len = data.len() as u64;

    let raw_chunks: Vec<&[u8]> = if data.is_empty() {
        vec![&[][..]]
    } else {
        data.chunks(MAX_CHUNK_SIZE).collect()
    };
    let chunks = raw_chunks
        .into_iter()
        .map(|chunk| PreparedChunk {
            len: chunk.len() as u32,
            sha256: Sha256::digest(chunk).into(),
            data: chunk.to_vec(),
        })
        .collect();

    PreparedEncoding {
        encoding,
        sha256,
        content_len,
        chunks,
    }
}

fn load_redirect_rules(dir: &str) -> Result<Vec<RedirectRule>, String> {
    let path = Path::new(dir).join(REDIRECTS_FILENAME);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    redirects::parse(&content).map_err(|e| format!("{}: {e}", path.display()))
}

/// Reads and parses `_headers` from `dir`, if present. A missing file means "no
/// rules"; parse errors carry the file path and line number.
fn load_header_rules(dir: &str) -> Result<Vec<HeaderRule>, String> {
    let path = Path::new(dir).join(HEADERS_FILENAME);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    headers::parse(&content).map_err(|e| format!("{}: {e}", path.display()))
}

fn is_3xx(status: u16) -> bool {
    (300..400).contains(&status)
}

/// Path-like key for running the header resolver against a redirect rule's
/// `from`: Exact yields the path; Subtree yields the prefix.
fn redirect_pattern_to_key(pattern: &RulePattern) -> String {
    match pattern {
        RulePattern::Exact(p) => p.clone(),
        RulePattern::Subtree(prefix) => prefix.clone(),
    }
}

/// Inlines `_headers` into every 3xx rule by resolving them against the rule's
/// `from` pattern. 200/4xx rules borrow headers from their target asset and pass
/// through untouched.
fn resolve_3xx_rule_headers(
    rules: &[RedirectRule],
    header_rules: &[HeaderRule],
) -> Vec<RedirectRule> {
    rules
        .iter()
        .map(|rule| {
            let mut rule = rule.clone();
            if is_3xx(rule.status) {
                let key = redirect_pattern_to_key(&rule.from);
                rule.headers = headers::resolve(&key, header_rules);
            }
            rule
        })
        .collect()
}

/// Maps a [`PreparedProject`] to the canonical [`state_hash::Manifest`]: the
/// shared view the canister also builds from its stored state.
pub fn manifest(prepared: &PreparedProject) -> state_hash::Manifest {
    let assets = prepared
        .assets
        .iter()
        .map(|asset| {
            let encodings = asset
                .encodings
                .iter()
                .map(|enc| {
                    if enc.chunks.len() > 1 {
                        state_hash::ManifestEncoding {
                            encoding: enc.encoding,
                            sha256: enc.sha256,
                            content_len: enc.content_len,
                            num_chunks: enc.chunks.len() as u32,
                            chunks: enc
                                .chunks
                                .iter()
                                .map(|c| state_hash::ManifestChunk {
                                    len: c.len,
                                    sha256: c.sha256,
                                })
                                .collect(),
                        }
                    } else {
                        state_hash::ManifestEncoding::single_chunk(
                            enc.encoding,
                            enc.sha256,
                            enc.content_len,
                        )
                    }
                })
                .collect();
            state_hash::ManifestAsset {
                key: asset.key.clone(),
                content_type: asset.content_type.clone(),
                headers: asset.headers.clone(),
                encodings,
            }
        })
        .collect();

    state_hash::Manifest {
        assets,
        redirect_rules: prepared.redirect_rules.clone(),
    }
}

/// Convenience for the verifier: prepare `dir` with `compressors` and return the
/// resulting canonical state hash — the value to compare against a canister's
/// `state_hash()`.
///
/// The registry is an input because it changes the stored state, and therefore
/// the hash: a canister deployed with [`Compressors::none`] holds only identity
/// encodings and hashes differently from the same `dist/` deployed with
/// compression on — and a canister deployed with compressors of its own matches
/// neither. A verifier who doesn't know which was used can compute the ones they
/// can reproduce and see whether any matches.
pub fn state_hash_for_dir(dir: &str, compressors: &Compressors) -> Result<[u8; 32], String> {
    let prepared = prepare_project(dir, compressors)?;
    Ok(manifest(&prepared).digest())
}

// Preparation tests need compressors to prepare *with*, and the canonical
// registry is the one whose output the assertions can name. `--no-default-features`
// therefore compiles the crate but skips these.
#[cfg(all(test, feature = "canonical-compressors"))]
mod tests {
    use super::*;
    use crate::compressors::CompressFn;
    use std::fs;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn write(dir: &TempDir, rel: &str, bytes: &[u8]) {
        let path = dir.path().join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
    }

    fn dir_str(d: &TempDir) -> String {
        d.path().to_str().unwrap().to_string()
    }

    #[test]
    fn empty_dir_injects_branded_404_and_catchall() {
        let dir = tempfile::tempdir().unwrap();
        let prepared = prepare_project(&dir_str(&dir), &Compressors::canonical()).unwrap();
        // A project shipping no root `404.html` gets the branded default injected
        // plus the `/* -> /404.html 404` catch-all (see `not_found`).
        assert_eq!(prepared.assets.len(), 1);
        assert_eq!(prepared.assets[0].key, not_found::ROOT_404_KEY);
        assert!(
            prepared
                .redirect_rules
                .iter()
                .any(|r| r.status == 404 && r.to == not_found::ROOT_404_KEY)
        );
    }

    #[test]
    fn ships_own_404_is_not_overridden() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir, "404.html", b"<h1>my 404</h1>");
        let prepared = prepare_project(&dir_str(&dir), &Compressors::canonical()).unwrap();
        // The user's own /404.html is used; no branded duplicate.
        let count_404 = prepared
            .assets
            .iter()
            .filter(|a| a.key == not_found::ROOT_404_KEY)
            .count();
        assert_eq!(count_404, 1);
        assert!(
            prepared.assets[0]
                .encodings
                .iter()
                .any(|e| e.encoding == Encoding::Identity)
        );
    }

    #[test]
    fn single_html_asset_is_prepared_with_identity_encoding() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir, "index.html", b"<!DOCTYPE html><html></html>");
        let prepared = prepare_project(&dir_str(&dir), &Compressors::canonical()).unwrap();

        let index = prepared
            .assets
            .iter()
            .find(|a| a.key == "/index.html")
            .expect("index.html prepared");
        assert_eq!(index.content_type, "text/html");
        assert!(
            index
                .encodings
                .iter()
                .any(|e| e.encoding == Encoding::Identity)
        );
        // Each kept encoding is at least one chunk.
        for enc in &index.encodings {
            assert!(!enc.chunks.is_empty());
            let total: u64 = enc.chunks.iter().map(|c| c.len as u64).sum();
            assert_eq!(enc.content_len, total);
        }
    }

    #[test]
    fn incompressible_asset_keeps_only_identity() {
        let dir = tempfile::tempdir().unwrap();
        // A tiny PNG-typed file: not compressible, so identity only.
        write(&dir, "logo.png", &[0u8; 16]);
        let prepared = prepare_project(&dir_str(&dir), &Compressors::canonical()).unwrap();
        let logo = prepared
            .assets
            .iter()
            .find(|a| a.key == "/logo.png")
            .unwrap();
        assert_eq!(logo.encodings.len(), 1);
        assert_eq!(logo.encodings[0].encoding, Encoding::Identity);
    }

    #[test]
    fn manifest_round_trips_through_digest() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir, "index.html", b"<!DOCTYPE html><h1>hi</h1>");
        write(&dir, "style.css", b"body{color:red}");
        let prepared = prepare_project(&dir_str(&dir), &Compressors::canonical()).unwrap();
        // The convenience helper equals manifest(&prepared).digest().
        assert_eq!(
            state_hash_for_dir(&dir_str(&dir), &Compressors::canonical()).unwrap(),
            manifest(&prepared).digest()
        );
    }

    #[test]
    fn empty_encoding_is_one_zero_byte_chunk() {
        let enc = prepare_encoding(Encoding::Identity, Vec::new());
        assert_eq!(enc.chunks.len(), 1);
        assert_eq!(enc.chunks[0].len, 0);
        assert_eq!(enc.content_len, 0);
    }

    // --- two-phase planning ---

    /// `PlannedAsset::is_multichunk` must agree with the encoded truth, since
    /// `sync-core` trusts it for assets it never encodes. `.bin` keeps this fast:
    /// octet-stream is incompressible, so no compressor runs on the big file.
    #[test]
    fn planned_multichunk_matches_encoded_chunk_count() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir, "big.bin", &vec![0u8; MAX_CHUNK_SIZE + 1]);
        write(&dir, "small.bin", &vec![0u8; MAX_CHUNK_SIZE]);

        let plan = plan_project(&dir_str(&dir), &Compressors::canonical()).unwrap();
        for planned in plan.assets {
            let expected = planned.is_multichunk();
            let prepared = planned.encode().unwrap();
            assert_eq!(
                expected,
                prepared.encodings.iter().any(|e| e.chunks.len() > 1),
                "multichunk mismatch for {}",
                prepared.key
            );
        }
    }

    // --- compressor registry ---

    #[test]
    fn empty_registry_keeps_only_identity() {
        let dir = tempfile::tempdir().unwrap();
        // Repetitive enough that both compressors would beat identity, so the
        // absent encodings are a decision and not a size check.
        write(&dir, "index.html", "<p>hello</p>".repeat(200).as_bytes());

        let prepared = prepare_project(&dir_str(&dir), &Compressors::none()).unwrap();
        for asset in &prepared.assets {
            assert_eq!(
                asset
                    .encodings
                    .iter()
                    .map(|e| e.encoding)
                    .collect::<Vec<_>>(),
                vec![Encoding::Identity],
                "{} should keep only identity",
                asset.key
            );
        }

        let compressed = prepare_project(&dir_str(&dir), &Compressors::canonical()).unwrap();
        assert!(
            compressed.assets.iter().any(|a| a.encodings.len() > 1),
            "the same project with compression on must keep more encodings"
        );
    }

    /// Identity content is identical whatever the registry — it only decides what
    /// is stored *alongside* it. This is what makes changing compressors converge
    /// without re-uploading unchanged uncompressed bytes.
    #[test]
    fn registry_does_not_change_identity_content() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir, "index.html", b"<!DOCTYPE html><h1>hi</h1>");

        let identity_of = |compressors: &Compressors| {
            let prepared = prepare_project(&dir_str(&dir), compressors).unwrap();
            prepared
                .assets
                .iter()
                .map(|a| {
                    let identity = a
                        .encodings
                        .iter()
                        .find(|e| e.encoding == Encoding::Identity)
                        .expect("identity is always kept");
                    (a.key.clone(), identity.sha256, identity.content_len)
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            identity_of(&Compressors::canonical()),
            identity_of(&Compressors::none())
        );
    }

    /// The registry is part of what the state hash covers, which is why
    /// `state-hash-cli` can only speak for the canonical one: a canister prepared
    /// with different compressors is a different hash, not a near-miss.
    #[test]
    fn registry_changes_the_state_hash() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir, "index.html", "<p>hello</p>".repeat(200).as_bytes());
        assert_ne!(
            state_hash_for_dir(&dir_str(&dir), &Compressors::canonical()).unwrap(),
            state_hash_for_dir(&dir_str(&dir), &Compressors::none()).unwrap()
        );
    }

    /// The planning phase must resolve exactly the identity, media type and
    /// headers the eager path produces — `sync-core` diffs on those without
    /// encoding.
    #[test]
    fn plan_matches_prepare_without_encoding() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir, "index.html", b"<!DOCTYPE html><h1>hi</h1>");
        write(&dir, "logo.png", &[0u8; 16]);
        write(&dir, "_headers", b"/*\n  X-Frame-Options: DENY\n");

        let plan = plan_project(&dir_str(&dir), &Compressors::canonical()).unwrap();
        let prepared = prepare_project(&dir_str(&dir), &Compressors::canonical()).unwrap();
        assert_eq!(plan.redirect_rules, prepared.redirect_rules);
        assert_eq!(plan.assets.len(), prepared.assets.len());

        for (planned, prepared) in plan.assets.iter().zip(&prepared.assets) {
            assert_eq!(planned.key, prepared.key);
            assert_eq!(planned.content_type, prepared.content_type);
            assert_eq!(planned.headers, prepared.headers);

            let identity = prepared
                .encodings
                .iter()
                .find(|e| e.encoding == Encoding::Identity)
                .expect("identity is always kept");
            assert_eq!(planned.identity_sha256, identity.sha256);
            assert_eq!(planned.identity_len, identity.content_len);

            let compressible = is_compressible(&planned.content_type.parse().unwrap());
            assert_eq!(
                planned.attempted_encodings(),
                if compressible {
                    vec![Encoding::Identity, Encoding::Gzip, Encoding::Brotli]
                } else {
                    vec![Encoding::Identity]
                },
                "attempted set for {}",
                planned.key
            );
        }
    }

    /// The attempted set is the intersection of "this media type is worth
    /// compressing" and "the caller set this compressor" — the rule `sync-core`
    /// diffs the canister's stored encoding set against.
    #[test]
    fn attempted_encodings_follow_the_registry() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir, "index.html", b"<h1>hi</h1>");
        write(&dir, "logo.png", &[0u8; 16]);

        let canonical = Compressors::canonical();
        let cases = [
            (
                Compressors::canonical(),
                vec![Encoding::Identity, Encoding::Gzip, Encoding::Brotli],
            ),
            (
                Compressors {
                    gzip: None,
                    br: canonical.br.clone(),
                },
                vec![Encoding::Identity, Encoding::Brotli],
            ),
            (
                Compressors {
                    gzip: canonical.gzip.clone(),
                    br: None,
                },
                vec![Encoding::Identity, Encoding::Gzip],
            ),
            (Compressors::none(), vec![Encoding::Identity]),
        ];

        for (compressors, expected_for_html) in cases {
            let plan = plan_project(&dir_str(&dir), &compressors).unwrap();
            let attempted = |key: &str| {
                plan.assets
                    .iter()
                    .find(|a| a.key == key)
                    .unwrap()
                    .attempted_encodings()
            };
            assert_eq!(
                attempted("/index.html"),
                expected_for_html,
                "html under {compressors:?}"
            );
            // An incompressible media type is offered to no compressor, whatever
            // the registry holds.
            assert_eq!(
                attempted("/logo.png"),
                vec![Encoding::Identity],
                "png under {compressors:?}"
            );
        }
    }

    fn encodings_of(prepared: &PreparedProject, key: &str) -> Vec<Encoding> {
        let mut encs: Vec<Encoding> = prepared
            .assets
            .iter()
            .find(|a| a.key == key)
            .unwrap_or_else(|| panic!("asset {key} prepared"))
            .encodings
            .iter()
            .map(|e| e.encoding)
            .collect();
        encs.sort_by_key(|e| *e as u8);
        encs
    }

    #[test]
    fn incompressible_text_skips_gzip() {
        // All 256 byte values: gzip's framing exceeds any savings, so the
        // keep-if-smaller guard drops gzip (identity is always kept).
        let dir = tempfile::tempdir().unwrap();
        write(&dir, "blob.txt", &(0u8..=255u8).collect::<Vec<u8>>());
        let prepared = prepare_project(&dir_str(&dir), &Compressors::canonical()).unwrap();
        let encs = encodings_of(&prepared, "/blob.txt");
        assert!(encs.contains(&Encoding::Identity), "identity always kept");
        assert!(
            !encs.contains(&Encoding::Gzip),
            "gzip dropped when not smaller"
        );
    }

    #[test]
    fn compressible_keeps_identity_gzip_brotli() {
        // Highly repetitive CSS shrinks under both compressors, so all three are
        // kept.
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir,
            "style.css",
            "body { color: red; }\n".repeat(500).as_bytes(),
        );
        let prepared = prepare_project(&dir_str(&dir), &Compressors::canonical()).unwrap();
        assert_eq!(
            encodings_of(&prepared, "/style.css"),
            vec![Encoding::Identity, Encoding::Gzip, Encoding::Brotli]
        );
    }

    /// A caller's compressor is subject to the same keep-if-smaller rule as the
    /// canonical ones. This is what keeps identity the longest kept encoding —
    /// the invariant `is_multichunk` reads off `identity_len` alone — no matter
    /// what an injected function returns.
    #[test]
    fn caller_compressor_that_grows_content_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir, "index.html", b"<h1>hi</h1>");

        let bloat: CompressFn = Arc::new(|bytes: &[u8]| {
            let mut out = bytes.to_vec();
            out.extend_from_slice(&[0u8; 64]);
            Ok(out)
        });
        let prepared = prepare_project(
            &dir_str(&dir),
            &Compressors {
                gzip: Some(bloat),
                br: None,
            },
        )
        .unwrap();

        for asset in &prepared.assets {
            assert_eq!(
                asset
                    .encodings
                    .iter()
                    .map(|e| e.encoding)
                    .collect::<Vec<_>>(),
                vec![Encoding::Identity],
                "{} should keep only identity",
                asset.key
            );
        }
    }

    /// A failing compressor fails the preparation rather than silently storing
    /// fewer encodings than the plan attempted.
    #[test]
    fn caller_compressor_error_fails_preparation() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir, "index.html", b"<h1>hi</h1>");

        let err = prepare_project(
            &dir_str(&dir),
            &Compressors {
                gzip: Some(Arc::new(|_: &[u8]| Err("no thanks".to_string()))),
                br: None,
            },
        )
        .unwrap_err();
        assert_eq!(err, "no thanks");
    }

    #[test]
    fn prepare_resolves_3xx_rule_headers_from_headers_file() {
        // A 3xx rule synthesizes its own response, so `_headers` matching its
        // `from` are inlined onto the rule. 200/4xx rules borrow from their target
        // asset and stay header-less.
        let dir = tempfile::tempdir().unwrap();
        write(&dir, "index.html", b"<h1>hi</h1>");
        write(
            &dir,
            "_redirects",
            b"/old /new 301\n/page /target.html 200\n",
        );
        write(&dir, "_headers", b"/*\n  X-Robots-Tag: noindex\n");
        let prepared = prepare_project(&dir_str(&dir), &Compressors::canonical()).unwrap();

        let r301 = prepared
            .redirect_rules
            .iter()
            .find(|r| r.status == 301)
            .expect("301 rule");
        assert_eq!(
            r301.headers,
            vec![("X-Robots-Tag".to_string(), "noindex".to_string())],
            "3xx rule carries resolved _headers"
        );

        let r200 = prepared
            .redirect_rules
            .iter()
            .find(|r| r.status == 200)
            .expect("200 rule");
        assert!(
            r200.headers.is_empty(),
            "200 rewrite inherits from target, no inlined headers"
        );
    }

    #[test]
    fn headers_content_type_override_drives_encoder_and_type() {
        // A `.did` file has no mime_guess entry (→ octet-stream, identity only).
        // A `_headers` `Content-Type: text/plain` override makes it compressible.
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir,
            "ic.did",
            b"service : { greet : (text) -> (text); }\n"
                .repeat(100)
                .as_ref(),
        );

        let without = prepare_project(&dir_str(&dir), &Compressors::canonical()).unwrap();
        let did = without.assets.iter().find(|a| a.key == "/ic.did").unwrap();
        assert_eq!(did.content_type, "application/octet-stream");
        assert_eq!(encodings_of(&without, "/ic.did"), vec![Encoding::Identity]);

        write(
            &dir,
            "_headers",
            b"/*.did\n  Content-Type: text/plain; charset=utf-8\n",
        );
        let with = prepare_project(&dir_str(&dir), &Compressors::canonical()).unwrap();
        let did = with.assets.iter().find(|a| a.key == "/ic.did").unwrap();
        assert_eq!(did.content_type, "text/plain; charset=utf-8");
        assert!(encodings_of(&with, "/ic.did").contains(&Encoding::Gzip));
    }
}
