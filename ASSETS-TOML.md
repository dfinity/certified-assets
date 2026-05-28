# `assets.toml` Support — v1: Content-Type Overrides

## Goal

Let users declare per-glob `Content-Type` overrides for uploaded assets through an `assets.toml` file. v1 ships **only this one field**; the broader `assets.toml` schema (ignore patterns, encoding overrides, `allow_raw_access`) is sketched in [PROPOSAL-asset-config-refactor.md](PROPOSAL-asset-config-refactor.md) — this plan is the first slice and pins the file format, validation rules, and pipeline integration that subsequent fields will build on.

## Why content-type first

The legacy `.ic-assets.json5` workflow allowed users to set `Content-Type` via the same `headers` block as everything else. That worked structurally — the value flowed through `CreateAssetArguments.headers` and got appended to the asset's response — but it produced a **duplicate** `Content-Type` header (the canister always prepends one derived from `CreateAssetArguments.content_type`, then appends user headers without deduping). Behavior across clients is undefined; in practice the user override is often silently ignored.

`_headers` deliberately rejects `Content-Type` as a header rule for exactly this reason ([assets-sync/src/headers.rs](assets-sync/src/headers.rs)). So content-type needs a different home — one that feeds `CreateAssetArguments.content_type` directly, where the canister's certification machinery picks it up and writes it as the **sole** `Content-Type` of the certified response. That home is `assets.toml`.

This also closes the only blocker preventing the developer-docs `.ic-assets.json5` from being expressible in the new config: all the `**/*.md`, `**/*.did`, `**/*.sh`, and `llms.txt` rules in that file exist solely to plug gaps in `mime_guess::from_path`.

## Design choice: override the plugin's mime_guess step

Today the plugin computes content-type via `mime_guess::from_path(path)` ([assets-sync/src/content.rs:40](assets-sync/src/content.rs#L40)) and stuffs the result into `CreateAssetArguments.content_type`. The canister stores it on the asset and emits exactly one `content-type` header per response ([ic-certified-assets/src/asset.rs:309-310](ic-certified-assets/src/asset.rs#L309-L310)).

`assets.toml` slots in **before** `mime_guess` in the resolution chain:

```
1. assets.toml `[[asset]]` blocks (first matching `content_type` wins)
2. mime_guess::from_path(path)
3. application/octet-stream
```

The result still ends up in `CreateAssetArguments.content_type` and is certified by the canister exactly as today. **No canister-side change. No new candid types. No new cert-tree shape.** Same plugin-side-lowering pattern as `_headers`.

## File format

A TOML file passed to the plugin through the manifest's `files:` field. The plugin contract ([plugin/wit/sync-plugin.wit](plugin/wit/sync-plugin.wit)) already carries a `files: list<file-input>` on `SyncExecInput` — `icp-cli` reads each declared file on the host side and forwards its contents inline. We expect at most one entry, treated as the asset config:

```yaml
# icp.yaml (excerpt)
canisters:
  - name: frontend
    sync:
      steps:
        - type: plugin
          path: ./plugins/assets-sync.wasm
          dirs:
            - dist            # build output: read-only WASI preopen
          files:
            - assets.toml     # host reads this and passes its contents to the plugin
```

`files: []` (or omitted) → no overrides. One entry → that entry's `content` is parsed as the asset config. **Two or more entries → error** with a message asking the user to consolidate, since the plugin has no merge semantics for multiple config files.

The plugin does **not** assert the entry's `name` matches `assets.toml`. The manifest's `files:` field is already the authoritative declaration of which file is the asset config — re-validating the filename inside the plugin would just duplicate that check while preventing legitimate alternative names (e.g., a project that organises its config under `config/frontend-assets.toml`). The standard name `assets.toml` is a convention documented for users and tooling; the plugin trusts the bytes it receives.

```toml
# assets.toml

# Per-glob content-type overrides. First matching block wins.
[[asset]]
match = "/*.md"
content_type = "text/markdown; charset=utf-8"

[[asset]]
match = "/llms.txt"
content_type = "text/plain; charset=utf-8"

[[asset]]
match = "/*.did"
content_type = "text/plain; charset=utf-8"

[[asset]]
match = "/*.sh"
content_type = "text/plain; charset=utf-8"
```

### Fields

| Field | Required | Validation |
|---|---|---|
| `match` | yes | Glob over the asset key. Same dialect as `_headers` post-globs: leading `/`, `*` matches any sequence (including `/` and empty), no `**`, no `:placeholder`. |
| `content_type` | optional in the schema, but a block with no recognised v1 field is a no-op | Parsed via `mime::Mime::from_str` at config-load time. Rejects malformed MIME, empty subtype, CR/LF, and other invalid bytes — same safety guarantee as `_headers` gets from `http::HeaderValue`. |

`content_type` is marked optional in the schema because future `[[asset]]` fields (`ignore`, `encodings`, `allow_raw_access`) will populate the same block standalone. v1 silently ignores blocks with no recognised fields rather than erroring — forward compatibility over strictness.

Unknown top-level or per-block keys are **rejected** at parse time (`#[serde(deny_unknown_fields)]`). Typo protection beats forward compatibility for an unreleased plugin: catching `contetn_type` immediately is more useful than allowing a v2 field to pass through silently. When v2 fields land, the schema is updated atomically with the plugin that supports them.

### Resolution

For each asset key during sync:

1. Walk `[[asset]]` blocks in declaration order.
2. The first block whose `match` matches the key contributes its `content_type` (when set).
3. If no block contributes a `content_type`, fall back to `mime_guess::from_path(path).first()`.
4. Final fallback: `application/octet-stream` (unchanged from today).

**Order is semantic.** A specific block (`match = "/legacy/oldstyle.md"`) must precede a broader one (`match = "/*.md"`) to take effect — Netlify/Cloudflare convention, same as `_redirects` ordering. This is why the schema uses `[[asset]]` (TOML array-of-tables, order-preserving by spec) rather than an inline-table map (where order is parser-dependent).

### Determinism

Identical to the `_headers` determinism guarantee:

- The resolver is a pure function of `(blocks, key)`. Same `assets.toml` + same asset key → same `Option<Mime>` byte-for-byte.
- The canister stores the resolved string in `Asset.content_type` and emits it as the single `content-type` header of the certified response.
- No runtime injection, no hidden defaults beyond `mime_guess` and the `application/octet-stream` fallback (both of which are themselves pure functions of the file path).

## Validation

Rejected at config-load with a TOML span pointing at the offending line:

- TOML syntax errors (from the `toml` crate's error type).
- `[[asset]]` block missing `match`.
- `match` value that fails the `_headers`-style pattern rules: must start with `/`, no `**`, no `:placeholder`.
- `content_type` value that fails `mime::Mime::from_str` — catches CR/LF, missing slash, empty subtype, etc.

A **missing** `assets.toml` is treated as "no overrides" — the feature is purely opt-in. An **empty** `assets.toml` (zero `[[asset]]` blocks) is valid and equivalent to absent.

Parsing aborts at the first malformed block — matches the `_headers`/`_redirects` philosophy of "fix issues one at a time rather than wade through cascading errors."

## Integration in `assets-sync`

- **Parser** (`assets-sync/src/asset_config.rs`). Uses the `toml` crate (already a candidate workspace dep — to be added). Defines `AssetConfig { asset: Vec<AssetBlock> }` and `AssetBlock { match, content_type }` with serde-deserialized fields. Returns errors with the file path and TOML span.
- **Pattern matcher**. Reuses `HeaderPattern` from `headers.rs`. As part of step 1 below, the pattern type is renamed to `KeyPattern` and lifted into a shared module (`assets-sync/src/glob.rs`); `headers.rs` re-exports it as `HeaderPattern` (alias) to keep its API stable. Single matcher, both file formats.
- **Resolver**. `AssetConfig::content_type_for(key: &str) -> Option<mime::Mime>` walks blocks in declaration order, returns the first matching block's `content_type`.
- **Plugin entry point** (`plugin/src/lib.rs`). Threads `input.files` through to `assets_sync::sync::sync(..)`. No filesystem reads for the config — `assets.toml` is **not** in `CONFIG_FILENAMES` and is **not** discovered by `scan.rs`. The config arrives inline on every invocation.
- **Sync integration** (`assets-sync/src/sync.rs`):
  - `sync()` gains a `files: &[(String, String)]` parameter (name + content pairs). It calls `parse_asset_config(files)` once per run, alongside `load_redirect_rules` and `load_header_rules`.
  - `parse_asset_config` validates the entry-count contract (0 → empty config, 1 → parsed, ≥2 → error) and parses the single TOML string.
  - `prepare_asset` applies the override after `Content::load`: if `config.content_type_for(&source.key)` is `Some(mime)`, replace `content.media_type` before the `encoders_for(&media_type)` step. This is important — see "downstream effects" below.
  - The "nothing to commit" short-circuit considers asset-config drift just as it considers `_headers` and `_redirects` drift today: an `assets.toml`-only edit triggers a sync because it can change `CreateAssetArguments.content_type` and therefore the certified response.

### Downstream effects of overriding `media_type`

Applying the override **before** `encoders_for(&media_type)` runs has two intentional consequences:

1. **Compression policy follows the override.** `encoders_for` selects `gzip` for `text/*`, `*/javascript`, and `*/html` ([assets-sync/src/content.rs:81-84](assets-sync/src/content.rs#L81-L84)). A `.did` file overridden to `text/plain` will now be uploaded with a `gzip` encoding alongside `identity` — same as other text files. Without the override it stayed `application/octet-stream` and was identity-only.
2. **Drift detection sees the new type.** `is_already_in_place` and the delete-then-recreate logic in `build_operations` compare `media_type.to_string()` to the canister-stored `content_type` ([assets-sync/src/sync.rs:174](assets-sync/src/sync.rs#L174), [sync.rs:371](assets-sync/src/sync.rs#L371)). Flipping a `.did` file's content-type from `application/octet-stream` to `text/plain` triggers a one-time delete-then-create on the next sync — intentional, because the cert tree's response hash changes when the content-type changes.

Both are correct and what the user wants. Worth noting in the README so the first sync after adopting `assets.toml` isn't surprising.

## Step breakdown

1. **Shared glob module.** Rename `HeaderPattern` to `KeyPattern` and lift it from `headers.rs` to `assets-sync/src/glob.rs`. `headers.rs` re-exports as a type alias for source compatibility. Zero behavior change; pure refactor.
2. **Parser + unit tests** (`asset_config.rs`). Happy path, missing-`match`, bad pattern, bad MIME, multiple blocks, unknown-field forward compat, empty file. Mirrors the test layout in `headers.rs`.
3. **Sync integration.** `load_asset_config` in `sync()`; override application in `prepare_asset`; drift-trigger in the short-circuit. Update mocked-canister tests in `sync.rs` to cover content-type override → recreate, and override-only edit → recreate without content change.
4. **E2E test** (`e2e/tests/assets_toml.rs`). Fixture with `.md` / `.did` / `.sh` / `llms.txt` files and an `assets.toml` matching the developer-docs case. Verifies the canister returns the configured `Content-Type` exactly once, and that flipping a content-type triggers a re-upload (cert tree updates).
5. **Docs.** Short section in top-level `README.md` next to `_headers` / `_redirects`. Brief note in `plugin/README.md` that the first sync after adopting `assets.toml` may recreate assets whose content-type changes — by design.

Each step is independently shippable; together they ship the v1 surface.

## What this plan is *not* for

- **Response headers other than `Content-Type`.** Those go in `_headers`. The split is the whole point of the refactor.
- **A general MIME-type extension table.** No `[content_type.extensions] md = "text/markdown"` shorthand — every override is an explicit `[[asset]]` block. "No implicit rules" is a stated principle: defaults come from `mime_guess`, overrides come from `assets.toml`, nothing in between.
- **Built-in security-policy bundles.** Removed entirely per the broader proposal.

## Parked for follow-up

- **`[[asset]]` block growth.** When `ignore`, `encodings`, `allow_raw_access` land, each new field picks its own composition rule (per-field first-match-wins, last-wins as a global toggle, etc.) — v1 only commits to the rule for `content_type`. Future fields can revisit composition without breaking v1.
- **Overlap warnings.** v1 doesn't lint that multiple `[[asset]]` blocks could both match some asset — first-match-wins handles it implicitly. If users hit footguns (broad rule shadowing a more specific one declared later), add a sync-time warning then.
