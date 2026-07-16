---
paths:
  - "Cargo.toml"
  - "**/Cargo.toml"
---

# Dependencies

Declare every dependency **version once**, in the root `Cargo.toml`
`[workspace.dependencies]`. A crate's own `Cargo.toml` must reference it with
`.workspace = true` — never a version literal.

```toml
# root Cargo.toml
[workspace.dependencies]
tokio = { version = "1", features = ["rt", "rt-multi-thread"] }

# crates/<crate>/Cargo.toml
[dependencies]
tokio.workspace = true          # or { workspace = true, features = ["extra"] }
```

- **Version and shared features live at the workspace level.** If two crates
  need different feature sets, declare the union in `[workspace.dependencies]`
  (cargo unifies features across the workspace anyway) and let both use
  `.workspace = true`. A crate may add *extra* features with
  `{ workspace = true, features = [...] }` (see `reqwest` → e2e's `blocking`),
  but must not restate the version.
- Applies to `[dependencies]`, `[dev-dependencies]`, and `[build-dependencies]`.
- Path deps between workspace crates (`{ path = "../foo" }`) are the one
  exception — they have no version to hoist.

**Why:** one place to bump a version keeps the workspace on a single resolved
copy of each crate, and keeps `Cargo.lock` churn and version-skew bugs out of
per-crate edits.
