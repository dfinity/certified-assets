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

- **The version always lives in the workspace entry** — a crate must never
  restate it.
- **Features: put each one where its need lives, and make every crate enable
  what it uses.** A crate only gets the workspace base features plus whatever it
  adds in its own `{ workspace = true, features = [...] }`; you cannot rely on
  *another* crate's features reaching yours (that only happens via feature
  unification when both are built together, and breaks under
  `cargo build -p <crate>`). So:
  - shared by several crates → declare in the workspace base (`tokio`'s
    `rt` / `rt-multi-thread`);
  - needed by one crate → add it in that crate's own `features` (`reqwest`'s
    `blocking`, used only by e2e).

  Within one build Cargo compiles a single copy with the *union* of all
  requested features, so per-crate extras document intent, they don't isolate
  the artifact. Additive features are safe to over-enable, so "union in the
  base" is also fine when simpler.
- **`default-features = false` must be in the workspace entry**, not a member.
  A member-level `default-features` on an inherited dep is *ignored with a
  warning*, and because features unify to the union, defaults stay off only if
  the base sets it and no consumer re-enables them (`reqwest` is the example:
  `default-features = false` in the base, `blocking` added by e2e).
- Applies to `[dependencies]`, `[dev-dependencies]`, and `[build-dependencies]`.
- Path deps between workspace crates (`{ path = "../foo" }`) are the one
  exception — they have no version to hoist.

**Why:** one place to bump a version keeps the workspace on a single resolved
copy of each crate, and keeps `Cargo.lock` churn and version-skew bugs out of
per-crate edits.
