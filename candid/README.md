# Candid interfaces

This directory holds the canister's Candid interface files.

## Files

- **`assets.did`** — the assets canister's public interface. This is the file
  the canister is checked against (`candid_interface_compatibility` in
  [`crates/canister/src/lib.rs`](../crates/canister/src/lib.rs) compares the
  Rust-exported service to it via `service_equal`).
- **`http-gateway.did`** — the IC HTTP Gateway interface types, downloaded from
  the official specification:
  <https://docs.internetcomputer.org/references/http-gateway.did>

## Reusing the HTTP Gateway types

`assets.did` does not repeat the HTTP types. Instead it imports them:

```candid
import "http-gateway.did";
```

Plain `import` (without `service`) textually includes only the **type
definitions** from `http-gateway.did` — `HeaderField`, `HttpRequest`,
`HttpResponse`, `StreamingToken`, `StreamingStrategy`,
`StreamingCallbackHttpResponse` — and ignores that file's own `service`
declaration. `assets.did` then references those types directly and declares its
own service.

### The one local change to `http-gateway.did`

The gateway spec defines `StreamingToken` as an **opaque placeholder** — every
canister picks its own concrete type:

```candid
// (as published)
type StreamingToken = record {
  // application-specific type
};
```

We fill that placeholder in with the assets canister's concrete token:

```candid
type StreamingToken = record {
  key: text;
  encoding: text;
  index: nat;
  sha256: opt blob;
};
```

This is the customization the spec explicitly invites, and it is what lets the
imported `HttpResponse` / `StreamingStrategy` / `StreamingCallbackHttpResponse`
chain match the canister's actual (concrete-token) implementation. Aside from
this one record body, `http-gateway.did` is kept verbatim from the upstream
spec so it stays easy to diff against future versions.

> Note: Candid `import` errors on duplicate type names (it does not shadow), so
> each HTTP type must be defined in exactly one place. That's why `assets.did`
> defines none of them locally and relies entirely on the import.
