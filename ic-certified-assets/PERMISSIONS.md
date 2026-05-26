# Assets Canister Permission System

## Overview

The canister uses a three-tier permission model stored as three independent
`BTreeSet<Principal>` collections in the canister state. Controllers (set at
the platform level by `ic0.msg_caller_is_controller`) always pass every
permission check regardless of the explicit permission lists.

---

## Permission Types

Defined in `src/types.rs`:

```
Permission::Commit            — create/update/delete assets, commit batches
Permission::Prepare           — create batches and chunks
Permission::ManagePermissions — grant and revoke permissions for others
```

**Hierarchy:** A principal with `Commit` implicitly has `Prepare` as well
(implemented in `State::can`). The reverse is not true.

---

## Storage

`src/state_machine/mod.rs` — three fields on `State`:

```rust
commit_principals:              BTreeSet<Principal>
prepare_principals:             BTreeSet<Principal>
manage_permissions_principals:  BTreeSet<Principal>
```

These are serialised to `StableStatePermissionsV2` on upgrade and restored in
`impl From<StableStateV2> for State`.  Canisters upgraded from the legacy
`authorized` field treat all principals in that list as having `Commit`.

---

## Authorization Helpers (`src/lib.rs`)

| Helper | Succeeds when |
|--------|---------------|
| `can(permission)` | caller's principal is in the list **or** is a controller (`Commit` also implies `Prepare`) |
| `has_permission_or_is_controller(p)` | principal is in list **or** is a controller |
| `is_manager_or_controller()` | `ManagePermissions` list or controller |
| `is_controller()` | platform-level controller only |

---

## Operation → Required Permission

| Canister method | Minimum permission |
|---|---|
| `store` | `Commit` |
| `create_batch` | `Prepare` (or `Commit`) |
| `create_chunk` / `create_chunks` | `Prepare` (or `Commit`) |
| `create_asset` | `Commit` |
| `set_asset_content` | `Commit` |
| `unset_asset_content` | `Commit` |
| `delete_asset` | `Commit` |
| `clear` | `Commit` |
| `commit_batch` | `Commit` |
| `delete_batch` | `Prepare` (or `Commit`) |
| `set_asset_properties` | `Commit` |
| `configure` | `Commit` |
| `get_configuration` | `Prepare` (or `Commit`) |
| `authorize` | `ManagePermissions` or controller |
| `grant_permission` | `ManagePermissions` or controller |
| `deauthorize` | `Commit` (self) or controller (others) |
| `revoke_permission` | self: any listed permission; others: `ManagePermissions` or controller |
| `take_ownership` | controller only |
| `list_authorized` / `list_permitted` | none (public) |
| `get` / `get_chunk` / `list` / `api_version` | none (public) |

---

## Initialisation

`init()` in `src/lib.rs`:

1. Clears all state.
2. Grants the **message caller** `Commit` permission — so whoever deploys the
   canister gets `Commit` by default.
3. Optionally applies `InitArgs::set_permissions` to override the lists
   completely (used for programmatic deployments that want a custom initial
   permission set).

**Implication for proxy-deployed canisters:** when `icp deploy --proxy` creates
the assets canister, the proxy canister is the message caller at `init` time, so
the proxy gets `Commit`. The user's signing identity is not granted any
permission. The proxy is also the sole controller of the new canister.

---

## Proxy Mode Problem and Recommended Solution

### Problem

When the sync plugin is invoked after `icp deploy --proxy`:

1. The assets canister was created by the proxy → the **proxy canister** holds
   `Commit` permission and is the controller.
2. The sync plugin currently sends all calls with `direct: true` → calls are
   signed by the **user's identity**.
3. `create_batch`, `create_chunk`, and `commit_batch` all require `Commit`;
   the user's identity has none → every upload call is rejected.

### Solution (permission bootstrap in proxy mode)

Before starting the upload flow, the plugin should:

1. **Detect proxy mode** — `SyncExecInput::proxy_canister_id` is `Some`.

2. **Check current permissions** — call `list_permitted(Commit)` as a direct
   query (no proxy needed; this method is public). Parse the returned
   `Vec<Principal>` and check whether `input.identity_principal` is present.

3. **Grant if missing** — if the user's principal is not in the list, make a
   **proxy call** (`direct: false`) to `grant_permission` with:
   ```
   GrantPermissionArguments {
       to_principal: identity_principal,
       permission: Permission::Commit,
   }
   ```
   The proxy canister is a controller of the assets canister, so
   `has_permission_or_is_controller(ManagePermissions)` succeeds for it.

4. **Proceed normally** — all subsequent upload calls remain `direct: true`
   (signed by the user's identity, which now has `Commit`).

### Why `Commit` is sufficient

The V2 batch upload flow (`create_batch` → `create_chunk` → `commit_batch`)
requires only `Commit`. Granting `Commit` to the user's identity is therefore
the minimal permission needed and does not expose `ManagePermissions` to the
user.

### Candid reference

```candid
// Public read — no permission required; update (not query) call
list_permitted : (ListPermitted) -> (vec principal);

// Requires ManagePermissions or controller
grant_permission : (GrantPermission) -> ();

// Types
type Permission = variant { Commit; Prepare; ManagePermissions };
type ListPermitted = record { permission : Permission };
type GrantPermission = record { to_principal : principal; permission : Permission };
```
