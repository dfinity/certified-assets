# Access protection (private app)

A runnable example of the [access-protection feature](../../docs/access-protection.md):
a static site that, once protection is enabled, redirects unauthenticated
visitors to a login page and serves content only to requests carrying a valid
access token.

It is exercised in CI by
[`crates/e2e/tests/protection.rs`](../../crates/e2e/tests/protection.rs), which
deploys this exact project to a local replica and drives the whole flow through
the real HTTP gateway.

## What it demonstrates

- A **public** site becomes **private** with one controller call.
- Unauthenticated **HTML** requests get a certified `307` redirect to the login
  page; unauthenticated **non-HTML** assets (here `app.js`) get a certified `401`.
- The login page validates a token via a `POST`, and the canister sets an
  `HttpOnly` session cookie — so page scripts can never read or delete the
  credential.
- A token in the URL fragment (`/login.html#t=<token>`) signs a visitor in with
  no prompt — the fragment never reaches the server.

## Project structure

```
access-protection
├── icp.yaml            # the `frontend` asset canister config
├── dist                # the site that gets synced
│   ├── index.html      # the private content (served only when authenticated)
│   ├── app.js          # a non-HTML asset — gated too (401 when logged out)
│   └── login.html      # the gate-exempt login page (fully self-contained)
└── preview-harness     # optional local iframe check (Chromium only)
    └── serve.sh
```

## Prerequisites

- [icp-cli](https://cli.icp.build)
- A Rust toolchain with the `wasm32-unknown-unknown` and `wasm32-wasip2` targets
  (to build the canister + plugin), plus `make`.

## Run it

From the repo root, build the canister and sync-plugin wasms — this example's
`icp.yaml` references them at `../../dist/`:

```sh
make wasm
```

Deploy the (still public) site to a local replica:

```sh
cd examples/access-protection
icp network start -d
icp deploy
```

Note the `frontend` URL that `icp deploy` prints — it looks like
`http://<canister-id>.localhost:<port>`. Open it: the site is public, so you see
the content.

Now turn the gate on and mint a token (a long-lived chosen "password"):

```sh
icp canister call frontend enable_protection '("/login.html")'
icp canister call frontend issue_token \
  '(record { label = "demo"; ttl_secs = 31536000 : nat32; value = opt "secret" })'
```

Reload the page:

- You're redirected to `/login.html`. Enter `secret` and submit — you're in.
- Or open `…/login.html#t=secret` to sign in with no prompt.
- Requesting `/app.js` directly while logged out returns `401`.

Make it public again, then stop the replica when you're done:

```sh
icp canister call frontend disable_protection '()'
icp network stop
```

## Preview it in an embedded iframe (local, Chromium only)

The access cookie is `SameSite=None; Secure; Partitioned`, so a private app also
works when shown inside a **cross-site iframe** (e.g. an embedded preview). To
check this locally:

```sh
cd examples/access-protection
icp network start -d && icp deploy
./preview-harness/serve.sh --setup   # enables protection + issues token "secret"
```

Open <http://harness.localhost:8000/> in a **Chromium-based** browser
(Chrome/Edge/Brave): the page frames this canister as a cross-site iframe.
**PASS** = the private content renders in the frame; **FAIL** = you get the
login page (the cookie was blocked as a third-party cookie).

Only Chromium browsers can be checked this way — they resolve `*.localhost` and
honour `Secure` cookies over local `http`. Safari and Firefox behave correctly
only over real HTTPS, so verify those against a deployed `https://<id>.icp0.io`.

## Managing access

| Call | Effect |
|---|---|
| `enable_protection '("/login.html")'` | Turn the gate on, naming your login page. |
| `issue_token '(record { label = "..."; ttl_secs = N : nat32; value = opt "..." })'` | Mint a token (pass `null` for `value` to get a random one); returns its value. |
| `revoke_token '("<label>")'` | Kill a token immediately (live on the next request). |
| `list_tokens '()'` | List live tokens — `{ label; expires_at }` (controller-only). |
| `check_protection_status '()'` | `Disabled`, `Enabled`, or `EnabledLoginPageMissing`. |
| `disable_protection '()'` | Turn the gate off and drop all tokens. |

See [`docs/access-protection.md`](../../docs/access-protection.md) for the full
model, the login-page contract, and the threat model.
