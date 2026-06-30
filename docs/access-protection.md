# Access protection (private apps)

By default every deployed app is public. **Access protection** puts a login screen
in front of it: unauthenticated visitors get a certified redirect to your login
page (or a `401` for non-page assets) instead of your content. It's meant to
**deter casual/public access** to in-progress or preview work — not to provide
confidentiality against a determined attacker (see [Threat model](#threat-model)).

Access is a set of **labeled tokens**. The cookie *is* the token: a visitor presents
a token, the canister sets it as a cookie, and every request re-validates that cookie
against the token store. A classic single "password" is just one long-lived token.

When protection is off, the app is **completely unchanged** — no gate, no extra
headers, no cost difference. Everything below applies only once you enable it.

## Quick start

Protection is configured through controller-only canister methods, so you call them
with `icp canister call` as the canister's controller.

```sh
# 1. Add a login page to your site (see "The login page" below) and deploy it.
icp deploy

# 2. Turn the gate on, naming your login page.
icp canister call frontend enable_protection '("/login.html")'

# 3. Mint a credential. Here, a chosen "password" valid for ~1 year.
icp canister call frontend issue_token '("owner", 31536000 : nat32, opt "my-passphrase")'
```

That's it — `https://<canister-id>.icp0.io/` now redirects strangers to
`/login.html`, and visitors who present `my-passphrase` get in.

> **Enable before the first sync for a brand-new private app.** Enabling on an empty
> canister, *then* syncing, means there is never a window where your assets are
> world-readable. Enabling on an already-public app necessarily had a public period.

## Managing tokens

| Method | Call | Effect |
|---|---|---|
| Issue | `issue_token '("<label>", <ttl_secs> : nat32, opt "<value>")'` | Mints a token and **returns its value**. Omit the `opt "<value>"` (pass `null`) to get a high-entropy random token instead of a chosen passphrase. |
| Revoke | `revoke_token '("<label>")'` | Removes every token with that label — **live**, so the next request bearing it is rejected. |
| List | `list_tokens` | Returns `{ label; expires_at }` for every live token (controller-only). |
| Status | `check_protection_status` | `Disabled`, `Enabled`, or `EnabledLoginPageMissing` (controller-only). |
| Disable | `disable_protection` | Turns the gate off and drops all tokens. |

Each token has its **own expiry** and is **individually revocable** — revoking one
leaked share doesn't disturb anyone else. Expired tokens are rejected immediately
whether or not they've been swept, and are garbage-collected as new ones are issued.

**Random vs. chosen value.** A random token (omit the chosen value) is unguessable
and never transits the subnet in readable form. A chosen passphrase is typeable but
brute-forceable, and is visible to node operators in the block that carries the
`issue_token` call — acceptable under the threat model, but prefer random tokens for
share links.

## The login page

The login page is **your own asset**, synced in `dist/` and named when you
`enable_protection`. The canister serves it certified like any other page; it is the
**only gate-exempt path**, so it must be **fully self-contained** — inline its CSS and
JS, and use `data:` URIs for images. Any external subresource it referenced would
itself be gated and fail to load for a logged-out visitor.

The page honors a small contract:

- **Manual login:** render a form that `POST`s to its own path with a body of
  `token=<value>` (`application/x-www-form-urlencoded`). On success the canister
  replies `302 → /` and sets the cookie; on failure, `401` (re-prompt).
- **Transparent login (optional):** on load, read a token from `location.hash`
  (e.g. `#t=<token>`), auto-submit it to the same path, then clear the fragment with
  `history.replaceState`. The fragment never reaches the server, so a launcher can
  open `…/login.html#t=<token>` to sign a viewer in with no prompt.

A minimal page that does both:

```html
<!DOCTYPE html>
<html>
  <body>
    <form method="POST" action="/login.html">
      <input type="password" name="token" />
      <button type="submit">Enter</button>
    </form>
    <script>
      const t = new URLSearchParams(location.hash.slice(1)).get("t");
      if (t) {
        const f = document.forms[0];
        f.token.value = t;
        history.replaceState(null, "", location.pathname);
        f.submit();
      }
    </script>
  </body>
</html>
```

## What unauthenticated visitors get

| Request | Response |
|---|---|
| An HTML page (or any path with no exact asset — SPA routes, 404s) | Certified `307 → <login_page>` |
| A non-HTML asset (JS/CSS/image/JSON) | Certified `401` (a redirect would hand a `<script>` the wrong content type) |
| The login page itself | Always served (gate-exempt) |

Every protected response carries `Cache-Control: no-store` so the shared,
cookie-blind boundary cache can never replay one visitor's response to another.

## Lifecycle and the missing-page case

`check_protection_status` reports one of:

- **`Disabled`** — public app.
- **`Enabled`** — gate on, login page present.
- **`EnabledLoginPageMissing`** — gate on, but the named login-page asset isn't
  synced. The app **stays protected** (no content is served); requests redirect to a
  page that 404s until you sync it. It **self-heals** to `Enabled` once the page lands
  — no need to re-enable.

The gate **fails closed**: a sync that removes the login page, or enabling before the
first sync, never exposes content.

## Cross-app isolation

A token only works on the canister that issued it: the cookie is host-only (the
browser never sends it to another origin) **and** tokens live in this canister's own
store, so a token replayed against another canister isn't in *its* store.

## How the gate is certified

The canister serves **response-only** certified responses: the HTTP gateway (and any
verifier) checks that each response is an *authentic, certified* response for the
requested path — but **not** which of several certified responses the canister chose to
return. Choosing one is ordinary application logic.

That is the same mechanism the canister already uses to serve more than one response
per URL — different content encodings, `200` vs `304`, `206` range responses, and the
redirect/rewrite rules that serve one asset's body under another path. Access
protection has the same shape: under every protected path the canister certifies
**both** the asset's normal responses **and** a certified *unauthenticated sibling* —
the `307 → <login_page>` (HTML pages) or the `401` (other types). At serve time it
reads the `certified_assets_access` cookie and returns the sibling when it's missing or
invalid, the real asset when it's valid — each one independently verified by the
gateway. The login page's path additionally carries the certified `302 + Set-Cookie`
redeem (one per token) and the `401` re-prompt, so a login `POST` is honored only
because its outcome is certified too.

**Why not certify the request?** Doing so would let the canister prove *which* request
it answered, but request certification hashes the whole `Cookie` header verbatim — it
can't match on a single *named* cookie. Nor would it fire: the canister sets its own
`ic_env` cookie on HTML responses, so a browser always sends
`Cookie: ic_env=…; certified_assets_access=…`, never a bare value. Picking one cookie
out of many is necessarily app-side logic — hence response-only.

**The caveat this creates.** Because the cookie→response choice is uncertified app
logic, *which* response a request receives is **not** covered by the certificate. An
honest replica gates correctly; a **malicious** replica could hand the asset to a
token-less request (or the login page to a valid one), and the gateway couldn't tell.
This is the unavoidable property of any cookie-driven gate on a response-only canister,
and it sets up the trust boundary the threat model below makes precise.

## Threat model

This is **access gating, not confidentiality.** Under the IC's honest-replica /
honest-boundary-node assumption — the same assumption all query serving already makes
— unauthorized visitors can't pull your content. But:

- Asset bytes and the token store live in replicated canister state, so a **node
  operator can read both**. Protection does not hide content from operators. (Random
  token values are stored hashed; a low-entropy chosen passphrase is still
  brute-forceable, like any password hash.)
- TLS terminates at the boundary node, which sees the cookie in clear.
- There is **no brute-force protection, lockout, or rate-limiting** — login attempts
  are unbilled, untracked queries. The deterrent is high-entropy random tokens.

Use it to keep a preview or in-progress app out of public view — not to protect
secrets from a determined adversary.
