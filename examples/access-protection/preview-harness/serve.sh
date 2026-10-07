#!/usr/bin/env bash
#
# Local browser check for the canister's two cookie variants.
#
# The canister emits `ic_env` and the access cookie twice each, under one name
# and value: a `SameSite=Lax` variant and a `SameSite=None; Secure; Partitioned`
# (CHIPS) one. Neither alone is accepted everywhere, so this harness opens both
# contexts side by side and lets you confirm a real browser ends up with a
# working session in each:
#
#   first-party  — the app opened directly, as a normal top-level visit. A
#                  current browser stores both variants here (they are separate
#                  jar entries: the partitioned one is keyed to the top-level
#                  site), so this checks that emitting two same-named cookies
#                  doesn't disturb the ordinary path. It is also the only
#                  context a client that rejects `SameSite=None` ever has, and
#                  there the `Lax` variant is what carries the session.
#   cross-site   — the app inside an iframe on another site (the "embedded
#                  preview" scenario). Only the partitioned variant is stored
#                  and sent here; `Lax` is not delivered cross-site.
#
# Both are served from a parent page on harness.localhost, which is a different
# site from the canister's <canister-id>.localhost — that difference is what
# makes the iframe genuinely cross-site.
#
# Both cookies are session cookies, so each check must be done in one browser
# session: quitting the browser drops them, and a reused profile will look like
# a logged-out visitor. Re-open this page to start over rather than reloading a
# stale tab.
#
# Chromium-based browsers ONLY (Chrome/Edge/Brave): they resolve *.localhost and
# accept Secure cookies over local http. Safari/Firefox cannot be checked this
# way; verify those against a real https deployment (see the README).
#
# Usage: ./serve.sh [--setup]
#   --setup  first enable protection + issue the token "secret" on the canister.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PROJECT="$(dirname "$HERE")"
TOKEN="secret"
PORT=8000

cid="$(cd "$PROJECT" && icp canister status frontend --id-only | tr -d '[:space:]')"
gw="$(cd "$PROJECT" && icp network status --json \
       | python3 -c 'import sys,json; print(json.load(sys.stdin)["gateway_url"])')"
gwport="$(python3 -c 'import sys; from urllib.parse import urlparse; print(urlparse(sys.argv[1]).port)' "$gw")"

if [ "${1:-}" = "--setup" ]; then
  ( cd "$PROJECT" && icp canister call frontend enable_protection '("/login.html")' ) || true
  # Record form (not a positional tuple): the dev wasm carries no candid metadata,
  # so icp infers arg types from the text and a tuple would be read as 3 args.
  ( cd "$PROJECT" && icp canister call frontend issue_token \
      "(record { label = \"preview\"; ttl_secs = 3600 : nat32; value = opt \"$TOKEN\" })" )
fi

app="http://$cid.localhost:$gwport"

serve="$(mktemp -d)"
cat > "$serve/index.html" <<HTML
<!DOCTYPE html>
<meta charset="utf-8" />
<title>cookie variant check</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
  section { margin-bottom: 2.5rem; }
  iframe { width: 840px; max-width: 100%; height: 480px; border: 1px solid #888; }
  .pass { color: #1a7f37; } .fail { color: #cf222e; }
  code { background: #eee; padding: .1rem .35rem; border-radius: 4px; }
</style>

<h1>Access-protection cookie check</h1>
<p>The canister sets each cookie twice, <code>SameSite=Lax</code> and
   <code>SameSite=None; Secure; Partitioned</code>. Each section below needs a
   different one, so both must work.</p>

<section>
  <h2>1. First-party (ordinary visit)</h2>
  <p>Opens the app directly as a top-level visit — what an ordinary visitor does.
     A current browser keeps both variants here; a client that rejects
     <code>SameSite=None</code> keeps only <code>Lax</code>, and this is the
     context it has.</p>
  <p><a href="$app/login.html#t=$TOKEN" target="_blank" rel="noopener">
     Open $app &rarr;</a></p>
  <p><span class="pass">PASS</span>: the private dashboard renders, including the
     <code>app.js</code> line (proving a non-HTML asset passed the gate too).<br />
     <span class="fail">FAIL</span>: the login page comes back, or the
     <code>app.js</code> line still reads &ldquo;Loading&rdquo;.</p>
  <p>While it is open, check the env cookie is readable by page scripts there:
     run <code>document.cookie</code> in that tab's console — it should contain
     <code>ic_env=</code>. (The access cookie is <code>HttpOnly</code> by design
     and must <em>not</em> appear.)</p>
</section>

<section>
  <h2>2. Cross-site iframe (the partitioned variant)</h2>
  <p>This page is on <code>harness.localhost</code>, a different site from the
     canister, so the frame below is genuinely cross-site — the embedded-preview
     scenario. <code>Lax</code> is not delivered here; only CHIPS is.</p>
  <p><span class="pass">PASS</span>: app content renders in the frame.<br />
     <span class="fail">FAIL</span>: the login page appears (cookie blocked).</p>
  <iframe src="$app/login.html#t=$TOKEN"></iframe>
</section>
HTML

echo "Open  http://harness.localhost:$PORT/  in a Chromium-based browser (Ctrl-C to stop)."
cd "$serve"
exec python3 -m http.server "$PORT" --bind 127.0.0.1
