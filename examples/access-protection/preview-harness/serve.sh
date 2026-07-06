#!/usr/bin/env bash
#
# Local cross-site iframe preview check for access protection.
#
# Serves a tiny parent page (on harness.localhost) that embeds this canister
# (on <canister-id>.localhost) in an iframe. The two are different sites, so the
# browser treats the canister as a cross-site frame — the "embedded preview"
# scenario — which exercises the SameSite=None; Secure; Partitioned access cookie.
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

serve="$(mktemp -d)"
cat > "$serve/index.html" <<HTML
<!DOCTYPE html>
<meta charset="utf-8" />
<title>iframe preview check</title>
<p>Cross-site iframe of <code>http://$cid.localhost:$gwport</code> —
   PASS: app content renders below; FAIL: the login page appears (cookie blocked).</p>
<iframe src="http://$cid.localhost:$gwport/login.html#t=$TOKEN"
        style="width:840px;max-width:100%;height:600px;border:1px solid #888"></iframe>
HTML

echo "Open  http://harness.localhost:$PORT/  in a Chromium-based browser (Ctrl-C to stop)."
cd "$serve"
exec python3 -m http.server "$PORT" --bind 127.0.0.1
