#!/usr/bin/env bash
#
# Publish the `certified-assets` recipe to the dfinity/icp-cli-recipes registry.
#
# Generates the *release* recipe (pinning this repo's canister/plugin wasm by
# release URL + the exact published sha256), drops it into a sibling clone of
# icp-cli-recipes on a fresh branch, commits, and — by default — stops so you can
# review the diff before opening the PR. Pass --push to push the branch and open
# the PR.
#
# Resumable & idempotent: each phase (prepare the branch / push + open PR) is
# safe to re-run. A review run (no --push) prepares the branch; re-running with
# --push reuses that prepared branch and just pushes + opens the PR. Running with
# --push from scratch does everything in one shot.
#
# Non-destructive: it refuses to *prepare* against a dirty recipes clone,
# branches off a freshly fetched origin/main, and never commits onto your current
# branch.
#
# Usage:
#   scripts/publish-recipe.sh <version-tag> [--recipes-repo <path>] [--push]
#
#   <version-tag>      e.g. v1.0.0 — must match a published GitHub release of
#                      this repo (the .sha256 release assets are downloaded).
#   --recipes-repo P   path to your icp-cli-recipes clone (default: ../icp-cli-recipes)
#   --push             push the branch and open the PR (default: stop after
#                      preparing the branch and print the commands)
#
# After the PR merges, publish the recipe release by pushing the registry tag:
#   git -C <recipes-repo> tag certified-assets-<version> && git push origin certified-assets-<version>
# which triggers icp-cli-recipes' release-recipe.yml.

set -euo pipefail

RECIPE_NAME="certified-assets"
THIS_REPO="dfinity/certified-assets"

die() {
  echo "error: $*" >&2
  exit 1
}

# --- parse args --------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VERSION=""
RECIPES_REPO="$REPO_ROOT/../icp-cli-recipes"
PUSH=0

while [ $# -gt 0 ]; do
  case "$1" in
    --recipes-repo)
      [ $# -ge 2 ] || die "--recipes-repo needs a path"
      RECIPES_REPO="$2"
      shift 2
      ;;
    --push)
      PUSH=1
      shift
      ;;
    -h | --help)
      sed -n '3,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    -*)
      die "unknown flag: $1"
      ;;
    *)
      [ -z "$VERSION" ] || die "unexpected extra argument: $1"
      VERSION="$1"
      shift
      ;;
  esac
done

[ -n "$VERSION" ] || die "missing <version-tag> (e.g. v1.0.0)"
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must look like v1.0.0, got: $VERSION"

command -v gh >/dev/null 2>&1 || die "gh (GitHub CLI) is required"

# --- locate the recipes clone ------------------------------------------------

[ -d "$RECIPES_REPO/.git" ] || die "not a git clone: $RECIPES_REPO (pass --recipes-repo)"
RECIPES_REPO="$(cd "$RECIPES_REPO" && pwd)"

BRANCH="$RECIPE_NAME-$VERSION"
COMMIT_MSG="feat($RECIPE_NAME): publish $VERSION"
DEST_REL="recipes/$RECIPE_NAME"

# --- prepare the branch (idempotent) -----------------------------------------
#
# If the branch already exists *and* its tip is our publish commit, an earlier
# run already prepared it — reuse it. If it exists but isn't ours, refuse. Else
# create it fresh.

prepared_now=0
if git -C "$RECIPES_REPO" show-ref --verify --quiet "refs/heads/$BRANCH"; then
  tip_subject="$(git -C "$RECIPES_REPO" log -1 --format=%s "$BRANCH")"
  [ "$tip_subject" = "$COMMIT_MSG" ] || die \
    "branch $BRANCH exists in $RECIPES_REPO but its tip ('$tip_subject') isn't a '$COMMIT_MSG' commit — delete it or pick another version"
  echo "Branch '$BRANCH' was already prepared by an earlier run — reusing it."
else
  # Fresh prepare: this is the only phase that writes to the working tree, so
  # guard it with the dirty-tree check.
  [ -z "$(git -C "$RECIPES_REPO" status --porcelain)" ] || die \
    "recipes clone has uncommitted changes: $RECIPES_REPO — commit/stash first"

  TMP="$(mktemp -d)"
  trap 'rm -rf "$TMP"' EXIT

  echo "Downloading release checksums for $VERSION from $THIS_REPO ..."
  gh release download "$VERSION" -R "$THIS_REPO" -p '*.sha256' --dir "$TMP" \
    || die "could not download .sha256 assets for $VERSION — is the release published?"

  echo "Generating $RECIPE_NAME recipe.hbs ..."
  cargo run --quiet --manifest-path "$REPO_ROOT/Cargo.toml" -p recipe-gen -- release \
    --version "$VERSION" \
    --shas-from "$TMP" \
    -o "$TMP/recipe.hbs"

  echo "Fetching origin/main in $RECIPES_REPO ..."
  git -C "$RECIPES_REPO" fetch --quiet origin main
  git -C "$RECIPES_REPO" switch --quiet --no-track -c "$BRANCH" origin/main

  mkdir -p "$RECIPES_REPO/$DEST_REL"
  cp "$TMP/recipe.hbs" "$RECIPES_REPO/$DEST_REL/recipe.hbs"
  cp "$REPO_ROOT/crates/recipe-gen/assets/README.md" "$RECIPES_REPO/$DEST_REL/README.md"

  git -C "$RECIPES_REPO" add "$DEST_REL/recipe.hbs" "$DEST_REL/README.md"
  git -C "$RECIPES_REPO" commit --quiet -m "$COMMIT_MSG"
  prepared_now=1
  echo "Committed $COMMIT_MSG on branch '$BRANCH'."
fi

echo
echo "Changes on '$BRANCH' (vs origin/main):"
git -C "$RECIPES_REPO" show --stat --oneline "$BRANCH" | sed 's/^/  /'

# --- push + open PR (idempotent) ---------------------------------------------

PR_TITLE="$COMMIT_MSG"
PR_BODY="Publishes the \`$RECIPE_NAME\` recipe at $VERSION, pinning the canister and sync-plugin wasm from $THIS_REPO's $VERSION release.

After merge, tag \`$RECIPE_NAME-$VERSION\` in this repo to cut the recipe release."

if [ "$PUSH" -eq 1 ]; then
  echo
  echo "Pushing '$BRANCH' to origin ..."
  git -C "$RECIPES_REPO" push -u origin "$BRANCH"

  existing_pr="$(cd "$RECIPES_REPO" && gh pr list --head "$BRANCH" --state open --json url --jq '.[0].url // empty' 2>/dev/null || true)"
  if [ -n "$existing_pr" ]; then
    echo "PR already open: $existing_pr"
  else
    ( cd "$RECIPES_REPO" && gh pr create --base main --head "$BRANCH" --title "$PR_TITLE" --body "$PR_BODY" )
  fi
else
  echo
  if [ "$prepared_now" -eq 1 ]; then
    echo "Review the diff above, then re-run with --push to push and open the PR:"
  else
    echo "Branch is ready. Re-run with --push to push and open the PR:"
  fi
  echo "  scripts/publish-recipe.sh $VERSION --push"
  echo "or do it by hand:"
  echo "  git -C \"$RECIPES_REPO\" push -u origin \"$BRANCH\""
  echo "  ( cd \"$RECIPES_REPO\" && gh pr create --base main --head \"$BRANCH\" --title \"$PR_TITLE\" )"
fi
