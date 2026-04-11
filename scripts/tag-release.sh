#!/usr/bin/env bash
# Cut a GitHub release: bumps nothing (edit internal/version/version.go first), then tag + push.
# GitHub Actions (release.yml) creates the Release and assets when tag v*.*.* is pushed.
set -euo pipefail
cd "$(dirname "$0")/.."

TAG="${1:?Usage: $0 v3.4.0}"
case "$TAG" in
  v*.*.*) ;;
  *) echo "Tag must look like v1.2.3" >&2; exit 1 ;;
esac

if ! git diff --quiet internal/version/version.go 2>/dev/null; then
  echo "Commit changes to internal/version/version.go before tagging, or stash them." >&2
  exit 1
fi

git fetch origin --tags -q
if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "Tag $TAG already exists locally." >&2
  exit 1
fi

read -r ver < <(grep 'const Version' internal/version/version.go | sed -E 's/.*const Version = "([^"]+)".*/\1/')
expect="v${ver}"
if [[ "$TAG" != "$expect" ]]; then
  echo "internal/version/version.go says ${ver} — expected tag $expect, got $TAG" >&2
  exit 1
fi

git tag -a "$TAG" -m "Release $TAG"
echo "Created annotated tag $TAG"
echo "Pushing branch and tag (opens GitHub Actions release workflow)..."
current_branch=$(git branch --show-current)
git push origin "$current_branch"
git push origin "$TAG"
echo "Done. Watch: https://github.com/$(git remote get-url origin | sed -E 's|.*github\.com[:/]([^/]+)/([^/.]+).*|\1/\2|')/actions"
