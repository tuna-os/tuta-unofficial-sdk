#!/bin/sh
# Make the vendored twin of a release tag, so the library builds as a plain
# Cargo git dependency:
#
#   scripts/vendor.sh v0.1.0          # creates the tag v0.1.0-vendored
#   git push origin v0.1.0-vendored
#
# The twin is one commit on top of the release: prepared/ (the patched SDK
# prepare.sh writes, about 4 MB) committed, and the upstream submodule left
# out, so Cargo neither needs Python to prepare it nor clones the 500 MB
# tutanota checkout. Nothing else changes; the content digest in
# prepared/sdk/EXPECTED still pins exactly what is built.
set -eu

tag=${1:?usage: scripts/vendor.sh <release tag>}
here=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
cleanup() {
    git -C "$here" worktree remove --force "$work" 2>/dev/null || rm -rf "$work"
}
trap cleanup EXIT INT TERM

git -C "$here" rev-parse --verify --quiet "refs/tags/$tag" >/dev/null || {
    echo "vendor.sh: no tag $tag" >&2
    exit 1
}
git -C "$here" worktree add --quiet --detach "$work" "$tag"
cd "$work"
# Borrow the objects of this checkout's submodules instead of cloning them.
git submodule update --quiet --init --reference "$here/upstream" upstream
git -C upstream submodule update --quiet --init --reference "$here/upstream/tuta-repo" tuta-repo
sh prepare.sh

git rm --quiet --cached upstream
git rm --quiet .gitmodules
grep -v '^/prepared/$' .gitignore >.gitignore.new && mv .gitignore.new .gitignore
git add .gitignore
git add --force prepared
git -c user.name="$(git -C "$here" config user.name)" \
    -c user.email="$(git -C "$here" config user.email)" \
    commit --quiet -m "build: vendor the prepared Tuta SDK for git dependencies

The release $tag with prepared/ committed and the upstream submodule left
out, so Cargo can build the library from git without running prepare.sh."
# The worktree shares this repository's refs, so the tag lands here.
git tag -a "$tag-vendored" -m "$tag with the prepared SDK vendored"
echo "created $tag-vendored"
