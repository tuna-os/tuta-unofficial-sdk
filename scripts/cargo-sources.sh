#!/bin/sh
# Write cargo-sources.json, the offline crate sources a Flatpak build of this
# workspace (or of an app that vendors it) hands to flatpak-builder:
#
#   scripts/cargo-sources.sh [output]     # default: cargo-sources.json
#
# Regenerate it after every Cargo.lock change, or the offline build fails.
# It runs flatpak-builder-tools' flatpak-cargo-generator.py at a pinned
# commit, checked against its SHA-256, under uv (https://docs.astral.sh/uv/).
set -eu

GENERATOR_COMMIT=9d86d336a39b9af38b86f114b6ce5820fe260f91
GENERATOR_SHA256=0a2db6be87d75910facef28ab46d4d6460802e8419ab850d0caa6a364d26b380
GENERATOR_URL="https://raw.githubusercontent.com/flatpak/flatpak-builder-tools/$GENERATOR_COMMIT/cargo/flatpak-cargo-generator.py"

here=$(cd "$(dirname "$0")/.." && pwd)
output=${1:-"$here/cargo-sources.json"}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

curl -fsSL -o "$work/flatpak-cargo-generator.py" "$GENERATOR_URL"
echo "$GENERATOR_SHA256  $work/flatpak-cargo-generator.py" | sha256sum -c --status || {
    echo "cargo-sources.sh: flatpak-cargo-generator.py does not match its pinned SHA-256" >&2
    exit 1
}
uv run --quiet --no-project --with aiohttp --with toml --with tomlkit \
    python "$work/flatpak-cargo-generator.py" "$here/Cargo.lock" -o "$output"
echo "wrote $output"
