#!/bin/sh
# Download the CycloneDX 2.0 draft schema used by tests/test_tmbom.py into
# tests/schemas/cyclonedx-2.0 (git-ignored). Keep COMMIT in sync with
# SCHEMA_COMMIT in pytm/tmbom.py.
set -eu
COMMIT=906c57979d786c935787213ae1693a98097858ce
DEST="$(dirname "$0")/schemas/cyclonedx-2.0"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
git clone -q --filter=blob:none --no-checkout \
    https://github.com/CycloneDX/specification.git "$TMP/spec"
git -C "$TMP/spec" sparse-checkout set schema/2.0
git -C "$TMP/spec" checkout -q "$COMMIT"
mkdir -p "$DEST"
cp -r "$TMP/spec/schema/2.0/model" "$TMP/spec/schema/2.0/cyclonedx-2.0.schema.json" "$DEST"
echo "schema written to $DEST"
