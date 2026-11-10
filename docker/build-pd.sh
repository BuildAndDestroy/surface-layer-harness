#!/usr/bin/env bash
# Build a ProjectDiscovery tool from its release tag, raising selected Go dependencies to their
# latest releases first (PATCH_MODULES). Upstream releases can lag behind security fixes in their
# libraries; this keeps image scans clean without waiting for upstream.
#   usage: build-pd.sh <repo> <tag> <main package> <binary name>
set -euo pipefail
repo=$1 tag=$2 pkg=$3 bin=$4
dir=$(mktemp -d)
git clone -q --depth 1 --branch "$tag" "https://github.com/projectdiscovery/$repo" "$dir"
cd "$dir"
for m in ${PATCH_MODULES:-}; do
  if go list -m "$m" >/dev/null 2>&1; then
    go get "$m@latest"
  fi
done
go mod tidy
go build -trimpath -ldflags="-s -w" -o "/go/bin/$bin" "$pkg"
cd /
rm -rf "$dir"
"/go/bin/$bin" -version 2>&1 | tail -1
