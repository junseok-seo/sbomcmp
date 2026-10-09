#!/usr/bin/env bash
# Shared helper: find the output path in argv (syft: -o cyclonedx-json=PATH; cdxgen: -o PATH; trivy: --output PATH)
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) shift; out="${1#cyclonedx-json=}";;
    --output) shift; out="$1";;
    --version|version) echo "$MOCK_VERSION"; exit 0;;
  esac
  shift
done
[ -z "$out" ] && { echo "mock: no output path" >&2; exit 2; }
