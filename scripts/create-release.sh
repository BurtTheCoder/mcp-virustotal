#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Copyright (c) 2024 TocharianOU Contributors
#
# Create a versioned release archive with SHA-256 and SHA-512 checksums.
#
# Usage:
#   ./scripts/create-release.sh
#
# Requirements:
#   - npm run build must succeed before running this script
#   - git working tree must be clean
#   - VERSION is read from package.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

VERSION="$(node -pe "require('./package.json').version")"
ARCHIVE="mcp-virustotal-v${VERSION}.tar.gz"
CHECKSUM_FILE="mcp-virustotal-v${VERSION}.sha256"
SHA512_FILE="mcp-virustotal-v${VERSION}.sha512"

echo "Building v${VERSION}…"
npm run build

echo "Creating archive ${ARCHIVE}…"
tar -czf "${ARCHIVE}" \
  dist \
  logos \
  LICENSE \
  README.md \
  server.json \
  package.json

echo "Generating checksums…"
shasum -a 256 "${ARCHIVE}" > "${CHECKSUM_FILE}"
shasum -a 512 "${ARCHIVE}" > "${SHA512_FILE}"

echo ""
echo "Release files created:"
echo "  ${ARCHIVE}"
echo "  ${CHECKSUM_FILE}"
echo "  ${SHA512_FILE}"
echo ""
cat "${CHECKSUM_FILE}"
