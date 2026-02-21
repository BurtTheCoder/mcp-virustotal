# Release Process

This document describes how to create a new release of `@tocharianou/mcp-virustotal`.

## Prerequisites

- Node.js >= 18
- npm account with publish access to the `@tocharianou` organisation
- GitHub repository write access

## Steps

### 1. Prepare the Release

Update `version` in `package.json` and `server.json` following [Semantic Versioning](https://semver.org/).

Ensure the changelog (if maintained) is up to date, then commit:

```bash
git add package.json server.json
git commit -m "chore: release v<VERSION>"
```

### 2. Create the Release Archive

```bash
./scripts/create-release.sh
```

This produces:

| File | Description |
|------|-------------|
| `mcp-virustotal-v<VERSION>.tar.gz` | Release archive |
| `mcp-virustotal-v<VERSION>.sha256` | SHA-256 checksum |
| `mcp-virustotal-v<VERSION>.sha512` | SHA-512 checksum |

### 3. Tag the Release

```bash
git tag -a "v<VERSION>" -m "Release v<VERSION>"
git push origin "v<VERSION>"
```

### 4. Publish to npm

```bash
npm publish --access public
```

### 5. Create a GitHub Release

Upload the archive and both checksum files to the GitHub release page.

## Versioning Policy

| Change type | Version bump |
|-------------|-------------|
| Bug fix     | Patch        |
| New tool / backward-compatible feature | Minor |
| Breaking change to tool interface | Major |
