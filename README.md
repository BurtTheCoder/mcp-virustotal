# VirusTotal MCP Server

[![npm version](https://img.shields.io/npm/v/@tocharianou/mcp-virustotal)](https://www.npmjs.com/package/@tocharianou/mcp-virustotal)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Node.js >= 18](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that provides security analysis tools powered by the [VirusTotal API v3](https://docs.virustotal.com/reference/overview). Analyse URLs, files, IP addresses and domains directly from your AI assistant.

## Quick Start

### Claude Desktop (stdio)

Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "virustotal": {
      "command": "npx",
      "args": ["-y", "@tocharianou/mcp-virustotal"],
      "env": {
        "VIRUSTOTAL_API_KEY": "<your-api-key>"
      }
    }
  }
}
```

Get your free API key at [virustotal.com](https://www.virustotal.com/gui/my-apikey).

### HTTP / Streamable mode

```bash
MCP_TRANSPORT=http MCP_HTTP_PORT=3000 VIRUSTOTAL_API_KEY=<key> npx @tocharianou/mcp-virustotal
```

Then point your MCP client at `http://localhost:3000/mcp`.

## Features

- **URL analysis** — full scan results, HTTP response details, trackers, redirection chains
- **File analysis** — hash lookup (MD5/SHA-1/SHA-256), sandbox verdicts, YARA/Sigma/IDS results
- **IP analysis** — geolocation, ASN, WHOIS, SSL certificate chain
- **Domain analysis** — DNS records, WHOIS, popularity rankings, threat severity
- **Relationship traversal** — paginated access to all VT relationship types per resource

## Configuration

| Environment variable | Required | Description |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | ✓\* | VT API key, sent as `x-apikey` header (direct mode) |
| `VIRUSTOTAL_BASE_URL` | – | Override API base URL (e.g. proxy endpoint) |
| `VIRUSTOTAL_AUTH_TOKEN` | ✓\* | Bearer token for proxy authentication |
| `VIRUSTOTAL_TIMEOUT` | – | Request timeout in ms (default: `30000`) |
| `MCP_TRANSPORT` | – | `stdio` (default) or `http` |
| `MCP_HTTP_PORT` | – | HTTP server port (default: `3000`) |
| `MCP_HTTP_HOST` | – | HTTP server host (default: `localhost`) |

\* Either `VIRUSTOTAL_API_KEY` (direct) **or** `VIRUSTOTAL_BASE_URL` + `VIRUSTOTAL_AUTH_TOKEN` (proxy) must be set.

### Direct vs Proxy mode

**Direct mode** — the server calls VirusTotal directly using your own API key:
```
VIRUSTOTAL_API_KEY=VT_KEY_HERE
```

**Proxy mode** — the server calls a backend gateway that injects the real API key and handles billing. The server authenticates to the gateway using a Bearer token:
```
VIRUSTOTAL_BASE_URL=https://gateway.example.com/vt
VIRUSTOTAL_AUTH_TOKEN=YOUR_BEARER_TOKEN
```

The tool itself is mode-agnostic; the calling application sets the appropriate variables.

## Available Tools

| Tool | Description |
|------|-------------|
| `get_url_report` | Full URL scan including automatic relationship fetch |
| `get_url_relationship` | Paginated URL relationship query (17 types) |
| `get_file_report` | File analysis by hash (MD5/SHA-1/SHA-256) |
| `get_file_relationship` | Paginated file relationship query (41 types) |
| `get_ip_report` | IP address analysis with geolocation and relationships |
| `get_ip_relationship` | Paginated IP relationship query (12 types) |
| `get_domain_report` | Domain analysis with DNS, WHOIS and relationships |

## Example Queries

- *"Check if this URL is malicious: https://example.com"*
- *"Analyse this file hash: d41d8cd98f00b204e9800998ecf8427e"*
- *"What files has IP 8.8.8.8 been communicating with?"*
- *"Give me the SSL certificate history for github.com"*

## Debugging

Use the [MCP Inspector](https://github.com/modelcontextprotocol/inspector) to test and debug:

```bash
npm run inspector
```

Server logs are written to **stderr** so they do not interfere with the MCP JSON-RPC stream on stdout.

## Troubleshooting

| Symptom | Likely cause |
|---------|-------------|
| `No credentials configured` | Neither `VIRUSTOTAL_API_KEY` nor `VIRUSTOTAL_AUTH_TOKEN` is set |
| `VirusTotal API error: 401` | Invalid or expired API key |
| `VirusTotal API error: 429` | API quota exceeded (free tier: 500 req/day) |
| Tool calls time out | Increase `VIRUSTOTAL_TIMEOUT` or check network connectivity |

## Development

```bash
git clone https://github.com/TocharianOU/mcp-virustotal.git
cd mcp-virustotal
npm install --ignore-scripts
npm run build
cp .env.example .env   # fill in your API key
npm start
```

## Release

See [RELEASE.md](RELEASE.md) for the full release process.

## License

[MIT](LICENSE) — Copyright © 2024 TocharianOU

> **Disclaimer**: This project is community-maintained and is not affiliated with or endorsed by VirusTotal or Google LLC.
