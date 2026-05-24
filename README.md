# VirusTotal MCP Server

[![MCP Registry](https://img.shields.io/badge/MCP-Registry-blue)](https://registry.modelcontextprotocol.io)
[![smithery badge](https://smithery.ai/badge/@burtthecoder/mcp-virustotal)](https://smithery.ai/server/@burtthecoder/mcp-virustotal)

A Model Context Protocol (MCP) server for querying the [VirusTotal API](https://www.virustotal.com/). This server provides comprehensive security analysis tools with automatic relationship data fetching. It integrates seamlessly with MCP-compatible applications like [Claude Desktop](https://claude.ai).

## Quick Start (Recommended)

### Claude Code
```bash
claude mcp add --transport stdio --env VIRUSTOTAL_API_KEY=your-key virustotal -- npx -y @burtthecoder/mcp-virustotal
```

### Codex CLI
```bash
codex mcp add virustotal --env VIRUSTOTAL_API_KEY=your-key -- npx -y @burtthecoder/mcp-virustotal
```

### Gemini CLI
```bash
gemini mcp add -e VIRUSTOTAL_API_KEY=your-key virustotal npx -y @burtthecoder/mcp-virustotal
```

### Installing via Smithery

To install VirusTotal Server for Claude Desktop automatically via [Smithery](https://smithery.ai/server/@burtthecoder/mcp-virustotal):

```bash
npx -y @smithery/cli install @burtthecoder/mcp-virustotal --client claude
```

### Installing Manually

1. Install the server globally via npm:
```bash
npm install -g @burtthecoder/mcp-virustotal
```

2. Add to your Claude Desktop configuration file:
```json
{
  "mcpServers": {
    "virustotal": {
      "command": "mcp-virustotal",
      "env": {
        "VIRUSTOTAL_API_KEY": "your-virustotal-api-key"
      }
    }
  }
}
```

Configuration file location:
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

3. Restart Claude Desktop

### Using with VS Code

To use this MCP server in VS Code with GitHub Copilot:

1. Install the server globally via npm:
```bash
npm install -g @burtthecoder/mcp-virustotal
```

2. Create or update your VS Code MCP configuration file at:
   - macOS/Linux: `~/.vscode/mcp.json`
   - Windows: `%USERPROFILE%\.vscode\mcp.json`

3. Add the following configuration:
```json
{
  "servers": {
    "virustotal": {
      "command": "mcp-virustotal",
      "env": {
        "VIRUSTOTAL_API_KEY": "your-virustotal-api-key"
      }
    }
  }
}
```

4. Reload VS Code to activate the MCP server

You can then use the VirusTotal tools through GitHub Copilot in VS Code by referencing the available tools in your prompts.

## Alternative Setup (From Source)

If you prefer to run from source or need to modify the code:

1. Clone and build:
```bash
git clone <repository_url>
cd mcp-virustotal
npm install
npm run build
```

2. Add to your Claude Desktop configuration:
```json
{
  "mcpServers": {
    "virustotal": {
      "command": "node",
      "args": ["/absolute/path/to/mcp-virustotal/build/index.js"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your-virustotal-api-key"
      }
    }
  }
}
```

## HTTP Streaming Transport

The server supports HTTP streaming transport in addition to the default stdio transport. This is useful for running the server as a standalone HTTP service that multiple clients can connect to.

### Running in HTTP Streaming Mode

Set the `MCP_TRANSPORT` environment variable to `httpStream`:

```bash
MCP_TRANSPORT=httpStream MCP_PORT=3000 VIRUSTOTAL_API_KEY=your-key node build/index.js
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | *(required)* | Your VirusTotal API key |
| `MCP_TRANSPORT` | `stdio` | Transport mode: `stdio` or `httpStream` |
| `MCP_PORT` | `3000` | HTTP server port (only for `httpStream`) |
| `MCP_ENDPOINT` | `/mcp` | HTTP endpoint path (only for `httpStream`) |

### Docker with HTTP Streaming

```bash
docker build -t mcp-virustotal .
docker run -p 3000:3000 \
  -e VIRUSTOTAL_API_KEY=your-key \
  -e MCP_TRANSPORT=httpStream \
  mcp-virustotal
```

The server exposes a health check endpoint at `/health` when running in HTTP streaming mode.

## Features

- **Comprehensive Analysis Reports**: Each analysis tool automatically fetches relevant relationship data along with the basic report using VirusTotal's `?relationships=` query, batched to minimize API calls
- **URL Analysis**: Cached-report-first lookups with automatic fallback to scanning, plus contacted domains, downloaded files, and threat actors
- **File Analysis**: Detailed analysis of file hashes including behaviors, dropped files, and network connections
- **IP Analysis**: Security reports with historical data, resolutions, and related threats
- **Domain Analysis**: DNS information, WHOIS data, SSL certificates, and subdomains
- **Detailed Relationship Analysis**: Dedicated tools for querying specific types of relationships with pagination support
- **Corpus Search**: Free-form search across files, URLs, domains, IPs, and comments, including VTI-style modifier syntax (`type:peexe positives:5+`)
- **Sandbox Behaviour Summary**: Cross-sandbox merged view of processes, files, registry, network, MITRE ATT&CK, IDS alerts, and signature matches
- **Threat Collections**: Read APT, malware-family, campaign, and intel-report objects referenced from any report's relationships
- **Rich Formatting**: Clear categorization and presentation of analysis results and relationship data

## Tools

### Report Tools (with Automatic Relationship Fetching)

### 1. URL Report Tool
- Name: `get_url_report`
- Description: Get a comprehensive URL analysis report including security scan results and key relationships (communicating files, contacted domains/IPs, downloaded files, redirects, threat actors). Returns the cached VirusTotal report when available; only submits the URL for scanning and polls for completion on a cache miss
- Parameters:
  * `url` (required): The URL to analyze

### 2. File Report Tool
- Name: `get_file_report`
- Description: Get a comprehensive file analysis report using its hash (MD5/SHA-1/SHA-256). Includes detection results, file properties, and key relationships (behaviors, dropped files, network connections, embedded content, threat actors)
- Parameters:
  * `hash` (required): MD5, SHA-1 or SHA-256 hash of the file

### 3. IP Report Tool
- Name: `get_ip_report`
- Description: Get a comprehensive IP address analysis report including geolocation, reputation data, and key relationships (communicating files, historical certificates/WHOIS, resolutions)
- Parameters:
  * `ip` (required): IP address to analyze

### 4. Domain Report Tool
- Name: `get_domain_report`
- Description: Get a comprehensive domain analysis report including DNS records, WHOIS data, and key relationships (SSL certificates, subdomains, historical data)
- Parameters:
  * `domain` (required): Domain name to analyze
  * `relationships` (optional): Array of specific relationships to include in the report

### Relationship Tools (for Detailed Analysis)

### 1. URL Relationship Tool
- Name: `get_url_relationship`
- Description: Query a specific relationship type for a URL with pagination support. Choose from 22 relationship types including analyses, communicating files, contacted domains/IPs, downloaded files, graphs, referrers, redirects, threat actors, collections, and votes
- Parameters:
  * `url` (required): The URL to get relationships for
  * `relationship` (required): Type of relationship to query
    - Available relationships: analyses, collections, comments, communicating_files, contacted_domains, contacted_ips, downloaded_files, embedded_js_files, graphs, last_serving_ip_address, network_location, referrer_files, referrer_urls, redirecting_urls, redirects_to, related_comments, related_references, related_threat_actors, submissions, urls_related_by_tracker_id, user_votes, votes
  * `limit` (optional, default: 10): Maximum number of related objects to retrieve (1-40)
  * `cursor` (optional): Continuation cursor for pagination

### 2. File Relationship Tool
- Name: `get_file_relationship`
- Description: Query a specific relationship type for a file with pagination support. Choose from 40 relationship types including behaviors, network connections, dropped files, embedded content, execution chains, and threat actors
- Parameters:
  * `hash` (required): MD5, SHA-1 or SHA-256 hash of the file
  * `relationship` (required): Type of relationship to query
    - Available relationships: analyses, behaviours, bundled_files, carbonblack_children, carbonblack_parents, ciphered_bundled_files, ciphered_parents, collections, comments, compressed_parents, contacted_domains, contacted_ips, contacted_urls, dropped_files, email_attachments, email_parents, embedded_domains, embedded_ips, embedded_urls, execution_parents, graphs, itw_domains, itw_ips, itw_urls, memory_pattern_domains, memory_pattern_ips, memory_pattern_urls, overlay_children, overlay_parents, pcap_children, pcap_parents, pe_resource_children, pe_resource_parents, related_references, related_threat_actors, similar_files, submissions, screenshots, urls_for_embedded_js, votes
  * `limit` (optional, default: 10): Maximum number of related objects to retrieve (1-40)
  * `cursor` (optional): Continuation cursor for pagination

### 3. IP Relationship Tool
- Name: `get_ip_relationship`
- Description: Query a specific relationship type for an IP address with pagination support. Choose from 15 relationship types including communicating files, historical SSL certificates, WHOIS records, resolutions, threat actors, and votes
- Parameters:
  * `ip` (required): IP address to analyze
  * `relationship` (required): Type of relationship to query
    - Available relationships: collections, comments, communicating_files, downloaded_files, graphs, historical_ssl_certificates, historical_whois, related_comments, related_references, related_threat_actors, referrer_files, resolutions, urls, user_votes, votes
  * `limit` (optional, default: 10): Maximum number of related objects to retrieve (1-40)
  * `cursor` (optional): Continuation cursor for pagination

### 4. Domain Relationship Tool
- Name: `get_domain_relationship`
- Description: Query a specific relationship type for a domain with pagination support. Choose from 24 relationship types including SSL certificates, subdomains, historical data, DNS records, and collections
- Parameters:
  * `domain` (required): Domain name to analyze
  * `relationship` (required): Type of relationship to query
    - Available relationships: caa_records, cname_records, collections, comments, communicating_files, downloaded_files, graphs, historical_ssl_certificates, historical_whois, immediate_parent, mx_records, ns_records, parent, referrer_files, related_comments, related_references, related_threat_actors, resolutions, soa_records, siblings, subdomains, urls, user_votes, votes
  * `limit` (optional, default: 10): Maximum number of related objects to retrieve (1-40)
  * `cursor` (optional): Continuation cursor for pagination

### Search & Pivot Tools

### 1. Corpus Search
- Name: `search_vt`
- Description: Search the VirusTotal corpus for files, URLs, domains, IPs, or comments matching a query. Accepts plain IOCs (hash, URL, domain, IP), free text against comments, or VTI-style search modifiers
- Parameters:
  * `query` (required): Search query. Examples: a SHA-256 hash, `evil.com`, `8.8.8.8`, `type:peexe size:90kb+ tag:signed positives:5+`
  * `limit` (optional, default: 20): Maximum number of results (1-300)
  * `cursor` (optional): Continuation cursor for pagination

### 2. File Behaviour Summary
- Name: `get_file_behaviour_summary`
- Description: Get a consolidated sandbox behaviour summary for a file, merged across every sandbox that analyzed it. Returns processes, files, registry, network activity, DNS lookups, MITRE ATT&CK techniques, IDS alerts, and signature matches in a single view — far more useful than iterating individual behaviour reports
- Parameters:
  * `hash` (required): MD5, SHA-1 or SHA-256 hash of the file

### 3. Collection Lookup
- Name: `get_collection`
- Description: Retrieve a VirusTotal collection by ID. Collections represent threat actors, malware families, campaigns, intel reports, and curated IOC sets — often referenced from the `related_threat_actors` and `collections` relationships on other tools. Optionally include relationships to fetch member IOCs in the same call
- Parameters:
  * `id` (required): Collection ID (e.g. `threat-actor--<uuid>`, `malware-family--<id>`)
  * `relationships` (optional): Array of relationship names to include
    - Available relationships: autogenerated_graphs, comments, domains, files, ip_addresses, owner, references, related_collections, related_references, threat_actors, urls

## Requirements

- Node.js (v20 or later)
- A valid [VirusTotal API Key](https://www.virustotal.com/gui/my-apikey)

## Troubleshooting

### API Key Issues

If you see "Wrong API key" errors:

1. Check the log file at `/tmp/mcp-virustotal-server.log` (on macOS) for API key status
2. Verify your API key:
   - Should be a valid VirusTotal API key (usually 64 characters)
   - No extra spaces or quotes around the key
   - Must be from the API Keys section in your VirusTotal account
3. After any configuration changes:
   - Save the config file
   - Restart Claude Desktop
   - Check logs for new API key status

## Development

To run in development mode with hot reloading:
```bash
npm run dev
```

## Testing

### Unit tests
Run the formatter test suite (no API key, no network):
```bash
npm test
```

### Live smoke test
Exercise all 11 tools end-to-end against the real VirusTotal API:
```bash
VIRUSTOTAL_API_KEY=your-key npm run smoke
```

The smoke test paces calls at 20 s to stay under the 4-requests-per-minute public-tier rate limit. **It is not compatible with heavily reduced free tiers (e.g. 1 lookup/day)** — for those, run a single tool by editing `scripts/smoke-test.mjs` and pick the one you want to verify.

## Error Handling

The server includes comprehensive error handling for:
- Invalid API keys
- Rate limiting
- Network errors
- Invalid input parameters
- Invalid hash formats
- Invalid IP formats
- Invalid URL formats
- Invalid relationship types
- Pagination errors

## Version History

- v1.0.0: Initial release with core functionality
- v1.1.0: Added relationship analysis tools for URLs, files, and IP addresses
- v1.2.0: Added improved error handling and logging
- v1.3.0: Added pagination support for relationship queries
- v1.4.0: Added automatic relationship fetching in report tools and domain analysis support
- v1.5.0: Migrated to FastMCP framework with HTTP streaming transport support
- v1.6.0: Added `search_vt`, `get_file_behaviour_summary`, `get_collection`, and `get_domain_relationship` tools; synced relationship lists with current VirusTotal v3 docs (drops removed `clues`, adds `collections`/`votes`/`user_votes`/`embedded_js_files`/`urls_related_by_tracker_id` where applicable); `get_url_report` now returns the cached report when available instead of re-scanning on every call; report tools use batched `?relationships=` queries for dramatically fewer API calls

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
