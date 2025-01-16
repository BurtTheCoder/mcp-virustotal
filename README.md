# VirusTotal MCP Server

[![smithery badge](https://smithery.ai/badge/@burtthecoder/mcp-virustotal)](https://smithery.ai/server/@burtthecoder/mcp-virustotal)

A Model Context Protocol (MCP) server for querying the [VirusTotal API](https://www.virustotal.com/). This server provides comprehensive security analysis tools with automatic relationship data fetching. It integrates seamlessly with MCP-compatible applications like [Claude Desktop](https://claude.ai).

<a href="https://glama.ai/mcp/servers/rcbu34kp5c"><img width="380" height="200" src="https://glama.ai/mcp/servers/rcbu34kp5c/badge" /></a>

## Quick Start (Recommended)

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
      "args": ["--experimental-modules", "/absolute/path/to/mcp-virustotal/build/index.js"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your-virustotal-api-key"
      }
    }
  }
}
```

## Features

- **Comprehensive Analysis Reports**: Each analysis tool automatically fetches relevant relationship data along with the basic report, providing a complete security overview in a single request
- **URL Analysis**: Security reports with automatic fetching of contacted domains, downloaded files, and threat actors
- **File Analysis**: Detailed analysis of file hashes including behaviors, dropped files, and network connections
- **IP Analysis**: Security reports with historical data, resolutions, and related threats
- **Domain Analysis**: DNS information, WHOIS data, SSL certificates, and subdomains
- **Detailed Relationship Analysis**: Dedicated tools for querying specific types of relationships with pagination support
- **Rich Formatting**: Clear categorization and presentation of analysis results and relationship data

## Tools

### Report Tools (with Automatic Relationship Fetching)

### 1. URL Report Tool
- Name: `get_url_report`
- Description: Get a comprehensive URL analysis report including security scan results and key relationships (communicating files, contacted domains/IPs, downloaded files, redirects, threat actors)
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
- Description: Query a specific relationship type for a URL with pagination support. Choose from 17 relationship types including analyses, communicating files, contacted domains/IPs, downloaded files, graphs, referrers, redirects, and threat actors
- Parameters:
  * `url` (required): The URL to get relationships for
  * `relationship` (required): Type of relationship to query
    - Available relationships: analyses, comments, communicating_files, contacted_domains, contacted_ips, downloaded_files, graphs, last_serving_ip_address, network_location, referrer_files, referrer_urls, redirecting_urls, redirects_to, related_comments, related_references, related_threat_actors, submissions
  * `limit` (optional, default: 10): Maximum number of related objects to retrieve (1-40)
  * `cursor` (optional): Continuation cursor for pagination

### 2. File Relationship Tool
- Name: `get_file_relationship`
- Description: Query a specific relationship type for a file with pagination support. Choose from 41 relationship types including behaviors, network connections, dropped files, embedded content, execution chains, and threat actors
- Parameters:
  * `hash` (required): MD5, SHA-1 or SHA-256 hash of the file
  * `relationship` (required): Type of relationship to query
    - Available relationships: analyses, behaviours, bundled_files, carbonblack_children, carbonblack_parents, ciphered_bundled_files, ciphered_parents, clues, collections, comments, compressed_parents, contacted_domains, contacted_ips, contacted_urls, dropped_files, email_attachments, email_parents, embedded_domains, embedded_ips, embedded_urls, execution_parents, graphs, itw_domains, itw_ips, itw_urls, memory_pattern_domains, memory_pattern_ips, memory_pattern_urls, overlay_children, overlay_parents, pcap_children, pcap_parents, pe_resource_children, pe_resource_parents, related_references, related_threat_actors, similar_files, submissions, screenshots, urls_for_embedded_js, votes
  * `limit` (optional, default: 10): Maximum number of related objects to retrieve (1-40)
  * `cursor` (optional): Continuation cursor for pagination

### 3. IP Relationship Tool
- Name: `get_ip_relationship`
- Description: Query a specific relationship type for an IP address with pagination support. Choose from 12 relationship types including communicating files, historical SSL certificates, WHOIS records, resolutions, and threat actors
- Parameters:
  * `ip` (required): IP address to analyze
  * `relationship` (required): Type of relationship to query
    - Available relationships: comments, communicating_files, downloaded_files, graphs, historical_ssl_certificates, historical_whois, related_comments, related_references, related_threat_actors, referrer_files, resolutions, urls
  * `limit` (optional, default: 10): Maximum number of related objects to retrieve (1-40)
  * `cursor` (optional): Continuation cursor for pagination

### 4. Domain Relationship Tool
- Name: `get_domain_relationship`
- Description: Query a specific relationship type for a domain with pagination support. Choose from 21 relationship types including SSL certificates, subdomains, historical data, and DNS records
- Parameters:
  * `domain` (required): Domain name to analyze
  * `relationship` (required): Type of relationship to query
    - Available relationships: caa_records, cname_records, comments, communicating_files, downloaded_files, historical_ssl_certificates, historical_whois, immediate_parent, mx_records, ns_records, parent, referrer_files, related_comments, related_references, related_threat_actors, resolutions, soa_records, siblings, subdomains, urls, user_votes
  * `limit` (optional, default: 10): Maximum number of related objects to retrieve (1-40)
  * `cursor` (optional): Continuation cursor for pagination

## Requirements

- Node.js (v18 or later)
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

### Module Loading Issues

If you see ES module loading warnings:
1. For global installation: Use the simple configuration shown in Quick Start
2. For source installation: Ensure you include `--experimental-modules` in the args

## Development

To run in development mode with hot reloading:
```bash
npm run dev
```

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

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
