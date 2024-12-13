# VirusTotal MCP Server

A Model Context Protocol (MCP) server for querying the [VirusTotal API](https://www.virustotal.com/). This server provides tools for scanning URLs, analyzing file hashes, and retrieving IP address reports. It is designed to integrate seamlessly with MCP-compatible applications like [Claude Desktop](https://claude.ai).

## Features

- **URL Scanning**: Submit and analyze URLs for potential security threats
- **File Hash Analysis**: Get detailed analysis results for file hashes
- **IP Reports**: Retrieve comprehensive security analysis reports for IP addresses
- **Relationship Analysis**: Get related objects for URLs, files, and IP addresses

## Tools

### 1. URL Scan Tool
- Name: `scan_url`
- Description: Scan a URL for potential security threats
- Parameters:
  * `url` (required): The URL to scan

### 2. URL Relationship Tool
- Name: `get_url_relationship`
- Description: Get related objects for a URL (e.g., downloaded files, contacted domains)
- Parameters:
  * `url` (required): The URL to get relationships for
  * `relationship` (required): Type of relationship to query
    - Available relationships: analyses, comments, communicating_files, contacted_domains, contacted_ips, downloaded_files, graphs, last_serving_ip_address, network_location, referrer_files, referrer_urls, redirecting_urls, redirects_to, related_comments, related_references, related_threat_actors, submissions
  * `limit` (optional, default: 10): Maximum number of related objects to retrieve
  * `cursor` (optional): Continuation cursor for pagination

### 3. File Hash Analysis Tool
- Name: `scan_file_hash`
- Description: Get analysis results for a file hash
- Parameters:
  * `hash` (required): MD5, SHA-1 or SHA-256 hash of the file

### 4. File Relationship Tool
- Name: `get_file_relationship`
- Description: Get related objects for a file (e.g., dropped files, contacted domains)
- Parameters:
  * `hash` (required): MD5, SHA-1 or SHA-256 hash of the file
  * `relationship` (required): Type of relationship to query
    - Available relationships: analyses, behaviours, bundled_files, carbonblack_children, carbonblack_parents, ciphered_bundled_files, ciphered_parents, clues, collections, comments, compressed_parents, contacted_domains, contacted_ips, contacted_urls, dropped_files, email_attachments, email_parents, embedded_domains, embedded_ips, embedded_urls, execution_parents, graphs, itw_domains, itw_ips, itw_urls, memory_pattern_domains, memory_pattern_ips, memory_pattern_urls, overlay_children, overlay_parents, pcap_children, pcap_parents, pe_resource_children, pe_resource_parents, related_references, related_threat_actors, similar_files, submissions, screenshots, urls_for_embedded_js, votes
  * `limit` (optional, default: 10): Maximum number of related objects to retrieve
  * `cursor` (optional): Continuation cursor for pagination

### 5. IP Report Tool
- Name: `get_ip_report`
- Description: Get security analysis report for an IP address
- Parameters:
  * `ip` (required): IP address to analyze

### 6. IP Relationship Tool
- Name: `get_ip_relationship`
- Description: Get related objects for an IP address (e.g., downloaded files, resolutions)
- Parameters:
  * `ip` (required): IP address to analyze
  * `relationship` (required): Type of relationship to query
    - Available relationships: comments, communicating_files, downloaded_files, graphs, historical_ssl_certificates, historical_whois, related_comments, related_references, related_threat_actors, referrer_files, resolutions, urls
  * `limit` (optional, default: 10): Maximum number of related objects to retrieve
  * `cursor` (optional): Continuation cursor for pagination

## Requirements

- Node.js (v18 or later)
- A valid [VirusTotal API Key](https://www.virustotal.com/gui/my-apikey)

## Setup Guide

### 1. Installation

```bash
git clone <repository_url>
cd mcp-virustotal
npm install
```

### 2. Configuration

Create a `.env` file in the root directory:
```
VIRUSTOTAL_API_KEY=your_virustotal_api_key
```

### 3. Build and Run

```bash
npm run build
npm start
```

### 4. Configure Claude Desktop

There are two ways to configure the VirusTotal MCP server in Claude Desktop:

#### Option 1: Direct Node Execution (Local Development)
```json
{
  "mcpServers": {
    "virustotal": {
      "command": "node",
      "args": ["path/to/mcp-virustotal/build/index.js"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your_virustotal_api_key"
      }
    }
  }
}
```

#### Option 2: NPX Installation (Recommended for Users)
```json
{
  "mcpServers": {
    "virustotal": {
      "command": "npm",
      "args": ["exec", "@burtthecoder/mcp-virustotal"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your_virustotal_api_key"
      }
    }
  }
}
```

The npm exec method automatically downloads and runs the latest version of the package from npm.

Configuration file location:
- Windows: %APPDATA%\Claude\claude_desktop_config.json
- macOS: ~/Library/Application Support/Claude/claude_desktop_config.json

## Usage

1. Start the MCP server:
```bash
npm start
```

2. Launch Claude Desktop and ensure the VirusTotal MCP server is detected
3. Use any of the available tools through the Claude interface

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

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
