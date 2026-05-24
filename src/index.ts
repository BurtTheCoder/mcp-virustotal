#!/usr/bin/env node

import { FastMCP } from 'fastmcp';
import dotenv from 'dotenv';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { logToFile } from './utils/logging.js';
import { initVirusTotalClient, RELATIONSHIPS } from './utils/api.js';
import {
  GetUrlReportArgsSchema,
  GetUrlRelationshipArgsSchema,
  GetFileReportArgsSchema,
  GetFileRelationshipArgsSchema,
  GetIpReportArgsSchema,
  GetIpRelationshipArgsSchema,
  GetDomainReportArgsSchema,
} from './schemas/index.js';
import {
  handleGetUrlReport,
  handleGetUrlRelationship,
  handleGetFileReport,
  handleGetFileRelationship,
  handleGetIpReport,
  handleGetIpRelationship,
  handleGetDomainReport,
} from './handlers/index.js';

dotenv.config();

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(
  readFileSync(join(__dirname, '..', 'package.json'), 'utf8'),
) as { version: string };

const server = new FastMCP({
  name: 'virustotal-mcp',
  version: pkg.version as `${number}.${number}.${number}`,
  instructions: `VirusTotal Analysis Server

This server provides comprehensive security analysis tools using the VirusTotal API. Each analysis tool automatically fetches relevant relationship data (e.g., contacted domains, downloaded files) along with the basic report.

For more detailed relationship analysis, dedicated relationship tools are available to query specific types of relationships with pagination support.

Available Analysis Types:
- URLs: Security reports and relationships like contacted domains
- Files: Analysis results and relationships like dropped files
- IPs: Security reports and relationships like historical data
- Domains: DNS information and relationships like subdomains

All tools return formatted results with clear categorization and relationship data.`,
});

server.addTool({
  name: 'get_url_report',
  description:
    'Get a comprehensive URL analysis report including security scan results and key relationships (communicating files, contacted domains/IPs, downloaded files, redirects, threat actors). Returns the cached VirusTotal report when available, or submits the URL for scanning and waits for results.',
  parameters: GetUrlReportArgsSchema,
  execute: async (args) => handleGetUrlReport(args),
});

server.addTool({
  name: 'get_url_relationship',
  description: `Query a specific relationship type for a URL with pagination support. Choose from ${RELATIONSHIPS.url.length} relationship types. Useful for detailed investigation of specific relationship types.`,
  parameters: GetUrlRelationshipArgsSchema,
  execute: async (args) => handleGetUrlRelationship(args),
});

server.addTool({
  name: 'get_file_report',
  description:
    'Get a comprehensive file analysis report using its hash (MD5/SHA-1/SHA-256). Includes detection results, file properties, and key relationships (behaviors, dropped files, network connections, embedded content, threat actors). Returns both the basic analysis and automatically fetched relationship data.',
  parameters: GetFileReportArgsSchema,
  execute: async (args) => handleGetFileReport(args),
});

server.addTool({
  name: 'get_file_relationship',
  description: `Query a specific relationship type for a file with pagination support. Choose from ${RELATIONSHIPS.file.length} relationship types including behaviors, network connections, dropped files, embedded content, execution chains, and threat actors. Useful for detailed investigation of specific relationship types.`,
  parameters: GetFileRelationshipArgsSchema,
  execute: async (args) => handleGetFileRelationship(args),
});

server.addTool({
  name: 'get_ip_report',
  description:
    'Get a comprehensive IP address analysis report including geolocation, reputation data, and key relationships (communicating files, historical certificates/WHOIS, resolutions). Returns both the basic analysis and automatically fetched relationship data.',
  parameters: GetIpReportArgsSchema,
  execute: async (args) => handleGetIpReport(args),
});

server.addTool({
  name: 'get_ip_relationship',
  description: `Query a specific relationship type for an IP address with pagination support. Choose from ${RELATIONSHIPS.ip.length} relationship types including communicating files, historical SSL certificates, WHOIS records, resolutions, and threat actors. Useful for detailed investigation of specific relationship types.`,
  parameters: GetIpRelationshipArgsSchema,
  execute: async (args) => handleGetIpRelationship(args),
});

server.addTool({
  name: 'get_domain_report',
  description:
    'Get a comprehensive domain analysis report including DNS records, WHOIS data, and key relationships (SSL certificates, subdomains, historical data). Optionally specify which relationships to include in the report. Returns both the basic analysis and relationship data.',
  parameters: GetDomainReportArgsSchema,
  execute: async (args) => handleGetDomainReport(args),
});

process.on('uncaughtException', (error) => {
  logToFile(`Uncaught exception: ${error.message}`);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logToFile(`Unhandled rejection: ${reason}`);
  process.exit(1);
});

async function main() {
  initVirusTotalClient();

  const transport = process.env.MCP_TRANSPORT || 'stdio';
  logToFile(`Starting VirusTotal MCP Server (transport: ${transport})...`);

  if (transport === 'httpStream') {
    const port = parseInt(process.env.MCP_PORT || '3000', 10);
    const endpoint = (process.env.MCP_ENDPOINT || '/mcp') as `/${string}`;

    await server.start({
      transportType: 'httpStream',
      httpStream: { port, endpoint },
    });

    logToFile(`VirusTotal MCP Server listening on port ${port} at ${endpoint}`);
  } else {
    await server.start({ transportType: 'stdio' });
    logToFile('VirusTotal MCP Server is running on stdio.');
  }
}

main().catch((error) => {
  logToFile(`Fatal error: ${error.message}`);
  process.exit(1);
});
