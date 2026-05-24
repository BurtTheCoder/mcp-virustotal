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
  GetFileBehaviourSummaryArgsSchema,
  GetIpReportArgsSchema,
  GetIpRelationshipArgsSchema,
  GetDomainReportArgsSchema,
  GetDomainRelationshipArgsSchema,
  SearchArgsSchema,
  GetCollectionArgsSchema,
} from './schemas/index.js';
import {
  handleGetUrlReport,
  handleGetUrlRelationship,
  handleGetFileReport,
  handleGetFileRelationship,
  handleGetFileBehaviourSummary,
  handleGetIpReport,
  handleGetIpRelationship,
  handleGetDomainReport,
  handleGetDomainRelationship,
  handleSearch,
  handleGetCollection,
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

Tools for querying the VirusTotal API. Pick a tool by what you have and what you need:

Direct lookups (you already have an IOC):
- get_url_report, get_file_report, get_ip_report, get_domain_report
  Each returns the full report plus a curated set of relationship summaries (e.g. contacted domains, dropped files, resolutions) in one call.

Targeted relationship queries (you need more items of one relationship type, with pagination):
- get_url_relationship, get_file_relationship, get_ip_relationship, get_domain_relationship
  Use these when the relationship summary in the *_report tools is truncated and you need to page through the full list.

Pivot tools (you don't have an IOC yet, or you want richer detail):
- search_vt — search the VirusTotal corpus by IOC, free text, or VTI modifier syntax. Use when the user gives you a fragment (filename, partial hash, comment text) or wants to hunt for files matching properties (type, size, detection count).
- get_file_behaviour_summary — consolidated sandbox view (processes, network, registry, MITRE ATT&CK, IDS) for one file hash. Prefer over the 'behaviours' relationship when you want an analyst-friendly summary instead of per-sandbox raw data.
- get_collection — fetch a threat-actor, malware-family, campaign, or intel-report object by ID. IDs come from the 'related_threat_actors' and 'collections' relationships on the other tools.

All tools return formatted text with clear categorization.`,
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
  description: `Query a specific relationship type for a URL with pagination support. Choose from ${RELATIONSHIPS.url.length} relationship types including communicating files, contacted domains/IPs, downloaded files, redirects, referrers, threat actors, and collections. Useful for paging through the full list when the summary in get_url_report is truncated.`,
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

server.addTool({
  name: 'get_domain_relationship',
  description: `Query a specific relationship type for a domain with pagination support. Choose from ${RELATIONSHIPS.domain.length} relationship types including subdomains, resolutions, SSL certificates, WHOIS history, and threat actors. Useful for detailed investigation of specific relationship types.`,
  parameters: GetDomainRelationshipArgsSchema,
  execute: async (args) => handleGetDomainRelationship(args),
});

server.addTool({
  name: 'search_vt',
  description:
    'Search the VirusTotal corpus for files, URLs, domains, IPs, or comments matching a query. Accepts plain IOCs (hash, URL, domain, IP), free text against comments, or VTI-style search modifiers like "type:peexe size:90kb+ tag:signed positives:5+". Paginated via cursor.',
  parameters: SearchArgsSchema,
  execute: async (args) => handleSearch(args),
});

server.addTool({
  name: 'get_file_behaviour_summary',
  description:
    'Get a consolidated sandbox behaviour summary for a file (MD5/SHA-1/SHA-256), merged across every sandbox that analyzed it. Returns processes, files, registry, network activity, MITRE ATT&CK techniques, IDS alerts, and signature matches in a single view — far more useful than iterating individual behaviour reports.',
  parameters: GetFileBehaviourSummaryArgsSchema,
  execute: async (args) => handleGetFileBehaviourSummary(args),
});

server.addTool({
  name: 'get_collection',
  description:
    'Retrieve a VirusTotal collection by ID. Collections represent threat actors, malware families, campaigns, intel reports, and curated IOC sets — often referenced from the related_threat_actors and collections relationships on other tools. Optionally include relationships (files, urls, domains, ip_addresses, references, threat_actors, related_collections, related_references, comments, owner, autogenerated_graphs) to fetch member IOCs in the same call.',
  parameters: GetCollectionArgsSchema,
  execute: async (args) => handleGetCollection(args),
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
