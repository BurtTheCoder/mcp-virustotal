#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  InitializeRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import axios from 'axios';
import dotenv from "dotenv";
import { zodToJsonSchema } from "zod-to-json-schema";
import { logToFile } from './utils/logging.js';
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

const API_KEY = process.env.VIRUSTOTAL_API_KEY;

if (!API_KEY) {
  throw new Error("VIRUSTOTAL_API_KEY environment variable is required");
}

// Server Setup
const server = new Server(
  {
    name: "virustotal-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {
        listChanged: true,
      },
    },
  }
);

// Handle Initialization
server.setRequestHandler(InitializeRequestSchema, async (request) => {
  logToFile("Received initialize request.");
  return {
    protocolVersion: "2024-11-05",
    capabilities: {
      tools: {
        listChanged: true,
      },
    },
    serverInfo: {
      name: "virustotal-mcp",
      version: "1.0.0",
    },
    instructions: `VirusTotal Analysis Server

This server provides comprehensive security analysis tools using the VirusTotal API. Each analysis tool automatically fetches relevant relationship data (e.g., contacted domains, downloaded files) along with the basic report.

For more detailed relationship analysis, dedicated relationship tools are available to query specific types of relationships with pagination support.

Available Analysis Types:
- URLs: Security reports and relationships like contacted domains
- Files: Analysis results and relationships like dropped files
- IPs: Security reports and relationships like historical data
- Domains: DNS information and relationships like subdomains

All tools return formatted results with clear categorization and relationship data.`,
  };
});

// Register Tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  const tools = [
    {
      name: "get_url_report",
      description: "Get a comprehensive URL analysis report including security scan results and key relationships (communicating files, contacted domains/IPs, downloaded files, redirects, threat actors). Returns both the basic security analysis and automatically fetched relationship data.",
      inputSchema: zodToJsonSchema(GetUrlReportArgsSchema),
    },
    {
      name: "get_url_relationship",
      description: "Query a specific relationship type for a URL with pagination support. Choose from 17 relationship types including analyses, communicating files, contacted domains/IPs, downloaded files, graphs, referrers, redirects, and threat actors. Useful for detailed investigation of specific relationship types.",
      inputSchema: zodToJsonSchema(GetUrlRelationshipArgsSchema),
    },
    {
      name: "get_file_report",
      description: "Get a comprehensive file analysis report using its hash (MD5/SHA-1/SHA-256). Includes detection results, file properties, and key relationships (behaviors, dropped files, network connections, embedded content, threat actors). Returns both the basic analysis and automatically fetched relationship data.",
      inputSchema: zodToJsonSchema(GetFileReportArgsSchema),
    },
    {
      name: "get_file_relationship",
      description: "Query a specific relationship type for a file with pagination support. Choose from 41 relationship types including behaviors, network connections, dropped files, embedded content, execution chains, and threat actors. Useful for detailed investigation of specific relationship types.",
      inputSchema: zodToJsonSchema(GetFileRelationshipArgsSchema),
    },
    {
      name: "get_ip_report",
      description: "Get a comprehensive IP address analysis report including geolocation, reputation data, and key relationships (communicating files, historical certificates/WHOIS, resolutions). Returns both the basic analysis and automatically fetched relationship data.",
      inputSchema: zodToJsonSchema(GetIpReportArgsSchema),
    },
    {
      name: "get_ip_relationship",
      description: "Query a specific relationship type for an IP address with pagination support. Choose from 12 relationship types including communicating files, historical SSL certificates, WHOIS records, resolutions, and threat actors. Useful for detailed investigation of specific relationship types.",
      inputSchema: zodToJsonSchema(GetIpRelationshipArgsSchema),
    },
    {
      name: "get_domain_report",
      description: "Get a comprehensive domain analysis report including DNS records, WHOIS data, and key relationships (SSL certificates, subdomains, historical data). Optionally specify which relationships to include in the report. Returns both the basic analysis and relationship data.",
      inputSchema: zodToJsonSchema(GetDomainReportArgsSchema),
    }
  ];

  logToFile("Registered tools.");
  return { tools };
});

// Create axios instance
const axiosInstance = axios.create({
  baseURL: 'https://www.virustotal.com/api/v3',
  headers: {
    'x-apikey': API_KEY,
  },
});

// Handle Tool Calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  logToFile(`Tool called: ${request.params.name}`);

  try {
    const { name, arguments: args } = request.params;

    switch (name) {
      case "get_url_report":
        return await handleGetUrlReport(axiosInstance, args);

      case "get_url_relationship":
        return await handleGetUrlRelationship(axiosInstance, args);

      case "get_file_report":
        return await handleGetFileReport(axiosInstance, args);

      case "get_file_relationship":
        return await handleGetFileRelationship(axiosInstance, args);

      case "get_ip_report":
        return await handleGetIpReport(axiosInstance, args);

      case "get_ip_relationship":
        return await handleGetIpRelationship(axiosInstance, args);

      case "get_domain_report":
        return await handleGetDomainReport(axiosInstance, args);

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error: any) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    logToFile(`Error handling tool call: ${errorMessage}`);
    return {
      content: [
        {
          type: "text",
          text: `Error: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
});

// Start the Server
async function runServer() {
  logToFile("Starting VirusTotal MCP Server...");

  try {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    logToFile("VirusTotal MCP Server is running.");
  } catch (error: any) {
    logToFile(`Error connecting server: ${error.message}`);
    process.exit(1);
  }
}

// Handle process events
process.on('uncaughtException', (error) => {
  logToFile(`Uncaught exception: ${error.message}`);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logToFile(`Unhandled rejection: ${reason}`);
  process.exit(1);
});

runServer().catch((error: any) => {
  logToFile(`Fatal error: ${error.message}`);
  process.exit(1);
});
