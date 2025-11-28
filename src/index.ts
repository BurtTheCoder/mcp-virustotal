#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  InitializeRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import axios from 'axios';
import dotenv from "dotenv";
import express, { Request, Response } from "express";
import { randomUUID } from "crypto";
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

// Create axios instance
const axiosInstance = axios.create({
  baseURL: 'https://www.virustotal.com/api/v3',
  headers: {
    'x-apikey': API_KEY,
  },
});

// Create and configure MCP Server
async function createVirusTotalMcpServer() {
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

  return server;
}

// Main function to start server
async function main() {
  try {
    // Check if HTTP transport mode is enabled
    const useHttp = process.env.MCP_TRANSPORT === 'http';
    const httpPort = parseInt(process.env.MCP_HTTP_PORT || '3000');
    const httpHost = process.env.MCP_HTTP_HOST || 'localhost';

    if (useHttp) {
      // HTTP Streamable Mode - Use Streamable HTTP Transport
      process.stderr.write(`Starting VirusTotal MCP Server in HTTP Streamable mode on ${httpHost}:${httpPort}\n`);
      
      const app = express();
      app.use(express.json());
      
      // Store active transports by session ID
      const transports = new Map<string, StreamableHTTPServerTransport>();

      // Health check endpoint
      app.get('/health', (req: Request, res: Response) => {
        res.json({ 
          status: 'ok', 
          transport: 'streamable-http',
          api_key_configured: !!API_KEY
        });
      });

      // MCP endpoint - POST for JSON-RPC requests
      app.post('/mcp', async (req: Request, res: Response) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        
        try {
          let transport: StreamableHTTPServerTransport;

          // Check if we have an existing session
          if (sessionId && transports.has(sessionId)) {
            transport = transports.get(sessionId)!;
          } else {
            // Create new transport for new session
            transport = new StreamableHTTPServerTransport({
              sessionIdGenerator: () => randomUUID(),
              onsessioninitialized: async (newSessionId: string) => {
                transports.set(newSessionId, transport);
                process.stderr.write(`New MCP session initialized: ${newSessionId}\n`);
              },
              onsessionclosed: async (closedSessionId: string) => {
                transports.delete(closedSessionId);
                process.stderr.write(`MCP session closed: ${closedSessionId}\n`);
              }
            });

            // Create server for this transport
            const server = await createVirusTotalMcpServer();
            await server.connect(transport);
          }

          // Handle the request
          await transport.handleRequest(req, res, req.body);
        } catch (error) {
          process.stderr.write(`Error handling MCP request: ${error}\n`);
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: '2.0',
              error: {
                code: -32603,
                message: 'Internal server error',
              },
              id: null,
            });
          }
        }
      });

      // MCP endpoint - GET for SSE streams
      app.get('/mcp', async (req: Request, res: Response) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        
        if (!sessionId || !transports.has(sessionId)) {
          res.status(400).json({
            jsonrpc: '2.0',
            error: {
              code: -32000,
              message: 'Invalid or missing session ID',
            },
            id: null,
          });
          return;
        }

        try {
          const transport = transports.get(sessionId)!;
          await transport.handleRequest(req, res);
        } catch (error) {
          process.stderr.write(`Error handling SSE stream: ${error}\n`);
          if (!res.headersSent) {
            res.status(500).json({
              jsonrpc: '2.0',
              error: {
                code: -32603,
                message: 'Failed to establish SSE stream',
              },
              id: null,
            });
          }
        }
      });

      // Start HTTP server
      app.listen(httpPort, httpHost, () => {
        console.log(`\n✓ VirusTotal MCP Server (HTTP Streamable Mode) is running`);
        console.log(`  Endpoint: http://${httpHost}:${httpPort}/mcp`);
        console.log(`  Health: http://${httpHost}:${httpPort}/health`);
        console.log(`  Transport: Streamable HTTP\n`);
      });

      // Handle process termination
      process.on("SIGINT", async () => {
        console.log("\nShutting down server...");
        for (const [sessionId, transport] of transports.entries()) {
          await transport.close();
        }
        process.exit(0);
      });

    } else {
      // Stdio Mode (Default) - Use Stdio Transport
      process.stderr.write(`Starting VirusTotal MCP Server in Stdio mode\n`);
      logToFile("Starting VirusTotal MCP Server...");
      
      const transport = new StdioServerTransport();
      const server = await createVirusTotalMcpServer();

      await server.connect(transport);
      logToFile("VirusTotal MCP Server is running.");

      // Handle process termination
      process.on("SIGINT", async () => {
        await server.close();
        process.exit(0);
      });
    }
    
  } catch (error) {
    console.error("Fatal error:", error);
    logToFile(`Fatal error: ${error instanceof Error ? error.message : String(error)}`);
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

main().catch((error: any) => {
  logToFile(`Fatal error: ${error.message}`);
  process.exit(1);
});
