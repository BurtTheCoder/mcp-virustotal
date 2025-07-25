#!/usr/bin/env node

import express, { Request, Response } from 'express';
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
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
import { JSONRPCRequest, JSONRPCResponse, JSONRPCMessage } from '@modelcontextprotocol/sdk/types.js';

dotenv.config();

const API_KEY = process.env.VIRUSTOTAL_API_KEY;
if (!API_KEY) throw new Error("VIRUSTOTAL_API_KEY environment variable is required");

// MCP Server Setup
const server = new Server(
  { name: "virustotal-mcp", version: "1.0.0" },
  { capabilities: { tools: { listChanged: true } } }
);

// Register handlers (same as stdio version)
server.setRequestHandler(InitializeRequestSchema, async (request) => {
  logToFile("[HTTP] Received initialize request.");
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
    instructions: `VirusTotal Analysis Server\n\nThis server provides comprehensive security analysis tools using the VirusTotal API. Each analysis tool automatically fetches relevant relationship data (e.g., contacted domains, downloaded files) along with the basic report.\n\nFor more detailed relationship analysis, dedicated relationship tools are available to query specific types of relationships with pagination support.\n\nAvailable Analysis Types:\n- URLs: Security reports and relationships like contacted domains\n- Files: Analysis results and relationships like dropped files\n- IPs: Security reports and relationships like historical data\n- Domains: DNS information and relationships like subdomains\n\nAll tools return formatted results with clear categorization and relationship data.`,
  };
});

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
  logToFile("[HTTP] Registered tools.");
  return { tools };
});

const axiosInstance = axios.create({
  baseURL: 'https://www.virustotal.com/api/v3',
  headers: { 'x-apikey': API_KEY },
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  logToFile(`[HTTP] Tool called: ${request.params.name}`);
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
    logToFile(`[HTTP] Error handling tool call: ${errorMessage}`);
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

// --- Streamable HTTP Transport ---
class StreamableHTTPTransport {
  onclose?: () => void;
  onerror?: (error: Error) => void;
  onmessage?: (message: JSONRPCMessage) => void;

  private responseHandlers: { [id: string]: (response: JSONRPCResponse) => void } = {};

  async send(message: JSONRPCMessage): Promise<void> {
    // For responses, call the response handler
    if ('id' in message && message.id !== undefined) {
      const handler = this.responseHandlers[message.id.toString()];
      if (handler) {
        handler(message as JSONRPCResponse);
        delete this.responseHandlers[message.id.toString()];
      }
    }
  }

  async close(): Promise<void> {
    if (this.onclose) {
      this.onclose();
    }
  }

  // Required by the Transport interface
  async start(): Promise<void> {
    // No-op for HTTP transport
    return;
  }

  // Send a request and wait for response
  async sendRequest(request: JSONRPCRequest): Promise<JSONRPCResponse> {
    return new Promise((resolve, reject) => {
      const id = request.id.toString();
      this.responseHandlers[id] = resolve;
      // Timeout after 30 seconds
      setTimeout(() => {
        if (this.responseHandlers[id]) {
          delete this.responseHandlers[id];
          reject(new Error('Request timeout'));
        }
      }, 30000);
      if (this.onmessage) {
        this.onmessage(request);
      }
    });
  }
}

const transport = new StreamableHTTPTransport();

const app = express();
app.use(express.json());

// POST / (streamable HTTP endpoint)
app.post('/', async (req: Request, res: Response) => {
  logToFile(`[HTTP] POST / received: ${JSON.stringify(req.body)}`);
  console.log(`[HTTP] POST / received: ${JSON.stringify(req.body)}`);
  try {
    const request = req.body as JSONRPCRequest;
    // Send request through the transport and wait for response
    const response = await transport.sendRequest(request);
    logToFile(`[HTTP] Sending response: ${JSON.stringify(response)}`);
    console.log(`[HTTP] Sending response: ${JSON.stringify(response)}`);
    res.json(response);
  } catch (error: any) {
    logToFile(`[HTTP] Error handling request: ${error.message}`);
    console.log(`[HTTP] Error handling request: ${error.message}`);
    res.status(500).json({
      jsonrpc: '2.0',
      error: {
        code: -32603,
        message: 'Internal error',
        data: error.message
      },
      id: req.body?.id || null
    });
  }
});

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString()
  });
});

async function runHttpServer() {
  const port = process.env.PORT || 3001;
  logToFile("[HTTP] Starting VirusTotal MCP Streamable HTTP Server...");
  console.log("[HTTP] Starting VirusTotal MCP Streamable HTTP Server...");
  try {
    await server.connect(transport);
    logToFile("[HTTP] MCP server connected to transport");
    console.log("[HTTP] MCP server connected to transport");
    app.listen(port, () => {
      logToFile(`[HTTP] VirusTotal MCP HTTP Server is running on port ${port}`);
      console.log(`[HTTP] VirusTotal MCP HTTP Server is running on port ${port}`);
      console.log(`[HTTP] Health check: http://localhost:${port}/health`);
      console.log(`[HTTP] MCP endpoint: POST http://localhost:${port}/`);
    });
  } catch (error: any) {
    logToFile(`[HTTP] Error starting HTTP server: ${error.message}`);
    console.log(`[HTTP] Error starting HTTP server: ${error.message}`);
    process.exit(1);
  }
}

process.on('uncaughtException', (error) => {
  logToFile(`[HTTP] Uncaught exception: ${error.message}`);
  console.log(`[HTTP] Uncaught exception: ${error.message}`);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logToFile(`[HTTP] Unhandled rejection: ${reason}`);
  console.log(`[HTTP] Unhandled rejection: ${reason}`);
  process.exit(1);
});

process.on('SIGINT', () => {
  logToFile('[HTTP] Received SIGINT, shutting down gracefully...');
  console.log('[HTTP] Received SIGINT, shutting down gracefully...');
  transport.close();
  process.exit(0);
});

process.on('SIGTERM', () => {
  logToFile('[HTTP] Received SIGTERM, shutting down gracefully...');
  console.log('[HTTP] Received SIGTERM, shutting down gracefully...');
  transport.close();
  process.exit(0);
});

runHttpServer().catch((error: any) => {
  logToFile(`[HTTP] Fatal error: ${error.message}`);
  console.log(`[HTTP] Fatal error: ${error.message}`);
  process.exit(1);
}); 