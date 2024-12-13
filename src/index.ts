#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  InitializeRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import axios, { AxiosInstance, AxiosError } from 'axios';
import dotenv from "dotenv";
import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import fs from "fs";
import path from "path";
import os from "os";

dotenv.config();

const logFilePath = path.join(os.tmpdir(), "mcp-virustotal-server.log");
const API_KEY = process.env.VIRUSTOTAL_API_KEY;

// Debug logging for API key
logToFile(`API Key status: ${API_KEY ? 'Present' : 'Missing'}`);
if (API_KEY) {
  logToFile(`API Key length: ${API_KEY.length}`);
  logToFile(`API Key preview: ${API_KEY.substring(0, 4)}...${API_KEY.substring(API_KEY.length - 4)}`);
}

if (!API_KEY) {
  throw new Error("VIRUSTOTAL_API_KEY environment variable is required");
}

// Logging Helper Function
function logToFile(message: string) {
  try {
    const timestamp = new Date().toISOString();
    const formattedMessage = `[${timestamp}] ${message}\n`;
    fs.appendFileSync(logFilePath, formattedMessage, "utf8");
    console.error(formattedMessage.trim());
  } catch (error) {
    console.error(`Failed to write to log file: ${error}`);
  }
}

// Common Schema for Pagination
const PaginationSchema = z.object({
  limit: z.number().min(1).max(40).optional().default(10),
  cursor: z.string().optional(),
});

// Tool Schemas
const ScanUrlArgsSchema = z.object({
  url: z.string().url("Must be a valid URL").describe("The URL to scan"),
});

const GetUrlRelationshipArgsSchema = z.object({
  url: z.string().url("Must be a valid URL").describe("The URL to get relationships for"),
  relationship: z.enum([
    "analyses", "comments", "communicating_files", "contacted_domains", 
    "contacted_ips", "downloaded_files", "graphs", "last_serving_ip_address",
    "network_location", "referrer_files", "referrer_urls", "redirecting_urls",
    "redirects_to", "related_comments", "related_references", "related_threat_actors",
    "submissions"
  ]).describe("Type of relationship to query"),
}).merge(PaginationSchema);

const ScanFileHashArgsSchema = z.object({
  hash: z
    .string()
    .regex(/^[a-fA-F0-9]{32,64}$/, "Must be a valid MD5, SHA-1, or SHA-256 hash")
    .describe("MD5, SHA-1 or SHA-256 hash of the file"),
});

const GetFileRelationshipArgsSchema = z.object({
  hash: z
    .string()
    .regex(/^[a-fA-F0-9]{32,64}$/, "Must be a valid MD5, SHA-1, or SHA-256 hash")
    .describe("MD5, SHA-1 or SHA-256 hash of the file"),
  relationship: z.enum([
    "analyses", "behaviours", "bundled_files", "carbonblack_children",
    "carbonblack_parents", "ciphered_bundled_files", "ciphered_parents",
    "clues", "collections", "comments", "compressed_parents", "contacted_domains",
    "contacted_ips", "contacted_urls", "dropped_files", "email_attachments",
    "email_parents", "embedded_domains", "embedded_ips", "embedded_urls",
    "execution_parents", "graphs", "itw_domains", "itw_ips", "itw_urls",
    "memory_pattern_domains", "memory_pattern_ips", "memory_pattern_urls",
    "overlay_children", "overlay_parents", "pcap_children", "pcap_parents",
    "pe_resource_children", "pe_resource_parents", "related_references",
    "related_threat_actors", "similar_files", "submissions", "screenshots",
    "urls_for_embedded_js", "votes"
  ]).describe("Type of relationship to query"),
}).merge(PaginationSchema);

const GetIpReportArgsSchema = z.object({
  ip: z
    .string()
    .ip("Must be a valid IP address")
    .describe("IP address to analyze"),
});

const GetIpRelationshipArgsSchema = z.object({
  ip: z
    .string()
    .ip("Must be a valid IP address")
    .describe("IP address to analyze"),
  relationship: z.enum([
    "comments", "communicating_files", "downloaded_files", "graphs",
    "historical_ssl_certificates", "historical_whois", "related_comments",
    "related_references", "related_threat_actors", "referrer_files",
    "resolutions", "urls"
  ]).describe("Type of relationship to query"),
}).merge(PaginationSchema);

interface VirusTotalErrorResponse {
  error?: {
    message?: string;
  };
}

// Helper Function to Query VirusTotal API
async function queryVirusTotal(axiosInstance: AxiosInstance, endpoint: string, method: 'get' | 'post' = 'get', data?: any) {
  try {
    // Log request details (excluding full API key)
    logToFile(`Making ${method.toUpperCase()} request to: ${endpoint}`);
    logToFile(`Request headers: ${JSON.stringify({
      ...axiosInstance.defaults.headers,
      'x-apikey': '[REDACTED]'
    }, null, 2)}`);
    
    const response = method === 'get' 
      ? await axiosInstance.get(endpoint)
      : await axiosInstance.post(endpoint, data);
    return response.data;
  } catch (error: any) {
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError<VirusTotalErrorResponse>;
      // Log error details
      logToFile(`API Error: ${JSON.stringify({
        status: axiosError.response?.status,
        statusText: axiosError.response?.statusText,
        data: axiosError.response?.data
      }, null, 2)}`);
      throw new Error(`VirusTotal API error: ${
        axiosError.response?.data?.error?.message || axiosError.message
      }`);
    }
    throw error;
  }
}

// Helper function to encode URL for VirusTotal API
function encodeUrlForVt(url: string): string {
  return Buffer.from(url).toString('base64url');
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
    instructions:
      "This server provides tools for scanning and analyzing URLs, files, and IP addresses using the VirusTotal API.",
  };
});

// Register Tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  const tools = [
    {
      name: "scan_url",
      description: "Scan a URL for potential security threats",
      inputSchema: zodToJsonSchema(ScanUrlArgsSchema),
    },
    {
      name: "get_url_relationship",
      description: "Get related objects for a URL (e.g., downloaded files, contacted domains)",
      inputSchema: zodToJsonSchema(GetUrlRelationshipArgsSchema),
    },
    {
      name: "scan_file_hash",
      description: "Get analysis results for a file hash",
      inputSchema: zodToJsonSchema(ScanFileHashArgsSchema),
    },
    {
      name: "get_file_relationship",
      description: "Get related objects for a file (e.g., dropped files, contacted domains)",
      inputSchema: zodToJsonSchema(GetFileRelationshipArgsSchema),
    },
    {
      name: "get_ip_report",
      description: "Get security analysis report for an IP address",
      inputSchema: zodToJsonSchema(GetIpReportArgsSchema),
    },
    {
      name: "get_ip_relationship",
      description: "Get related objects for an IP address (e.g., downloaded files, resolutions)",
      inputSchema: zodToJsonSchema(GetIpRelationshipArgsSchema),
    },
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
      case "scan_url": {
        const parsedArgs = ScanUrlArgsSchema.safeParse(args);
        if (!parsedArgs.success) {
          throw new Error("Invalid URL format");
        }

        logToFile(`Scanning URL: ${parsedArgs.data.url}`);
        
        const scanResponse = await queryVirusTotal(
          axiosInstance,
          '/urls',
          'post',
          new URLSearchParams({ url: parsedArgs.data.url })
        );
        
        const analysisId = scanResponse.data.id;
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        const analysisResponse = await queryVirusTotal(
          axiosInstance,
          `/analyses/${analysisId}`
        );

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                scan_id: analysisId,
                url: parsedArgs.data.url,
                scan_date: new Date().toISOString(),
                results: analysisResponse.data.attributes,
                stats: analysisResponse.data.attributes.stats,
              }, null, 2),
            },
          ],
        };
      }

      case "get_url_relationship": {
        const parsedArgs = GetUrlRelationshipArgsSchema.safeParse(args);
        if (!parsedArgs.success) {
          throw new Error("Invalid arguments for URL relationship query");
        }

        const { url, relationship, limit, cursor } = parsedArgs.data;
        const encodedUrl = encodeUrlForVt(url);
        
        logToFile(`Getting ${relationship} for URL: ${url}`);
        
        const params: Record<string, string | number> = { limit };
        if (cursor) params.cursor = cursor;
        
        const result = await queryVirusTotal(
          axiosInstance,
          `/urls/${encodedUrl}/${relationship}`,
          'get'
        );

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                url,
                relationship,
                data: result.data,
                meta: result.meta,
              }, null, 2),
            },
          ],
        };
      }

      case "scan_file_hash": {
        const parsedArgs = ScanFileHashArgsSchema.safeParse(args);
        if (!parsedArgs.success) {
          throw new Error("Invalid hash format. Must be MD5, SHA-1, or SHA-256");
        }

        logToFile(`Looking up file hash: ${parsedArgs.data.hash}`);
        
        const result = await queryVirusTotal(
          axiosInstance,
          `/files/${parsedArgs.data.hash}`
        );

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                hash: parsedArgs.data.hash,
                scan_date: result.data.attributes.last_analysis_date,
                reputation: result.data.attributes.reputation,
                total_votes: result.data.attributes.total_votes,
                stats: result.data.attributes.last_analysis_stats,
                results: result.data.attributes.last_analysis_results,
              }, null, 2),
            },
          ],
        };
      }

      case "get_file_relationship": {
        const parsedArgs = GetFileRelationshipArgsSchema.safeParse(args);
        if (!parsedArgs.success) {
          throw new Error("Invalid arguments for file relationship query");
        }

        const { hash, relationship, limit, cursor } = parsedArgs.data;
        
        logToFile(`Getting ${relationship} for file hash: ${hash}`);
        
        const params: Record<string, string | number> = { limit };
        if (cursor) params.cursor = cursor;
        
        const result = await queryVirusTotal(
          axiosInstance,
          `/files/${hash}/${relationship}`,
          'get'
        );

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                hash,
                relationship,
                data: result.data,
                meta: result.meta,
              }, null, 2),
            },
          ],
        };
      }

      case "get_ip_report": {
        const parsedArgs = GetIpReportArgsSchema.safeParse(args);
        if (!parsedArgs.success) {
          throw new Error("Invalid IP address format");
        }

        logToFile(`Getting IP report for: ${parsedArgs.data.ip}`);
        
        const result = await queryVirusTotal(
          axiosInstance,
          `/ip_addresses/${parsedArgs.data.ip}`
        );

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                ip: parsedArgs.data.ip,
                as_owner: result.data.attributes.as_owner,
                country: result.data.attributes.country,
                reputation: result.data.attributes.reputation,
                total_votes: result.data.attributes.total_votes,
                last_analysis_stats: result.data.attributes.last_analysis_stats,
                last_analysis_results: result.data.attributes.last_analysis_results,
              }, null, 2),
            },
          ],
        };
      }

      case "get_ip_relationship": {
        const parsedArgs = GetIpRelationshipArgsSchema.safeParse(args);
        if (!parsedArgs.success) {
          throw new Error("Invalid arguments for IP relationship query");
        }

        const { ip, relationship, limit, cursor } = parsedArgs.data;
        
        logToFile(`Getting ${relationship} for IP: ${ip}`);
        
        const params: Record<string, string | number> = { limit };
        if (cursor) params.cursor = cursor;
        
        const result = await queryVirusTotal(
          axiosInstance,
          `/ip_addresses/${ip}/${relationship}`,
          'get'
        );

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                ip,
                relationship,
                data: result.data,
                meta: result.meta,
              }, null, 2),
            },
          ],
        };
      }

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
