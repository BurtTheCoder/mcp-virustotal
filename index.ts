#!/usr/bin/env node
// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import express from 'express';
import { randomUUID } from 'crypto';
import axios from 'axios';
import {
  VirusTotalError,
  VirusTotalConfig,
  VirusTotalConfigSchema,
  ServerCreationOptions,
} from './src/types.js';
import { registerUrlTools } from './src/url-tools.js';
import { registerFileTools } from './src/file-tools.js';
import { registerIpTools } from './src/ip-tools.js';
import { registerDomainTools } from './src/domain-tools.js';

/**
 * Create an axios instance configured for the VirusTotal API.
 *
 * Auth header priority:
 *   1. apiKey  → x-apikey  (direct VT API access)
 *   2. authToken → Authorization: Bearer  (proxy / gateway access)
 */
function createVirusTotalClient(config: VirusTotalConfig) {
  const baseURL = config.baseUrl ?? 'https://www.virustotal.com/api/v3';
  const headers: Record<string, string> = {};

  if (config.apiKey) {
    headers['x-apikey'] = config.apiKey;
  } else if (config.authToken) {
    headers['Authorization'] = `Bearer ${config.authToken}`;
  } else {
    throw new VirusTotalError(
      'No credentials configured. Set VIRUSTOTAL_API_KEY for direct access ' +
        'or VIRUSTOTAL_AUTH_TOKEN for proxy access.'
    );
  }

  return axios.create({
    baseURL,
    headers,
    timeout: config.timeout,
  });
}

/**
 * Create and configure a VirusTotal MCP server instance with all tool modules registered.
 */
export async function createVirusTotalMcpServer(
  options: ServerCreationOptions
): Promise<McpServer> {
  const { name, version, config, description } = options;

  const validatedConfig = VirusTotalConfigSchema.parse(config);
  const client = createVirusTotalClient(validatedConfig);

  const server = new McpServer({
    name,
    version,
    ...(description ? { description } : {}),
  });

  await Promise.all([
    registerUrlTools(server, client),
    registerFileTools(server, client),
    registerIpTools(server, client),
    registerDomainTools(server, client),
  ]);

  return server;
}

// Main entry point
async function main(): Promise<void> {
  const config: VirusTotalConfig = {
    apiKey: process.env.VIRUSTOTAL_API_KEY,
    baseUrl: process.env.VIRUSTOTAL_BASE_URL,
    authToken: process.env.VIRUSTOTAL_AUTH_TOKEN,
    timeout: parseInt(process.env.VIRUSTOTAL_TIMEOUT ?? '30000', 10),
  };

  const SERVER_NAME = 'virustotal-mcp-server';
  const SERVER_VERSION = '1.1.0';
  const SERVER_DESCRIPTION = 'VirusTotal MCP Server – security analysis for URLs, files, IPs and domains';

  const useHttp = process.env.MCP_TRANSPORT === 'http';
  const httpPort = parseInt(process.env.MCP_HTTP_PORT ?? '3000', 10);
  const httpHost = process.env.MCP_HTTP_HOST ?? 'localhost';

  if (useHttp) {
    // HTTP Streamable mode – suitable for remote / multi-client deployments
    process.stderr.write(
      `Starting VirusTotal MCP Server in HTTP mode on ${httpHost}:${httpPort}\n`
    );

    const app = express();
    app.use(express.json());

    const transports = new Map<string, StreamableHTTPServerTransport>();

    app.get('/health', (_req, res) => {
      res.json({ status: 'ok', transport: 'streamable-http' });
    });

    app.post('/mcp', async (req, res) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;

      try {
        let transport: StreamableHTTPServerTransport;

        if (sessionId !== undefined && transports.has(sessionId)) {
          transport = transports.get(sessionId)!;
        } else {
          transport = new StreamableHTTPServerTransport({
            sessionIdGenerator: () => randomUUID(),
            onsessioninitialized: async (newSessionId: string) => {
              transports.set(newSessionId, transport);
              process.stderr.write(`MCP session initialized: ${newSessionId}\n`);
            },
            onsessionclosed: async (closedSessionId: string) => {
              transports.delete(closedSessionId);
              process.stderr.write(`MCP session closed: ${closedSessionId}\n`);
            },
          });

          const server = await createVirusTotalMcpServer({
            name: SERVER_NAME,
            version: SERVER_VERSION,
            config,
            description: SERVER_DESCRIPTION,
          });

          await server.connect(transport);
        }

        await transport.handleRequest(req, res, req.body);
      } catch (error) {
        process.stderr.write(`Error handling MCP request: ${error}\n`);
        if (!res.headersSent) {
          res.status(500).json({
            jsonrpc: '2.0',
            error: { code: -32603, message: 'Internal server error' },
            id: null,
          });
        }
      }
    });

    app.get('/mcp', async (req, res) => {
      const sessionId = req.headers['mcp-session-id'] as string | undefined;

      if (sessionId === undefined || !transports.has(sessionId)) {
        res.status(400).json({
          jsonrpc: '2.0',
          error: { code: -32000, message: 'Invalid or missing session ID' },
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
            error: { code: -32603, message: 'Failed to establish SSE stream' },
            id: null,
          });
        }
      }
    });

    app.listen(httpPort, httpHost, () => {
      process.stderr.write(
        `VirusTotal MCP Server (HTTP mode) started on http://${httpHost}:${httpPort}\n`
      );
    });

    process.on('SIGINT', async () => {
      for (const [, transport] of transports.entries()) {
        await transport.close();
      }
      process.exit(0);
    });
  } else {
    // Stdio mode (default) – for local MCP client integrations
    process.stderr.write('Starting VirusTotal MCP Server in Stdio mode\n');

    const server = await createVirusTotalMcpServer({
      name: SERVER_NAME,
      version: SERVER_VERSION,
      config,
      description: SERVER_DESCRIPTION,
    });

    const transport = new StdioServerTransport();
    await server.connect(transport);

    process.on('SIGINT', async () => {
      await server.close();
      process.exit(0);
    });
  }
}

main().catch((error: unknown) => {
  process.stderr.write(
    `Fatal error: ${error instanceof Error ? error.message : String(error)}\n`
  );
  process.exit(1);
});
