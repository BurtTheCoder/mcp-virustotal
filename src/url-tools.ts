// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AxiosInstance } from 'axios';
import { GetUrlReportArgsSchema, GetUrlRelationshipArgsSchema } from './schemas/index.js';
import { handleGetUrlReport, handleGetUrlRelationship } from './handlers/url.js';

/**
 * Register all URL analysis tools on the MCP server.
 */
export async function registerUrlTools(server: McpServer, client: AxiosInstance): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const registerTool = (server as any).tool.bind(server) as (
    name: string,
    description: string,
    shape: unknown,
    cb: (args: unknown) => unknown
  ) => void;

  registerTool(
    'get_url_report',
    'Get a comprehensive URL analysis report including security scan results and key relationships ' +
      '(communicating files, contacted domains/IPs, downloaded files, redirects, threat actors). ' +
      'Returns both the basic security analysis and automatically fetched relationship data.',
    GetUrlReportArgsSchema.shape,
    (args: unknown) => handleGetUrlReport(client, args)
  );

  registerTool(
    'get_url_relationship',
    'Query a specific relationship type for a URL with pagination support. ' +
      'Choose from 17 relationship types including analyses, communicating files, contacted domains/IPs, ' +
      'downloaded files, graphs, referrers, redirects, and threat actors. ' +
      'Useful for detailed investigation of specific relationship types.',
    GetUrlRelationshipArgsSchema.shape,
    (args: unknown) => handleGetUrlRelationship(client, args)
  );
}
