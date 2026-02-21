// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { AxiosInstance } from 'axios';
import { GetDomainReportArgsSchema } from './schemas/index.js';
import { handleGetDomainReport } from './handlers/domain.js';

/**
 * Register all domain analysis tools on the MCP server.
 */
export async function registerDomainTools(server: McpServer, client: AxiosInstance): Promise<void> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const registerTool = (server as any).tool.bind(server) as (
    name: string,
    description: string,
    shape: unknown,
    cb: (args: unknown) => unknown
  ) => void;

  registerTool(
    'get_domain_report',
    'Get a comprehensive domain analysis report including DNS records, WHOIS data, ' +
      'and key relationships (SSL certificates, subdomains, historical data). ' +
      'Optionally specify which relationships to include in the report. ' +
      'Returns both the basic analysis and relationship data.',
    GetDomainReportArgsSchema.shape,
    (args: unknown) => handleGetDomainReport(client, args)
  );
}
