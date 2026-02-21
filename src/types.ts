// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { z } from 'zod';

/**
 * Custom error class for VirusTotal API errors.
 */
export class VirusTotalError extends Error {
  public readonly statusCode?: number;
  public readonly details?: unknown;

  constructor(message: string, statusCode?: number, details?: unknown) {
    super(message);
    this.name = 'VirusTotalError';
    this.statusCode = statusCode;
    this.details = details;
  }
}

/**
 * VirusTotal client configuration schema.
 *
 * Supports two authentication patterns:
 *   - Direct:  Set VIRUSTOTAL_API_KEY.  Requests are sent to the official VT API.
 *   - Proxied: Set VIRUSTOTAL_BASE_URL (proxy endpoint) and VIRUSTOTAL_AUTH_TOKEN
 *              (Bearer token accepted by the proxy).  The proxy injects the real API key.
 *
 * The tool itself is agnostic to which pattern is in use.
 */
export const VirusTotalConfigSchema = z.object({
  apiKey: z
    .string()
    .optional()
    .describe('VirusTotal API key sent as x-apikey header (direct mode)'),
  baseUrl: z
    .string()
    .optional()
    .describe(
      'Override the VirusTotal API base URL. ' +
        'Defaults to https://www.virustotal.com/api/v3. ' +
        'Set this to a proxy endpoint to route requests through a backend.'
    ),
  authToken: z
    .string()
    .optional()
    .describe(
      'Bearer token sent as Authorization header when using a proxy base URL. ' +
        'Ignored when apiKey is set.'
    ),
  timeout: z.number().optional().default(30000).describe('Request timeout in milliseconds'),
});

export type VirusTotalConfig = z.infer<typeof VirusTotalConfigSchema>;

/**
 * Options for creating a VirusTotal MCP server instance.
 */
export interface ServerCreationOptions {
  name: string;
  version: string;
  config: VirusTotalConfig;
  description?: string;
}
