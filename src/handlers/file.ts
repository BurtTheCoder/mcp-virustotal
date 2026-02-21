// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { AxiosInstance } from 'axios';
import { queryVirusTotal } from '../utils/api.js';
import { formatFileResults } from '../formatters/index.js';
import { GetFileReportArgsSchema, GetFileRelationshipArgsSchema } from '../schemas/index.js';
import { logToFile } from '../utils/logging.js';
import { RelationshipData } from '../types/virustotal.js';

const DEFAULT_FILE_RELATIONSHIPS = [
  'behaviours',
  'contacted_domains',
  'contacted_ips',
  'contacted_urls',
  'dropped_files',
  'execution_parents',
  'embedded_domains',
  'embedded_ips',
  'embedded_urls',
  'itw_domains',
  'itw_ips',
  'itw_urls',
  'related_threat_actors',
  'similar_files',
] as const;

export async function handleGetFileReport(client: AxiosInstance, args: unknown) {
  const parsedArgs = GetFileReportArgsSchema.safeParse(args);
  if (!parsedArgs.success) {
    throw new Error('Invalid hash format. Must be MD5, SHA-1, or SHA-256');
  }

  const { hash } = parsedArgs.data;

  logToFile(`Fetching file report: ${hash}`);
  const basicReport = (await queryVirusTotal(client, `/files/${hash}`)) as {
    data: { attributes: unknown; id?: string; type?: string };
  };

  const relationshipData: Record<string, RelationshipData> = {};

  for (const relType of DEFAULT_FILE_RELATIONSHIPS) {
    logToFile(`Fetching relationship: ${relType}`);
    try {
      const response = (await queryVirusTotal(client, `/files/${hash}/${relType}`)) as {
        data: RelationshipData['data'];
        meta?: RelationshipData['meta'];
      };

      if (response.data) {
        relationshipData[relType] = { data: response.data, meta: response.meta };
      }
    } catch {
      logToFile(`Skipping ${relType} – fetch failed`);
    }
  }

  const combinedData = {
    id: basicReport.data.id,
    attributes: basicReport.data.attributes as Parameters<typeof formatFileResults>[0]['attributes'],
    relationships: relationshipData,
  };

  return { content: [formatFileResults(combinedData)] };
}

export async function handleGetFileRelationship(client: AxiosInstance, args: unknown) {
  const parsedArgs = GetFileRelationshipArgsSchema.safeParse(args);
  if (!parsedArgs.success) {
    throw new Error('Invalid arguments for file relationship query');
  }

  const { hash, relationship, limit, cursor } = parsedArgs.data;

  const params: Record<string, string | number> = {};
  if (limit != null) params.limit = limit;
  if (cursor) params.cursor = cursor;

  logToFile(`Fetching ${relationship} for file: ${hash}`);
  const result = (await queryVirusTotal(client, `/files/${hash}/${relationship}`, 'get', undefined, params)) as {
    data: { attributes: unknown };
    meta?: RelationshipData['meta'];
  };

  return {
    content: [
      formatFileResults({
        id: hash,
        attributes: result.data.attributes as Parameters<typeof formatFileResults>[0]['attributes'],
        relationships: {
          [relationship]: { data: result.data as RelationshipData['data'], meta: result.meta },
        },
      }),
    ],
  };
}
