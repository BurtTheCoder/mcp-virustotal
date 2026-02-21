// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { AxiosInstance } from 'axios';
import { queryVirusTotal } from '../utils/api.js';
import { formatIpResults } from '../formatters/index.js';
import { GetIpReportArgsSchema, GetIpRelationshipArgsSchema } from '../schemas/index.js';
import { logToFile } from '../utils/logging.js';
import { RelationshipData } from '../types/virustotal.js';

const DEFAULT_IP_RELATIONSHIPS = [
  'communicating_files',
  'downloaded_files',
  'historical_ssl_certificates',
  'resolutions',
  'related_threat_actors',
  'urls',
] as const;

export async function handleGetIpReport(client: AxiosInstance, args: unknown) {
  const parsedArgs = GetIpReportArgsSchema.safeParse(args);
  if (!parsedArgs.success) {
    throw new Error('Invalid IP address format');
  }

  const { ip } = parsedArgs.data;

  logToFile(`Fetching IP report: ${ip}`);
  const basicReport = (await queryVirusTotal(client, `/ip_addresses/${ip}`)) as {
    data: { attributes: unknown; id?: string; type?: string };
  };

  const relationshipData: Record<string, RelationshipData> = {};

  for (const relType of DEFAULT_IP_RELATIONSHIPS) {
    logToFile(`Fetching relationship: ${relType}`);
    try {
      const response = (await queryVirusTotal(client, `/ip_addresses/${ip}/${relType}`)) as {
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
    attributes: basicReport.data.attributes as Parameters<typeof formatIpResults>[0]['attributes'],
    relationships: relationshipData,
  };

  return { content: [formatIpResults(combinedData)] };
}

export async function handleGetIpRelationship(client: AxiosInstance, args: unknown) {
  const parsedArgs = GetIpRelationshipArgsSchema.safeParse(args);
  if (!parsedArgs.success) {
    throw new Error('Invalid arguments for IP relationship query');
  }

  const { ip, relationship, limit, cursor } = parsedArgs.data;

  const params: Record<string, string | number> = {};
  if (limit != null) params.limit = limit;
  if (cursor) params.cursor = cursor;

  logToFile(`Fetching ${relationship} for IP: ${ip}`);
  const result = (await queryVirusTotal(client, `/ip_addresses/${ip}/${relationship}`, 'get', undefined, params)) as {
    data: { attributes: unknown };
    meta?: RelationshipData['meta'];
  };

  return {
    content: [
      formatIpResults({
        id: ip,
        attributes: result.data.attributes as Parameters<typeof formatIpResults>[0]['attributes'],
        relationships: {
          [relationship]: { data: result.data as RelationshipData['data'], meta: result.meta },
        },
      }),
    ],
  };
}
