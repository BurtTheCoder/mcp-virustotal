// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { AxiosInstance } from 'axios';
import { queryVirusTotal, encodeUrlForVt } from '../utils/api.js';
import { formatUrlScanResults } from '../formatters/index.js';
import { GetUrlReportArgsSchema, GetUrlRelationshipArgsSchema } from '../schemas/index.js';
import { logToFile } from '../utils/logging.js';
import { RelationshipData } from '../types/virustotal.js';

const DEFAULT_URL_RELATIONSHIPS = [
  'communicating_files',
  'contacted_domains',
  'contacted_ips',
  'downloaded_files',
  'redirects_to',
  'redirecting_urls',
  'related_threat_actors',
] as const;

export async function handleGetUrlReport(client: AxiosInstance, args: unknown) {
  const parsedArgs = GetUrlReportArgsSchema.safeParse(args);
  if (!parsedArgs.success) {
    throw new Error('Invalid URL format');
  }

  const { url } = parsedArgs.data;
  const encodedUrl = encodeUrlForVt(url);

  logToFile(`Submitting URL for scan: ${url}`);
  const scanResponse = (await queryVirusTotal(client, '/urls', 'post', new URLSearchParams({ url }))) as {
    data: { id: string };
  };

  const analysisId = scanResponse.data.id;
  logToFile(`Analysis ID: ${analysisId}`);

  await new Promise((resolve) => setTimeout(resolve, 3000));

  const analysisResponse = (await queryVirusTotal(client, `/analyses/${analysisId}`)) as {
    data: { attributes: unknown };
  };

  const relationshipData: Record<string, RelationshipData> = {};

  for (const relType of DEFAULT_URL_RELATIONSHIPS) {
    logToFile(`Fetching relationship: ${relType}`);
    try {
      const response = (await queryVirusTotal(client, `/urls/${encodedUrl}/${relType}`)) as {
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
    id: analysisId,
    url,
    attributes: analysisResponse.data.attributes as import('../formatters/url.js').UrlAttributes,
    scan_date: new Date().toISOString(),
    relationships: relationshipData,
  };

  return { content: [formatUrlScanResults(combinedData)] };
}

export async function handleGetUrlRelationship(client: AxiosInstance, args: unknown) {
  const parsedArgs = GetUrlRelationshipArgsSchema.safeParse(args);
  if (!parsedArgs.success) {
    throw new Error('Invalid arguments for URL relationship query');
  }

  const { url, relationship, limit, cursor } = parsedArgs.data;
  const encodedUrl = encodeUrlForVt(url);

  const params: Record<string, string | number> = {};
  if (limit != null) params.limit = limit;
  if (cursor) params.cursor = cursor;

  logToFile(`Fetching ${relationship} for URL: ${url}`);
  const result = (await queryVirusTotal(client, `/urls/${encodedUrl}/${relationship}`, 'get', undefined, params)) as {
    data: { attributes: unknown };
    meta?: RelationshipData['meta'];
  };

  return {
    content: [
      formatUrlScanResults({
        url,
        attributes: result.data.attributes as import('../formatters/url.js').UrlAttributes,
        relationships: {
          [relationship]: { data: result.data as RelationshipData['data'], meta: result.meta },
        },
      }),
    ],
  };
}
