import { z } from 'zod';
import { queryVirusTotal, queryVirusTotalWithRelationships } from '../utils/api.js';
import { formatFileResults } from '../formatters/index.js';
import { GetFileReportArgsSchema, GetFileRelationshipArgsSchema } from '../schemas/index.js';
import { logToFile } from '../utils/logging.js';

const DEFAULT_RELATIONSHIPS = [
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

export async function handleGetFileReport(args: z.infer<typeof GetFileReportArgsSchema>) {
  const { hash } = args;
  logToFile('Getting file report with relationships...');
  const report = await queryVirusTotalWithRelationships(
    `/files/${hash}`,
    DEFAULT_RELATIONSHIPS,
  );
  return {
    content: [formatFileResults(report.data)],
  };
}

export async function handleGetFileRelationship(args: z.infer<typeof GetFileRelationshipArgsSchema>) {
  const { hash, relationship, limit, cursor } = args;

  const params: Record<string, string | number> = { limit };
  if (cursor) params.cursor = cursor;

  const result = await queryVirusTotal(
    `/files/${hash}/${relationship}`,
    'get',
    undefined,
    params,
  );

  return {
    content: [
      formatFileResults({
        relationships: {
          [relationship]: {
            data: result.data,
            meta: result.meta,
          },
        },
      }),
    ],
  };
}
