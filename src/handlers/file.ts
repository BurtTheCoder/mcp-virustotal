import { z } from 'zod';
import { queryVirusTotal } from '../utils/api.js';
import { formatFileResults } from '../formatters/index.js';
import { GetFileReportArgsSchema, GetFileRelationshipArgsSchema } from '../schemas/index.js';
import { logToFile } from '../utils/logging.js';
import { RelationshipData } from '../types/virustotal.js';

// Default relationships to fetch
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
    'similar_files'
] as const;

export async function handleGetFileReport(args: z.infer<typeof GetFileReportArgsSchema>) {
  const hash = args.hash;

  // First get the basic file report
  logToFile('Getting file report...');
  const basicReport = await queryVirusTotal(
    `/files/${hash}`
  );

  // Then get full data for specified relationships
  const relationshipData: Record<string, RelationshipData> = {};
  
  for (const relType of DEFAULT_RELATIONSHIPS) {
    logToFile(`Getting full data for ${relType}...`);
    try {
      const response = await queryVirusTotal(
        `/files/${hash}/${relType}`,
        'get'
      );

      // Format the relationship data
      if (Array.isArray(response.data)) {
        relationshipData[relType] = {
          data: response.data,
          meta: response.meta
        };
      } else if (response.data) {
        relationshipData[relType] = {
          data: response.data,
          meta: response.meta
        };
      }
    } catch (error) {
      logToFile(`Error fetching ${relType} data: ${error}`);
      // Continue with other relationships even if one fails
    }
  }

  // Combine the basic report with relationships
  const combinedData = {
    ...basicReport.data,
    relationships: relationshipData
  };

  return {
    content: [
      formatFileResults(combinedData)
    ],
  };
}

export async function handleGetFileRelationship(args: z.infer<typeof GetFileRelationshipArgsSchema>) {
  const { hash, relationship, limit, cursor } = args;
  
  const params: Record<string, string | number> = { limit };
  if (cursor) params.cursor = cursor;
  
  const result = await queryVirusTotal(
    `/files/${hash}/${relationship}`,
    'get'
  );

  return {
    content: [
      formatFileResults({
        ...result.data,
        relationships: {
          [relationship]: {
            data: result.data,
            meta: result.meta
          }
        }
      })
    ],
  };
}
