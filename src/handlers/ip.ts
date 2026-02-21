import { z } from 'zod';
import { queryVirusTotal } from '../utils/api.js';
import { formatIpResults } from '../formatters/index.js';
import { GetIpReportArgsSchema, GetIpRelationshipArgsSchema } from '../schemas/index.js';
import { logToFile } from '../utils/logging.js';
import { RelationshipData } from '../types/virustotal.js';

// Default relationships to fetch
const DEFAULT_RELATIONSHIPS = [
    'communicating_files',
    'downloaded_files',
    'historical_ssl_certificates',
    'resolutions',
    'related_threat_actors',
    'urls'
] as const;

export async function handleGetIpReport(args: z.infer<typeof GetIpReportArgsSchema>) {
  const ip = args.ip;

  // First get the basic IP report
  logToFile('Getting IP report...');
  const basicReport = await queryVirusTotal(
    `/ip_addresses/${ip}`
  );

  // Then get full data for specified relationships
  const relationshipData: Record<string, RelationshipData> = {};
  
  for (const relType of DEFAULT_RELATIONSHIPS) {
    logToFile(`Getting full data for ${relType}...`);
    try {
      const response = await queryVirusTotal(
        `/ip_addresses/${ip}/${relType}`,
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

  // Combine the basic report with detailed relationships
  const combinedData = {
    ...basicReport.data,
    relationships: relationshipData
  };

  return {
    content: [
      formatIpResults(combinedData)
    ],
  };
}

export async function handleGetIpRelationship(args: z.infer<typeof GetIpRelationshipArgsSchema>) {
  const { ip, relationship, limit, cursor } = args;
  
  const params: Record<string, string | number> = { limit };
  if (cursor) params.cursor = cursor;
  
  const result = await queryVirusTotal(
    `/ip_addresses/${ip}/${relationship}`,
    'get'
  );

  return {
    content: [
      formatIpResults({
        id: ip,
        attributes: result.data.attributes,
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
