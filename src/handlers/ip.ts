import { AxiosInstance } from 'axios';
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

export async function handleGetIpReport(axiosInstance: AxiosInstance, args: unknown) {
  const parsedArgs = GetIpReportArgsSchema.safeParse(args);
  if (!parsedArgs.success) {
    throw new Error("Invalid IP address format");
  }

  const ip = parsedArgs.data.ip;

  // First get the basic IP report
  logToFile('Getting IP report...');
  const basicReport = await queryVirusTotal(
    axiosInstance,
    `/ip_addresses/${ip}`
  );

  // Then get full data for specified relationships
  const relationshipData: Record<string, RelationshipData> = {};
  
  for (const relType of DEFAULT_RELATIONSHIPS) {
    logToFile(`Getting full data for ${relType}...`);
    try {
      const response = await queryVirusTotal(
        axiosInstance,
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

export async function handleGetIpRelationship(axiosInstance: AxiosInstance, args: unknown) {
  const parsedArgs = GetIpRelationshipArgsSchema.safeParse(args);
  if (!parsedArgs.success) {
    throw new Error("Invalid arguments for IP relationship query");
  }

  const { ip, relationship, limit, cursor } = parsedArgs.data;
  
  const params: Record<string, string | number> = { limit };
  if (cursor) params.cursor = cursor;
  
  const result = await queryVirusTotal(
    axiosInstance,
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
