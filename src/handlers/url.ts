import { AxiosInstance } from 'axios';
import { queryVirusTotal, encodeUrlForVt } from '../utils/api.js';
import { formatUrlScanResults } from '../formatters/index.js';
import { GetUrlReportArgsSchema, GetUrlRelationshipArgsSchema } from '../schemas/index.js';
import { logToFile } from '../utils/logging.js';
import { RelationshipData } from '../types/virustotal.js';

// Default relationships to fetch
const DEFAULT_RELATIONSHIPS = [
    'communicating_files',
    'contacted_domains',
    'contacted_ips',
    'downloaded_files',
    'redirects_to',
    'redirecting_urls',
    'related_threat_actors'
] as const;

export async function handleGetUrlReport(axiosInstance: AxiosInstance, args: unknown) {
  const parsedArgs = GetUrlReportArgsSchema.safeParse(args);
  if (!parsedArgs.success) {
    throw new Error("Invalid URL format");
  }

  const url = parsedArgs.data.url;
  const encodedUrl = encodeUrlForVt(url);

  // First submit URL for scanning
  logToFile(`Scanning URL: ${url}`);
  const scanResponse = await queryVirusTotal(
    axiosInstance,
    '/urls',
    'post',
    new URLSearchParams({ url })
  );
  
  const analysisId = scanResponse.data.id;
  logToFile(`Analysis ID: ${analysisId}`);
  
  // Wait for analysis to complete
  await new Promise(resolve => setTimeout(resolve, 3000));
  
  // Get analysis results
  const analysisResponse = await queryVirusTotal(
    axiosInstance,
    `/analyses/${analysisId}`
  );

  // Then get full data for specified relationships
  const relationshipData: Record<string, RelationshipData> = {};
  
  for (const relType of DEFAULT_RELATIONSHIPS) {
    logToFile(`Fetching ${relType}`);
    try {
      const response = await queryVirusTotal(
        axiosInstance,
        `/urls/${encodedUrl}/${relType}`,
        'get'
      );

      // Only log relationship metadata
      logToFile(`${relType} count: ${
        Array.isArray(response.data) ? response.data.length : 
        response.data ? '1' : '0'
      }`);

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
      logToFile(`Failed to fetch ${relType}`);
      // Continue with other relationships even if one fails
    }
  }

  // Combine the analysis results with relationships
  const combinedData = {
    id: analysisId,
    url: url,
    attributes: analysisResponse.data.attributes,
    scan_date: new Date().toISOString(),
    relationships: relationshipData
  };

  return {
    content: [
      formatUrlScanResults(combinedData)
    ],
  };
}

export async function handleGetUrlRelationship(axiosInstance: AxiosInstance, args: unknown) {
  const parsedArgs = GetUrlRelationshipArgsSchema.safeParse(args);
  if (!parsedArgs.success) {
    throw new Error("Invalid arguments for URL relationship query");
  }

  const { url, relationship, limit, cursor } = parsedArgs.data;
  const encodedUrl = encodeUrlForVt(url);
  
  const params: Record<string, string | number> = { limit };
  if (cursor) params.cursor = cursor;
  
  logToFile(`Fetching ${relationship} for URL: ${url}`);
  const result = await queryVirusTotal(
    axiosInstance,
    `/urls/${encodedUrl}/${relationship}`,
    'get'
  );

  return {
    content: [
      formatUrlScanResults({
        url: url,
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
