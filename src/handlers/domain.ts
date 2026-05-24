import { z } from 'zod';
import { queryVirusTotal, queryVirusTotalWithRelationships } from '../utils/api.js';
import { formatDomainResults } from '../formatters/index.js';
import {
  GetDomainReportArgsSchema,
  GetDomainRelationshipArgsSchema,
} from '../schemas/index.js';
import { logToFile } from '../utils/logging.js';
import { RelationshipItem, RelationshipData, DomainResponse } from '../types/virustotal.js';

const DEFAULT_RELATIONSHIPS = [
  'historical_whois',
  'historical_ssl_certificates',
  'resolutions',
  'communicating_files',
  'downloaded_files',
  'referrer_files',
] as const;

function formatDate(dateStr: string | number): string {
  try {
    if (typeof dateStr === 'number') {
      return new Date(dateStr * 1000).toLocaleDateString();
    }
    return new Date(dateStr).toLocaleDateString();
  } catch {
    return 'Unknown';
  }
}

function formatRelationshipData(relType: string, item: RelationshipItem): string {
  const attrs = item.attributes || {};

  switch (relType) {
    case 'resolutions':
      return `  • IP: ${attrs.ip_address} (${attrs.date ? new Date(Number(attrs.date) * 1000).toLocaleDateString() : 'Unknown'})
    Host: ${attrs.host_name || 'Unknown'}
    Analysis Stats:
    - IP: 🔴 ${attrs.ip_address_last_analysis_stats?.malicious || 0} malicious, ✅ ${attrs.ip_address_last_analysis_stats?.harmless || 0} harmless
    - Host: 🔴 ${attrs.host_name_last_analysis_stats?.malicious || 0} malicious, ✅ ${attrs.host_name_last_analysis_stats?.harmless || 0} harmless`;

    case 'communicating_files':
      return `  • ${attrs.meaningful_name || item.id}
    Type: ${attrs.type_description || attrs.type || 'Unknown'}
    First Seen: ${attrs.first_submission_date ? new Date(attrs.first_submission_date * 1000).toLocaleDateString() : 'Unknown'}`;

    case 'downloaded_files':
      return `  • ${attrs.meaningful_name || item.id}
    Type: ${attrs.type_description || attrs.type || 'Unknown'}
    First Seen: ${attrs.first_submission_date ? new Date(attrs.first_submission_date * 1000).toLocaleDateString() : 'Unknown'}`;

    case 'urls':
      return `  • ${attrs.url || item.id}
    Last Analysis: ${attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toLocaleDateString() : 'Unknown'}
    Reputation: ${attrs.reputation ?? 'Unknown'}`;

    case 'historical_whois': {
      const whoisMap = attrs.whois_map || {};
      const whoisInfo = [];
      if (whoisMap['Registrar']) whoisInfo.push(`Registrar: ${whoisMap['Registrar']}`);
      if (whoisMap['Creation Date']) whoisInfo.push(`Created: ${formatDate(whoisMap['Creation Date'])}`);
      if (whoisMap['Registry Expiry Date']) whoisInfo.push(`Expires: ${formatDate(whoisMap['Registry Expiry Date'])}`);
      if (whoisMap['Updated Date']) whoisInfo.push(`Updated: ${formatDate(whoisMap['Updated Date'])}`);
      if (whoisMap['Registrant Organization']) whoisInfo.push(`Organization: ${whoisMap['Registrant Organization']}`);
      if (attrs.registrar_name) whoisInfo.push(`Registrar: ${attrs.registrar_name}`);
      const lastUpdated = attrs.last_updated ? formatDate(attrs.last_updated) : 'Unknown';
      return `  • WHOIS Record from ${lastUpdated}${whoisInfo.length ? '\n    ' + whoisInfo.join('\n    ') : ''}`;
    }

    case 'historical_ssl_certificates': {
      const certInfo = [];
      if (attrs.subject?.CN) certInfo.push(`Subject: ${attrs.subject.CN}`);
      if (attrs.issuer?.CN) certInfo.push(`Issuer: ${attrs.issuer.CN}`);
      if (attrs.validity?.not_before) certInfo.push(`Valid From: ${formatDate(attrs.validity.not_before)}`);
      if (attrs.validity?.not_after) certInfo.push(`Valid Until: ${formatDate(attrs.validity.not_after)}`);
      if (attrs.serial_number) certInfo.push(`Serial: ${attrs.serial_number}`);
      const altNames = attrs.extensions?.subject_alternative_name;
      if (altNames && altNames.length) certInfo.push(`Alt Names: ${altNames.join(', ')}`);
      return `  • SSL Certificate${certInfo.length ? '\n    ' + certInfo.join('\n    ') : ''}`;
    }

    case 'referrer_files': {
      const stats = attrs.last_analysis_stats || {};
      const totalDetections = (Object.values(stats) as number[]).reduce((a, b) => a + b, 0);
      return `  • ${attrs.meaningful_name || item.id}
    Type: ${attrs.type_description || attrs.type || 'Unknown'}
    Detection Ratio: ${attrs.last_analysis_stats
        ? `${attrs.last_analysis_stats.malicious}/${totalDetections}`
        : 'Unknown'}`;
    }

    default:
      if (attrs.hostname) return `  • ${attrs.hostname}`;
      if (attrs.ip_address) return `  • ${attrs.ip_address}`;
      if (attrs.url) return `  • ${attrs.url}`;
      if (attrs.value) return `  • ${attrs.value}`;
      return `  • ${item.id}`;
  }
}

export async function handleGetDomainReport(args: z.infer<typeof GetDomainReportArgsSchema>) {
  const { domain, relationships = DEFAULT_RELATIONSHIPS } = args;

  logToFile('Getting domain report with relationships...');
  const report = (await queryVirusTotalWithRelationships(
    `/domains/${domain}`,
    relationships,
  )) as DomainResponse;

  // Attach formattedOutput to each relationship item for the formatter.
  const relationshipData: Record<string, RelationshipData> = {};
  for (const [relType, relData] of Object.entries(report.data?.relationships || {})) {
    const typed = relData as RelationshipData;
    if (Array.isArray(typed.data)) {
      relationshipData[relType] = {
        data: typed.data.map((item: RelationshipItem) => ({
          ...item,
          formattedOutput: formatRelationshipData(relType, item),
        })),
        meta: typed.meta,
      };
    } else if (typed.data) {
      relationshipData[relType] = {
        data: {
          ...typed.data,
          formattedOutput: formatRelationshipData(relType, typed.data),
        },
        meta: typed.meta,
      };
    }
  }

  const combinedData = {
    ...report.data,
    relationships: relationshipData,
  };

  return {
    content: [formatDomainResults(combinedData)],
  };
}

export async function handleGetDomainRelationship(
  args: z.infer<typeof GetDomainRelationshipArgsSchema>,
) {
  const { domain, relationship, limit, cursor } = args;

  const params: Record<string, string | number> = { limit };
  if (cursor) params.cursor = cursor;

  logToFile(`Fetching ${relationship} for domain: ${domain}`);
  const result = await queryVirusTotal(
    `/domains/${domain}/${relationship}`,
    'get',
    undefined,
    params,
  );

  // Attach formattedOutput for the existing domain formatter.
  const relationshipData: Record<string, RelationshipData> = {};
  if (Array.isArray(result.data)) {
    relationshipData[relationship] = {
      data: result.data.map((item: RelationshipItem) => ({
        ...item,
        formattedOutput: formatRelationshipData(relationship, item),
      })),
      meta: result.meta,
    };
  } else if (result.data) {
    relationshipData[relationship] = {
      data: {
        ...result.data,
        formattedOutput: formatRelationshipData(relationship, result.data),
      },
      meta: result.meta,
    };
  }

  return {
    content: [
      formatDomainResults({
        id: domain,
        relationships: relationshipData,
      }),
    ],
  };
}
