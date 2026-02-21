// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { AxiosInstance } from 'axios';
import { queryVirusTotal } from '../utils/api.js';
import { formatDomainResults } from '../formatters/index.js';
import { GetDomainReportArgsSchema } from '../schemas/index.js';
import { logToFile } from '../utils/logging.js';
import { RelationshipItem, RelationshipData, DomainResponse } from '../types/virustotal.js';

const DEFAULT_DOMAIN_RELATIONSHIPS = [
  'historical_whois',
  'historical_ssl_certificates',
  'resolutions',
  'communicating_files',
  'downloaded_files',
  'referrer_files',
] as const;

function formatDate(dateStr: string | number): string {
  try {
    return typeof dateStr === 'number'
      ? new Date(dateStr * 1000).toLocaleDateString()
      : new Date(dateStr).toLocaleDateString();
  } catch {
    return 'Unknown';
  }
}

function formatRelationshipItem(relType: string, item: RelationshipItem): string {
  const attrs = item.attributes ?? {};

  switch (relType) {
    case 'resolutions':
      return (
        `  • IP: ${attrs.ip_address} (${attrs.date ? new Date(Number(attrs.date) * 1000).toLocaleDateString() : 'Unknown'})\n` +
        `    Host: ${attrs.host_name ?? 'Unknown'}\n` +
        `    Analysis Stats:\n` +
        `    - IP: ${attrs.ip_address_last_analysis_stats?.malicious ?? 0} malicious, ` +
        `${attrs.ip_address_last_analysis_stats?.harmless ?? 0} harmless\n` +
        `    - Host: ${attrs.host_name_last_analysis_stats?.malicious ?? 0} malicious, ` +
        `${attrs.host_name_last_analysis_stats?.harmless ?? 0} harmless`
      );

    case 'communicating_files':
    case 'downloaded_files':
      return (
        `  • ${attrs.meaningful_name ?? item.id}\n` +
        `    Type: ${attrs.type_description ?? attrs.type ?? 'Unknown'}\n` +
        `    First Seen: ${attrs.first_submission_date ? new Date((attrs.first_submission_date as number) * 1000).toLocaleDateString() : 'Unknown'}`
      );

    case 'urls':
      return (
        `  • ${attrs.url ?? item.id}\n` +
        `    Last Analysis: ${attrs.last_analysis_date ? new Date((attrs.last_analysis_date as number) * 1000).toLocaleDateString() : 'Unknown'}\n` +
        `    Reputation: ${attrs.reputation ?? 'Unknown'}`
      );

    case 'historical_whois': {
      const whoisMap = (attrs.whois_map as Record<string, string>) ?? {};
      const parts: string[] = [];
      if (whoisMap['Registrar']) parts.push(`Registrar: ${whoisMap['Registrar']}`);
      if (whoisMap['Creation Date']) parts.push(`Created: ${formatDate(whoisMap['Creation Date'])}`);
      if (whoisMap['Registry Expiry Date']) parts.push(`Expires: ${formatDate(whoisMap['Registry Expiry Date'])}`);
      if (whoisMap['Updated Date']) parts.push(`Updated: ${formatDate(whoisMap['Updated Date'])}`);
      if (whoisMap['Registrant Organization']) parts.push(`Organization: ${whoisMap['Registrant Organization']}`);
      if (attrs.registrar_name) parts.push(`Registrar: ${attrs.registrar_name as string}`);
      return `  • WHOIS Record from ${formatDate((attrs.last_updated as string | number) ?? '')}${parts.length ? '\n    ' + parts.join('\n    ') : ''}`;
    }

    case 'historical_ssl_certificates': {
      const subject = attrs.subject as Record<string, string> | undefined;
      const issuer = attrs.issuer as Record<string, string> | undefined;
      const validity = attrs.validity as Record<string, string | number> | undefined;
      const extensions = attrs.extensions as Record<string, string[]> | undefined;
      const parts: string[] = [];
      if (subject?.CN) parts.push(`Subject: ${subject.CN}`);
      if (issuer?.CN) parts.push(`Issuer: ${issuer.CN}`);
      if (validity?.not_before) parts.push(`Valid From: ${formatDate(validity.not_before)}`);
      if (validity?.not_after) parts.push(`Valid Until: ${formatDate(validity.not_after)}`);
      if (attrs.serial_number) parts.push(`Serial: ${attrs.serial_number as string}`);
      const altNames = extensions?.subject_alternative_name;
      if (altNames?.length) parts.push(`Alt Names: ${altNames.join(', ')}`);
      return `  • SSL Certificate${parts.length ? '\n    ' + parts.join('\n    ') : ''}`;
    }

    case 'referrer_files': {
      const stats = (attrs.last_analysis_stats ?? {}) as Record<string, number>;
      const total = Object.values(stats).reduce((a, b) => a + b, 0);
      return (
        `  • ${attrs.meaningful_name ?? item.id}\n` +
        `    Type: ${attrs.type_description ?? attrs.type ?? 'Unknown'}\n` +
        `    Detection Ratio: ${attrs.last_analysis_stats ? `${stats.malicious}/${total}` : 'Unknown'}`
      );
    }

    default:
      if (attrs.hostname) return `  • ${attrs.hostname as string}`;
      if (attrs.ip_address) return `  • ${attrs.ip_address as string}`;
      if (attrs.url) return `  • ${attrs.url as string}`;
      if (attrs.value) return `  • ${attrs.value as string}`;
      return `  • ${item.id}`;
  }
}

export async function handleGetDomainReport(client: AxiosInstance, args: unknown) {
  const parsedArgs = GetDomainReportArgsSchema.safeParse(args);
  if (!parsedArgs.success) {
    throw new Error('Invalid domain format');
  }

  const { domain, relationships = DEFAULT_DOMAIN_RELATIONSHIPS } = parsedArgs.data;

  logToFile(`Fetching domain report: ${domain}`);
  const basicReport = (await queryVirusTotal(client, `/domains/${domain}`)) as DomainResponse;

  const relationshipData: Record<string, RelationshipData> = {};

  for (const relType of relationships) {
    logToFile(`Fetching relationship: ${relType}`);
    try {
      const response = (await queryVirusTotal(client, `/domains/${domain}/${relType}`)) as {
        data: RelationshipItem | RelationshipItem[];
        meta?: RelationshipData['meta'];
      };

      if (response.data) {
        if (Array.isArray(response.data)) {
          relationshipData[relType] = {
            data: response.data.map((item) => ({
              ...item,
              formattedOutput: formatRelationshipItem(relType, item),
            })),
            meta: response.meta,
          };
        } else {
          relationshipData[relType] = {
            data: {
              ...response.data,
              formattedOutput: formatRelationshipItem(relType, response.data),
            },
            meta: response.meta,
          };
        }
      }
    } catch {
      logToFile(`Skipping ${relType} – fetch failed`);
    }
  }

  const combinedData = { ...basicReport.data, relationships: relationshipData };

  return { content: [formatDomainResults(combinedData)] };
}
