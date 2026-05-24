import { FormattedResult } from './types.js';
import { formatDateTime } from './utils.js';
import { logToFile } from '../utils/logging.js';

interface CollectionData {
  type?: string;
  id?: string;
  attributes?: {
    name?: string;
    description?: string;
    collection_type?: string;
    tags?: string[];
    targeted_regions?: string[];
    targeted_industries?: string[];
    source_region?: string;
    motivations?: string[];
    threat_categories?: string[];
    aliases?: string[];
    creation_date?: number;
    last_modification_date?: number;
    files_count?: number;
    urls_count?: number;
    domains_count?: number;
    ip_addresses_count?: number;
    references_count?: number;
    [key: string]: any;
  };
  relationships?: Record<string, { data: any; meta?: { count?: number } }>;
}

function formatCounts(attrs: NonNullable<CollectionData['attributes']>): string[] {
  const counts: string[] = [];
  if (attrs.files_count != null) counts.push(`📁 Files: ${attrs.files_count}`);
  if (attrs.urls_count != null) counts.push(`🔗 URLs: ${attrs.urls_count}`);
  if (attrs.domains_count != null) counts.push(`🌍 Domains: ${attrs.domains_count}`);
  if (attrs.ip_addresses_count != null) counts.push(`🌐 IPs: ${attrs.ip_addresses_count}`);
  if (attrs.references_count != null) counts.push(`📚 References: ${attrs.references_count}`);
  return counts;
}

export function formatCollectionResults(data: CollectionData): FormattedResult {
  try {
    const attrs = data?.attributes || {};
    const lines: string[] = [
      `📚 Collection: ${attrs.name || data?.id || 'Unknown'}`,
      `ID: ${data?.id || 'Unknown'}`,
      attrs.collection_type ? `Type: ${attrs.collection_type}` : null,
      '',
    ].filter((line): line is string => line !== null);

    if (attrs.description) {
      lines.push('Description:', attrs.description, '');
    }

    if (attrs.aliases?.length) lines.push(`Aliases: ${attrs.aliases.join(', ')}`);
    if (attrs.tags?.length) lines.push(`Tags: ${attrs.tags.join(', ')}`);
    if (attrs.threat_categories?.length) lines.push(`Threat Categories: ${attrs.threat_categories.join(', ')}`);
    if (attrs.motivations?.length) lines.push(`Motivations: ${attrs.motivations.join(', ')}`);
    if (attrs.source_region) lines.push(`Source Region: ${attrs.source_region}`);
    if (attrs.targeted_regions?.length) lines.push(`Targeted Regions: ${attrs.targeted_regions.join(', ')}`);
    if (attrs.targeted_industries?.length) lines.push(`Targeted Industries: ${attrs.targeted_industries.join(', ')}`);

    const counts = formatCounts(attrs);
    if (counts.length) {
      lines.push('', 'IOC Counts:', ...counts.map((c) => `• ${c}`));
    }

    if (attrs.creation_date) lines.push(`\nCreated: ${formatDateTime(attrs.creation_date)}`);
    if (attrs.last_modification_date) lines.push(`Last Modified: ${formatDateTime(attrs.last_modification_date)}`);

    if (data.relationships) {
      lines.push('', '🔗 Included Relationships:');
      for (const [relType, relData] of Object.entries(data.relationships)) {
        const items = Array.isArray(relData.data) ? relData.data : relData.data ? [relData.data] : [];
        const count = relData.meta?.count ?? items.length;
        lines.push(`\n${relType} (${count} items):`);
        for (const item of items.slice(0, 10)) {
          const attrs = item.attributes || {};
          const label =
            attrs.meaningful_name ||
            attrs.url ||
            attrs.ip_address ||
            attrs.name ||
            item.id ||
            'unknown';
          lines.push(`  • ${label}`);
        }
        if (items.length > 10) {
          lines.push(`    … and ${items.length - 10} more`);
        }
      }
    }

    return { type: 'text', text: lines.join('\n').trimEnd() };
  } catch (error) {
    logToFile(`Error formatting collection results: ${error}`);
    return { type: 'text', text: 'Error formatting collection results' };
  }
}
