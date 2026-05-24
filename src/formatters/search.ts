import { FormattedResult } from './types.js';
import { formatDateTime } from './utils.js';
import { logToFile } from '../utils/logging.js';

interface SearchItem {
  type: string;
  id: string;
  attributes?: Record<string, any>;
}

interface SearchMeta {
  cursor?: string;
  count?: number;
}

function formatItem(item: SearchItem): string {
  const attrs = item.attributes || {};
  const stats = attrs.last_analysis_stats || {};
  const detection = stats.malicious !== undefined
    ? `🔴 ${stats.malicious} malicious / ${(stats.malicious || 0) + (stats.suspicious || 0) + (stats.harmless || 0) + (stats.undetected || 0)} engines`
    : '';

  switch (item.type) {
    case 'file': {
      const name = attrs.meaningful_name || attrs.names?.[0] || item.id;
      const fileType = attrs.type_description || attrs.type_tag || 'Unknown';
      const seen = attrs.first_submission_date ? formatDateTime(attrs.first_submission_date) : 'Unknown';
      return `📁 file • ${name}
    SHA-256: ${attrs.sha256 || item.id}
    Type: ${fileType}
    First Seen: ${seen}${detection ? `\n    Detection: ${detection}` : ''}`;
    }
    case 'url': {
      const url = attrs.url || item.id;
      const title = attrs.title ? `\n    Title: ${attrs.title}` : '';
      return `🔗 url • ${url}${title}${detection ? `\n    Detection: ${detection}` : ''}`;
    }
    case 'domain':
      return `🌍 domain • ${item.id}${detection ? `\n    Detection: ${detection}` : ''}`;
    case 'ip_address':
      return `🌐 ip • ${item.id}
    AS: ${attrs.as_owner || 'Unknown'} (${attrs.country || '?'})${detection ? `\n    Detection: ${detection}` : ''}`;
    case 'comment':
      return `💬 comment • ${item.id}
    ${(attrs.text || '').slice(0, 200)}${attrs.text && attrs.text.length > 200 ? '…' : ''}`;
    default:
      return `• ${item.type} • ${item.id}`;
  }
}

export function formatSearchResults(
  query: string,
  data: SearchItem[],
  meta?: SearchMeta,
): FormattedResult {
  try {
    const items = Array.isArray(data) ? data : [];
    const lines: string[] = [
      `🔎 VirusTotal Search Results`,
      `Query: ${query}`,
      `Results: ${items.length}${meta?.count ? ` of ${meta.count}` : ''}`,
      '',
    ];

    if (items.length === 0) {
      lines.push('No matching objects found.');
    } else {
      for (const item of items) {
        lines.push(formatItem(item));
        lines.push('');
      }
    }

    if (meta?.cursor) {
      lines.push(`📄 More results available. Pass cursor: ${meta.cursor}`);
    }

    return { type: 'text', text: lines.join('\n').trimEnd() };
  } catch (error) {
    logToFile(`Error formatting search results: ${error}`);
    return { type: 'text', text: 'Error formatting search results' };
  }
}
