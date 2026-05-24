// src/formatters/relationship.ts

import { FormattedResult } from './types.js';
import { logToFile } from '../utils/logging.js';

type EntityType = 'url' | 'file' | 'ip' | 'domain';

const ENTITY_EMOJI: Record<EntityType, string> = {
  url: '🔗',
  file: '📁',
  ip: '🌐',
  domain: '🌍',
};

const ENTITY_LABEL: Record<EntityType, string> = {
  url: 'URL',
  file: 'File',
  ip: 'IP',
  domain: 'Domain',
};

export interface RelationshipPageOptions {
  entity: EntityType;
  entityId: string;
  relationship: string;
  data: any;
  meta?: { count?: number; cursor?: string };
  renderItem: (relationship: string, item: any) => string;
}

/**
 * Render a focused page of relationship items for one entity, without the
 * noisy parent-entity preamble produced by the full report formatters.
 */
export function formatRelationshipPage(opts: RelationshipPageOptions): FormattedResult {
  try {
    const { entity, entityId, relationship, data, meta = {}, renderItem } = opts;
    const items = Array.isArray(data) ? data : data ? [data] : [];
    const total = meta.count;

    const header = `${ENTITY_EMOJI[entity]} ${ENTITY_LABEL[entity]} ${entityId} — ${relationship}`;
    const counts =
      total != null && total !== items.length
        ? `Showing ${items.length} of ${total} items.`
        : `${items.length} item${items.length === 1 ? '' : 's'}.`;

    const lines: string[] = [header, counts, ''];

    if (items.length === 0) {
      lines.push('(no results)');
    } else {
      for (const item of items) {
        try {
          lines.push(renderItem(relationship, item));
        } catch (err) {
          logToFile(`Error formatting relationship item: ${err}`);
          lines.push('  • Error formatting item');
        }
      }
    }

    if (meta.cursor) {
      lines.push('', `📄 More results available. Use cursor: ${meta.cursor}`);
    }

    return { type: 'text', text: lines.join('\n') };
  } catch (error) {
    logToFile(`Error formatting relationship page: ${error}`);
    return { type: 'text', text: 'Error formatting relationship page' };
  }
}

export function formatRelationshipResults(data: any, type: 'url' | 'file' | 'ip' | 'domain'): FormattedResult {
  try {
    const relationshipData = data?.data || [];
    const meta = data?.meta || {};
    
    const typeEmoji = {
      url: '🔗',
      file: '📁',
      ip: '🌐',
      domain: '🌍'
    }[type];

    let outputArray = [
      `${typeEmoji} ${type.toUpperCase()} Relationship Results`,
      `Type: ${data?.relationship || 'Unknown'}`,
      `Total Results: ${meta?.count || relationshipData.length}`,
      "",
      "Related Items:",
      ...relationshipData.map((item: any) => {
        try {
          switch(type) {
            case 'url':
              return `• ${item?.attributes?.url || 'Unknown URL'}`;
            case 'file':
              return `• ${item?.attributes?.meaningful_name || item?.id || 'Unknown File'} (${item?.attributes?.type || 'Unknown Type'})`;
            case 'ip':
              return `• ${item?.attributes?.ip_address || item?.id || 'Unknown IP'}`;
            case 'domain':
              // Handle different domain relationship types
              if (item?.attributes?.hostname) return `• ${item.attributes.hostname}`;
              if (item?.attributes?.value) return `• ${item.attributes.value}`;
              if (item?.attributes?.domain) return `• ${item.attributes.domain}`;
              if (item?.attributes?.ip_address) return `• ${item.attributes.ip_address}`;
              if (item?.attributes?.date) return `• Record from ${item.attributes.date}`;
              return `• ${item?.id || 'Unknown Domain Item'}`;
            default:
              return `• ${item?.id || 'Unknown Item'}`;
          }
        } catch (error) {
          logToFile(`Error formatting relationship item: ${error}`);
          return '• Error formatting item';
        }
      })
    ];

    if (meta?.cursor) {
      outputArray.push('\n📄 More results available. Use cursor: ' + meta.cursor);
    }

    return {
      type: "text",
      text: outputArray.join('\n')
    };
  } catch (error) {
    logToFile(`Error formatting relationship results: ${error}`);
    return {
      type: "text",
      text: "Error formatting relationship results"
    };
  }
}
