// src/formatters/relationship.ts

import { FormattedResult } from './types.js';
import { logToFile } from '../utils/logging.js';

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
