// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { FormattedResult } from './types.js';

interface RelationshipResponseItem {
  id?: string;
  attributes?: {
    url?: string;
    meaningful_name?: string;
    type?: string;
    ip_address?: string;
    hostname?: string;
    value?: string;
    domain?: string;
    date?: string | number;
    [key: string]: unknown;
  };
}

interface RelationshipResponseData {
  relationship?: string;
  data?: RelationshipResponseItem[];
  meta?: {
    count?: number;
    cursor?: string;
  };
}

export function formatRelationshipResults(
  data: RelationshipResponseData,
  type: 'url' | 'file' | 'ip' | 'domain'
): FormattedResult {
  const items = data.data ?? [];
  const meta = data.meta ?? {};

  const lines: string[] = [
    `${type.toUpperCase()} Relationship Results`,
    `Type: ${data.relationship ?? 'Unknown'}`,
    `Total Results: ${meta.count ?? items.length}`,
    '',
    'Related Items:',
    ...items.map((item) => {
      switch (type) {
        case 'url':
          return `• ${item.attributes?.url ?? 'Unknown URL'}`;
        case 'file':
          return `• ${item.attributes?.meaningful_name ?? item.id ?? 'Unknown File'} (${item.attributes?.type ?? 'Unknown Type'})`;
        case 'ip':
          return `• ${item.attributes?.ip_address ?? item.id ?? 'Unknown IP'}`;
        case 'domain':
          if (item.attributes?.hostname) return `• ${item.attributes.hostname}`;
          if (item.attributes?.value) return `• ${item.attributes.value}`;
          if (item.attributes?.domain) return `• ${item.attributes.domain}`;
          if (item.attributes?.ip_address) return `• ${item.attributes.ip_address}`;
          return `• ${item.id ?? 'Unknown Item'}`;
        default:
          return `• ${item.id ?? 'Unknown Item'}`;
      }
    }),
  ];

  if (meta.cursor) {
    lines.push('', `More results available. Use cursor: ${meta.cursor}`);
  }

  return { type: 'text', text: lines.join('\n') };
}
