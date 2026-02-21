// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { FormattedResult } from './types.js';
import { formatDateTime, formatDetectionResults } from './utils.js';
import { DomainData, RelationshipData, RelationshipItem } from '../types/virustotal.js';

export function formatDomainResults(data: DomainData): FormattedResult {
  const attributes = data.attributes ?? {};
  const stats = attributes.last_analysis_stats ?? null;
  const categories = attributes.categories ?? {};
  const ranks = attributes.popularity_ranks ?? {};
  const whois = attributes.whois ?? '';
  const dnsRecords = attributes.last_dns_records ?? [];
  const threatSeverity = attributes.threat_severity;
  const votes = attributes.total_votes;

  const lines: string[] = [
    'Domain Analysis Results',
    `Domain: ${data.id ?? 'Unknown Domain'}`,
    `Last Analysis Date: ${attributes.last_analysis_date ? formatDateTime(attributes.last_analysis_date) : 'N/A'}`,
    `Reputation Score: ${attributes.reputation ?? 'N/A'}`,
    '',
    'Analysis Statistics:',
    formatDetectionResults(stats),
  ];

  if (threatSeverity?.threat_severity_level) {
    const sd = threatSeverity.threat_severity_data;
    lines.push(
      '',
      'Threat Severity:',
      `Level: ${threatSeverity.threat_severity_level}`,
      `Description: ${threatSeverity.level_description ?? 'N/A'}`,
      ...(sd ? [`Detections: ${sd.num_detections}`, `Bad Collection: ${sd.belongs_to_bad_collection ? 'Yes' : 'No'}`] : [])
    );
  }

  if (Object.keys(categories).length > 0) {
    lines.push('', 'Categories:', ...Object.entries(categories).map(([s, c]) => `• ${s}: ${c}`));
  }

  if (dnsRecords.length > 0) {
    lines.push('', 'Latest DNS Records:', ...dnsRecords.map((r) => `• ${r.type}: ${r.value} (TTL: ${r.ttl})`));
  }

  if (Object.keys(ranks).length > 0) {
    lines.push('', 'Popularity Rankings:', ...Object.entries(ranks).map(([s, d]) => `• ${s}: Rank ${d.rank ?? 'N/A'}`));
  }

  if (whois) {
    const keyFields = [
      'Registrar:',
      'Creation Date:',
      'Registry Expiry Date:',
      'Updated Date:',
      'Registrant Organization:',
      'Admin Organization:',
    ];
    const relevant = [...new Set(whois.split('\n').filter((l) => keyFields.some((f) => l.trim().startsWith(f))))];
    if (relevant.length > 0) {
      lines.push('', 'WHOIS Information:', ...relevant.map((l) => `• ${l.trim()}`));
    }
  }

  if (attributes.creation_date) lines.push('', `Creation Date: ${formatDateTime(attributes.creation_date)}`);
  if (attributes.last_modification_date) lines.push(`Last Modified: ${formatDateTime(attributes.last_modification_date)}`);

  if (votes) {
    lines.push('', 'Community Votes:', `• Harmless: ${votes.harmless}`, `• Malicious: ${votes.malicious}`);
  }

  if (data.relationships) {
    lines.push('', 'Relationships:');
    for (const [relType, relData] of Object.entries(data.relationships)) {
      const typedRelData = relData as RelationshipData;
      const count = typedRelData.meta?.count ?? (Array.isArray(typedRelData.data) ? typedRelData.data.length : 1);
      lines.push(`\n${relType} (${count} items):`);

      if (Array.isArray(typedRelData.data)) {
        typedRelData.data.forEach((item) => {
          if ((item as RelationshipItem).formattedOutput) {
            lines.push((item as RelationshipItem).formattedOutput!);
          }
        });
      } else if (typedRelData.data && 'formattedOutput' in typedRelData.data) {
        const single = typedRelData.data as RelationshipItem;
        if (single.formattedOutput) lines.push(single.formattedOutput);
      }
    }
  }

  return { type: 'text', text: lines.join('\n') };
}
