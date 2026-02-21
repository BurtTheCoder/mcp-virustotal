// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { FormattedResult } from './types.js';
import { formatDateTime, formatDetectionResults } from './utils.js';
import { RelationshipData, RelationshipItem } from '../types/virustotal.js';

interface TrackerInstance {
  id: string;
  timestamp?: number;
  url?: string;
}

export interface UrlAttributes {
  url?: string;
  last_final_url?: string;
  title?: string;
  categories?: Record<string, string>;
  first_submission_date?: number;
  last_analysis_date?: number;
  last_modification_date?: number;
  times_submitted?: number;
  last_http_response_code?: number;
  last_http_response_content_length?: number;
  last_http_response_content_sha256?: string;
  last_http_response_cookies?: Record<string, string>;
  last_http_response_headers?: Record<string, string>;
  reputation?: number;
  html_meta?: Record<string, string[]>;
  redirection_chain?: string[];
  outgoing_links?: string[];
  trackers?: Record<string, TrackerInstance[]>;
  targeted_brand?: Record<string, string>;
  tags?: string[];
  total_votes?: { harmless: number; malicious: number };
  favicon?: { dhash: string; raw_md5: string };
  last_analysis_stats?: {
    harmless: number;
    malicious: number;
    suspicious: number;
    timeout: number;
    undetected: number;
  };
}

export interface UrlData {
  id?: string;
  url?: string;
  attributes?: UrlAttributes;
  scan_id?: string;
  scan_date?: string;
  relationships?: Record<string, RelationshipData>;
}

function formatRelationshipItem(relType: string, item: RelationshipItem): string {
  const attrs = item.attributes ?? {};

  switch (relType) {
    case 'communicating_files':
    case 'downloaded_files':
      return (
        `  • ${attrs.meaningful_name ?? item.id}\n` +
        `    Type: ${attrs.type_description ?? attrs.type ?? 'Unknown'}\n` +
        `    First Seen: ${attrs.first_submission_date ? formatDateTime(attrs.first_submission_date as number) : 'Unknown'}`
      );

    case 'contacted_domains':
      return (
        `  • ${item.id}\n` +
        `    Last DNS Resolution: ${(attrs.last_dns_records_date as number | undefined) ? formatDateTime(attrs.last_dns_records_date as number) : 'Unknown'}\n` +
        `    Categories: ${Object.entries((attrs.categories as Record<string, string>) ?? {}).map(([k, v]) => `${k}: ${v}`).join(', ') || 'None'}`
      );

    case 'contacted_ips':
      return (
        `  • ${attrs.ip_address ?? item.id}\n` +
        `    Country: ${attrs.country ?? 'Unknown'}\n` +
        `    AS Owner: ${attrs.as_owner ?? 'Unknown'}`
      );

    case 'redirects_to':
    case 'redirecting_urls':
      return (
        `  • ${attrs.url ?? item.id}\n` +
        `    Last Analysis: ${attrs.last_analysis_date ? formatDateTime(attrs.last_analysis_date as number) : 'Unknown'}\n` +
        `    Reputation: ${attrs.reputation ?? 'Unknown'}`
      );

    case 'related_threat_actors':
      return (
        `  • ${attrs.name ?? item.id}\n` +
        `    Description: ${attrs.description ?? 'No description available'}`
      );

    default:
      return `  • ${item.id}`;
  }
}

function formatSize(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB'];
  let size = bytes;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }
  return `${size.toFixed(2)} ${units[unitIndex]}`;
}

export function formatUrlScanResults(data: UrlData): FormattedResult {
  const attributes = data.attributes ?? {};
  const stats = attributes.last_analysis_stats ?? null;
  const votes = attributes.total_votes ?? { harmless: 0, malicious: 0 };
  const tags = attributes.tags ?? [];
  const redirectionChain = attributes.redirection_chain ?? [];
  const outgoingLinks = attributes.outgoing_links ?? [];

  const lines: (string | null)[] = [
    'URL Analysis Results',
    '',
    'URL Information:',
    `• URL: ${attributes.url ?? data.url ?? data.id ?? 'Unknown URL'}`,
    attributes.last_final_url && attributes.last_final_url !== attributes.url
      ? `• Final URL: ${attributes.last_final_url}`
      : null,
    attributes.title ? `• Page Title: ${attributes.title}` : null,
    `• First Seen: ${attributes.first_submission_date ? formatDateTime(attributes.first_submission_date) : 'N/A'}`,
    `• Last Analyzed: ${attributes.last_analysis_date ? formatDateTime(attributes.last_analysis_date) : 'N/A'}`,
    `• Times Submitted: ${attributes.times_submitted ?? 0}`,
    '',
    'Analysis Statistics:',
    formatDetectionResults(stats),
    '',
    'Community Feedback:',
    `• Reputation Score: ${attributes.reputation ?? 'N/A'}`,
    `• Harmless Votes: ${votes.harmless}`,
    `• Malicious Votes: ${votes.malicious}`,
  ];

  if (attributes.last_http_response_code) {
    lines.push(
      '',
      'HTTP Response:',
      `• Status Code: ${attributes.last_http_response_code}`,
      `• Content Length: ${formatSize(attributes.last_http_response_content_length ?? 0)}`,
      attributes.last_http_response_content_sha256
        ? `• Content SHA-256: ${attributes.last_http_response_content_sha256}`
        : null
    );
  }

  if (attributes.categories && Object.keys(attributes.categories).length > 0) {
    lines.push('', 'Categories:', ...Object.entries(attributes.categories).map(([s, c]) => `• ${s}: ${c}`));
  }

  if (redirectionChain.length > 0) {
    lines.push('', 'Redirection Chain:', ...redirectionChain.map((u, i) => `${i + 1}. ${u}`));
  }

  if (outgoingLinks.length > 0) {
    lines.push(
      '',
      'Outgoing Links:',
      ...outgoingLinks.slice(0, 5).map((u) => `• ${u}`),
      outgoingLinks.length > 5 ? `... and ${outgoingLinks.length - 5} more` : null
    );
  }

  if (attributes.trackers && Object.keys(attributes.trackers).length > 0) {
    lines.push('', 'Trackers:');
    for (const [tracker, instances] of Object.entries(attributes.trackers)) {
      if (Array.isArray(instances)) {
        lines.push(`${tracker}:`, ...instances.map((inst) => `• ID: ${inst.id}${inst.url ? `\n  URL: ${inst.url}` : ''}`));
      }
    }
  }

  if (attributes.targeted_brand && Object.keys(attributes.targeted_brand).length > 0) {
    lines.push('', 'Targeted Brands:', ...Object.entries(attributes.targeted_brand).map(([s, b]) => `• ${s}: ${b}`));
  }

  if (attributes.html_meta && Object.keys(attributes.html_meta).length > 0) {
    const relevant = ['description', 'keywords', 'author'];
    const metaEntries = Object.entries(attributes.html_meta).filter(([k]) => relevant.includes(k));
    if (metaEntries.length > 0) {
      lines.push('', 'Meta Information:');
      for (const [key, values] of metaEntries) {
        if (Array.isArray(values) && values.length > 0) lines.push(`• ${key}: ${values[0]}`);
      }
    }
  }

  if (attributes.favicon) {
    lines.push('', 'Favicon:', `• Hash: ${attributes.favicon.dhash}`, `• MD5: ${attributes.favicon.raw_md5}`);
  }

  if (tags.length > 0) {
    lines.push('', 'Tags:', ...tags.map((t) => `• ${t}`));
  }

  if (attributes.last_http_response_headers && Object.keys(attributes.last_http_response_headers).length > 0) {
    const important = ['server', 'content-type', 'x-powered-by', 'x-frame-options', 'x-xss-protection'];
    const relevant = Object.entries(attributes.last_http_response_headers).filter(([k]) =>
      important.includes(k.toLowerCase())
    );
    if (relevant.length > 0) {
      lines.push('', 'Important HTTP Headers:', ...relevant.map(([k, v]) => `• ${k}: ${v}`));
    }
  }

  if (attributes.last_http_response_cookies && Object.keys(attributes.last_http_response_cookies).length > 0) {
    lines.push('', 'Cookies:', ...Object.entries(attributes.last_http_response_cookies).map(([n, v]) => `• ${n}: ${v}`));
  }

  if (data.relationships) {
    lines.push('', 'Relationships:');
    for (const [relType, relData] of Object.entries(data.relationships)) {
      const count = relData.meta?.count ?? (Array.isArray(relData.data) ? relData.data.length : 1);
      lines.push(`\n${relType} (${count} items):`);
      if (Array.isArray(relData.data)) {
        relData.data.forEach((item) => lines.push(formatRelationshipItem(relType, item)));
      } else if (relData.data) {
        lines.push(formatRelationshipItem(relType, relData.data as RelationshipItem));
      }
    }
  }

  return { type: 'text', text: lines.filter((l) => l !== null).join('\n') };
}
