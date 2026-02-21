// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { FormattedResult } from './types.js';
import { formatDateTime, formatDetectionResults } from './utils.js';
import { RelationshipData, RelationshipItem, AnalysisStats } from '../types/virustotal.js';

interface CertExtensions {
  CA?: boolean;
  subject_alternative_name?: string[];
  certificate_policies?: string[];
  extended_key_usage?: string[];
}

interface Certificate {
  issuer: { C?: string; CN?: string; O?: string };
  subject: { CN?: string };
  validity: { not_after: string; not_before: string };
  version: string;
  serial_number: string;
  thumbprint_sha256: string;
  extensions?: CertExtensions;
}

interface IpAttributes {
  as_owner?: string;
  asn?: number;
  continent?: string;
  country?: string;
  network?: string;
  regional_internet_registry?: string;
  jarm?: string;
  reputation?: number;
  last_analysis_stats?: AnalysisStats;
  last_https_certificate?: Certificate;
  whois?: string;
  whois_date?: number;
  tags?: string[];
  total_votes?: { harmless: number; malicious: number };
}

interface IpData {
  id?: string;
  ip?: string;
  attributes?: IpAttributes;
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

    case 'historical_ssl_certificates': {
      const subject = attrs.subject as Record<string, string> | undefined;
      const issuer = attrs.issuer as Record<string, string> | undefined;
      const validity = attrs.validity as Record<string, string> | undefined;
      const parts: string[] = [];
      if (subject?.CN) parts.push(`Subject: ${subject.CN}`);
      if (issuer?.CN) parts.push(`Issuer: ${issuer.CN}`);
      if (validity?.not_before) parts.push(`Valid From: ${formatDateTime(new Date(validity.not_before).getTime() / 1000)}`);
      if (validity?.not_after) parts.push(`Valid Until: ${formatDateTime(new Date(validity.not_after).getTime() / 1000)}`);
      if (attrs.serial_number) parts.push(`Serial: ${attrs.serial_number as string}`);
      return `  • SSL Certificate${parts.length ? '\n    ' + parts.join('\n    ') : ''}`;
    }

    case 'resolutions':
      return (
        `  • Host: ${attrs.host_name ?? 'Unknown'}\n` +
        `    Last Resolved: ${attrs.date ? formatDateTime(Number(attrs.date)) : 'Unknown'}`
      );

    case 'related_threat_actors':
      return `  • ${attrs.name ?? item.id}\n    Description: ${attrs.description ?? 'No description available'}`;

    case 'urls':
      return (
        `  • ${attrs.url ?? item.id}\n` +
        `    Last Analysis: ${attrs.last_analysis_date ? formatDateTime(attrs.last_analysis_date as number) : 'Unknown'}\n` +
        `    Reputation: ${attrs.reputation ?? 'Unknown'}`
      );

    default:
      return `  • ${item.id}`;
  }
}

export function formatIpResults(data: IpData): FormattedResult {
  const attributes = data.attributes ?? {};
  const stats = attributes.last_analysis_stats ?? null;
  const votes = attributes.total_votes ?? { harmless: 0, malicious: 0 };
  const tags = attributes.tags ?? [];

  const lines: (string | null)[] = [
    'IP Address Analysis',
    `IP: ${data.id ?? data.ip ?? 'Unknown IP'}`,
    '',
    'Network Information:',
    `• AS Owner: ${attributes.as_owner ?? 'Unknown'}`,
    attributes.asn != null ? `• ASN: ${attributes.asn}` : null,
    `• Network: ${attributes.network ?? 'Unknown'}`,
    `• Country: ${attributes.country ?? 'Unknown'}`,
    `• Continent: ${attributes.continent ?? 'Unknown'}`,
    `• Registry: ${attributes.regional_internet_registry ?? 'Unknown'}`,
    '',
    'Analysis Statistics:',
    formatDetectionResults(stats),
    '',
    'Community Feedback:',
    `• Reputation Score: ${attributes.reputation ?? 'N/A'}`,
    `• Harmless Votes: ${votes.harmless}`,
    `• Malicious Votes: ${votes.malicious}`,
  ];

  if (attributes.jarm) {
    lines.push('', 'JARM Hash:', attributes.jarm);
  }

  if (attributes.last_https_certificate) {
    const cert = attributes.last_https_certificate;
    lines.push(
      '',
      'SSL Certificate:',
      `• Subject: ${cert.subject?.CN ?? 'Unknown'}`,
      `• Issuer: ${[cert.issuer?.O, cert.issuer?.CN].filter(Boolean).join(' - ')}`,
      `• Valid From: ${formatDateTime(new Date(cert.validity.not_before).getTime() / 1000)}`,
      `• Valid Until: ${formatDateTime(new Date(cert.validity.not_after).getTime() / 1000)}`,
      `• Serial Number: ${cert.serial_number}`,
      `• Version: ${cert.version}`,
      `• SHA-256 Fingerprint: ${cert.thumbprint_sha256}`
    );
    if (cert.extensions?.subject_alternative_name?.length) {
      lines.push('• Alternative Names:', ...cert.extensions.subject_alternative_name.map((n) => `  - ${n}`));
    }
    if (cert.extensions?.certificate_policies?.length) {
      lines.push('• Certificate Policies:', ...cert.extensions.certificate_policies.map((p) => `  - ${p}`));
    }
    if (cert.extensions?.extended_key_usage?.length) {
      lines.push('• Extended Key Usage:', ...cert.extensions.extended_key_usage.map((u) => `  - ${u}`));
    }
  }

  if (tags.length > 0) {
    lines.push('', 'Tags:', ...tags.map((t) => `• ${t}`));
  }

  if (attributes.whois) {
    const keyFields = ['Organization:', 'OrgName:', 'Country:', 'City:', 'Address:', 'RegDate:', 'NetName:', 'NetType:'];
    const relevant = [...new Set(
      attributes.whois.split('\n').filter((line) => keyFields.some((f) => line.trim().startsWith(f)))
    )];
    if (relevant.length > 0) {
      lines.push('', 'WHOIS Information:', ...relevant.map((l) => `• ${l.trim()}`));
      if (attributes.whois_date) lines.push(`Last Updated: ${formatDateTime(attributes.whois_date)}`);
    }
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
