// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import { FormattedResult } from './types.js';
import { formatDateTime, formatDetectionResults } from './utils.js';
import { RelationshipData, RelationshipItem, AnalysisStats } from '../types/virustotal.js';

interface SandboxVerdict {
  category: string;
  confidence: number;
  malware_classification?: string[];
  malware_names?: string[];
  sandbox_name: string;
}

interface CrowdsourcedIdsAlert {
  alert_severity: string;
  rule_category: string;
  rule_id: string;
  rule_msg: string;
  rule_source: string;
}

interface YaraResult {
  description: string;
  rule_name: string;
  ruleset_name: string;
  source: string;
}

interface SigmaResult {
  rule_title: string;
  rule_source: string;
  rule_level: string;
  rule_description: string;
  rule_author: string;
}

interface FileAttributes {
  sha256?: string;
  sha1?: string;
  md5?: string;
  vhash?: string;
  meaningful_name?: string;
  names?: string[];
  type_description?: string;
  size?: number;
  first_submission_date?: number;
  last_modification_date?: number;
  times_submitted?: number;
  unique_sources?: number;
  reputation?: number;
  total_votes?: { harmless: number; malicious: number };
  last_analysis_stats?: AnalysisStats;
  last_analysis_results?: Record<string, { category?: string; result?: string | null }>;
  sandbox_verdicts?: Record<string, SandboxVerdict>;
  sigma_analysis_results?: SigmaResult[];
  sigma_analysis_stats?: Record<string, number>;
  crowdsourced_ids_results?: CrowdsourcedIdsAlert[];
  crowdsourced_ids_stats?: Record<string, number>;
  crowdsourced_yara_results?: YaraResult[];
  capabilities_tags?: string[];
  tags?: string[];
}

interface FileData {
  id?: string;
  attributes?: FileAttributes;
  relationships?: Record<string, RelationshipData>;
}

function formatFileSize(bytes: number): string {
  const units = ['B', 'KB', 'MB', 'GB'];
  let size = bytes;
  let unitIndex = 0;
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex++;
  }
  return `${size.toFixed(2)} ${units[unitIndex]}`;
}

function formatCapabilityTag(tag: string): string {
  return tag
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

function formatRelationshipItem(relType: string, item: RelationshipItem): string {
  const attrs = item.attributes ?? {};

  switch (relType) {
    case 'behaviours': {
      const processes = (attrs.processes_created as string[] | undefined) ?? [];
      const commands = (attrs.command_executions as string[] | undefined) ?? [];
      const activities = [...processes, ...commands].filter(Boolean);
      const files = [
        ...((attrs.files_opened as string[] | undefined) ?? []),
        ...((attrs.files_written as string[] | undefined) ?? []),
      ].filter(Boolean);
      const registry = [
        ...((attrs.registry_keys_opened as string[] | undefined) ?? []),
        ...((attrs.registry_keys_deleted as string[] | undefined) ?? []),
      ].filter(Boolean);
      return (
        `  • Sandbox: ${attrs.sandbox_name ?? 'Unknown'}\n` +
        `    Activities (${activities.length}):${activities.length ? '\n      - ' + activities.slice(0, 5).join('\n      - ') : ' None'}\n` +
        `    Files (${files.length}):${files.length ? '\n      - ' + files.slice(0, 5).join('\n      - ') : ' None'}\n` +
        `    Registry (${registry.length}):${registry.length ? '\n      - ' + registry.slice(0, 5).join('\n      - ') : ' None'}`
      );
    }

    case 'contacted_domains':
    case 'embedded_domains':
    case 'itw_domains':
      return (
        `  • ${item.id}\n` +
        `    Categories: ${Object.entries((attrs.categories as Record<string, string>) ?? {}).map(([k, v]) => `${k}: ${v}`).join(', ') || 'None'}`
      );

    case 'contacted_ips':
    case 'embedded_ips':
    case 'itw_ips':
      return (
        `  • ${attrs.ip_address ?? item.id}\n` +
        `    Country: ${attrs.country ?? 'Unknown'}\n` +
        `    AS Owner: ${attrs.as_owner ?? 'Unknown'}`
      );

    case 'contacted_urls':
    case 'embedded_urls':
    case 'itw_urls':
      return (
        `  • ${attrs.url ?? item.id}\n` +
        `    Last Analysis: ${attrs.last_analysis_date ? formatDateTime(attrs.last_analysis_date as number) : 'Unknown'}\n` +
        `    Reputation: ${attrs.reputation ?? 'Unknown'}`
      );

    case 'dropped_files':
    case 'similar_files': {
      const nameList = attrs.names as string[] | undefined;
      return (
        `  • ${attrs.meaningful_name ?? nameList?.[0] ?? item.id}\n` +
        `    Type: ${attrs.type_description ?? attrs.type ?? 'Unknown'}\n` +
        `    Size: ${attrs.size ? formatFileSize(attrs.size as number) : 'Unknown'}`
      );
    }

    case 'execution_parents': {
      const fileStats = (attrs.last_analysis_stats as AnalysisStats | undefined) ?? null;
      const total = fileStats ? Object.values(fileStats).reduce((a, b) => a + b, 0) : 0;
      return (
        `  • ${attrs.meaningful_name ?? item.id}\n` +
        `    Type: ${attrs.type_description ?? attrs.type ?? 'Unknown'}\n` +
        `    Detection Ratio: ${fileStats ? `${fileStats.malicious}/${total}` : 'Unknown'}`
      );
    }

    case 'related_threat_actors':
      return `  • ${attrs.name ?? item.id}\n    Description: ${attrs.description ?? 'No description available'}`;

    default:
      return `  • ${item.id}`;
  }
}

export function formatFileResults(data: FileData): FormattedResult {
  const attributes = data.attributes ?? {};
  const stats = attributes.last_analysis_stats ?? null;
  const sandboxResults = attributes.sandbox_verdicts ?? {};
  const sigmaResults = attributes.sigma_analysis_results ?? [];
  const sigmaStats = attributes.sigma_analysis_stats ?? {};
  const crowdsourcedIds = attributes.crowdsourced_ids_results ?? [];
  const crowdsourcedIdsStats = attributes.crowdsourced_ids_stats ?? {};
  const yaraResults = attributes.crowdsourced_yara_results ?? [];
  const popularEngineNames = ['Microsoft', 'Kaspersky', 'Symantec', 'McAfee'];
  const results = attributes.last_analysis_results ?? {};
  const votes = attributes.total_votes ?? { harmless: 0, malicious: 0 };

  const lines: (string | null)[] = [
    'File Analysis Results',
    '',
    'Hashes:',
    `• SHA-256: ${attributes.sha256 ?? 'Unknown'}`,
    `• SHA-1: ${attributes.sha1 ?? 'Unknown'}`,
    `• MD5: ${attributes.md5 ?? 'Unknown'}`,
    attributes.vhash ? `• VHash: ${attributes.vhash}` : null,
    '',
    'File Information:',
    `• Name: ${attributes.meaningful_name ?? attributes.names?.[0] ?? 'Unknown'}`,
    `• Type: ${attributes.type_description ?? 'Unknown'}`,
    `• Size: ${attributes.size ? formatFileSize(attributes.size) : 'Unknown'}`,
    `• First Seen: ${formatDateTime(attributes.first_submission_date ?? null)}`,
    `• Last Modified: ${formatDateTime(attributes.last_modification_date ?? null)}`,
    `• Times Submitted: ${attributes.times_submitted ?? 0}`,
    `• Unique Sources: ${attributes.unique_sources ?? 0}`,
    '',
    'Analysis Statistics:',
    formatDetectionResults(stats),
    '',
    'Community Feedback:',
    `• Reputation Score: ${attributes.reputation ?? 'N/A'}`,
    `• Harmless Votes: ${votes.harmless}`,
    `• Malicious Votes: ${votes.malicious}`,
  ];

  if ((attributes.capabilities_tags?.length ?? 0) > 0) {
    lines.push('', 'Capabilities:', ...(attributes.capabilities_tags ?? []).map((t) => `• ${formatCapabilityTag(t)}`));
  }

  if ((attributes.tags?.length ?? 0) > 0) {
    lines.push('', 'Tags:', ...(attributes.tags ?? []).map((t) => `• ${t}`));
  }

  if (Object.keys(sandboxResults).length > 0) {
    lines.push('', 'Sandbox Analysis Results:');
    for (const [sandbox, v] of Object.entries(sandboxResults)) {
      lines.push(
        `${sandbox}:`,
        `• Category: ${v.category}`,
        `• Confidence: ${v.confidence}%`,
        ...(v.malware_classification ? [`• Classification: ${v.malware_classification.join(', ')}`] : []),
        ...(v.malware_names ? [`• Identified as: ${v.malware_names.join(', ')}`] : []),
        ''
      );
    }
  }

  if (sigmaResults.length > 0 || Object.keys(sigmaStats).length > 0) {
    lines.push(
      '',
      'Sigma Analysis:',
      'Statistics:',
      `• Critical: ${sigmaStats['critical'] ?? 0}`,
      `• High: ${sigmaStats['high'] ?? 0}`,
      `• Medium: ${sigmaStats['medium'] ?? 0}`,
      `• Low: ${sigmaStats['low'] ?? 0}`,
      ''
    );
    if (sigmaResults.length > 0) {
      lines.push('Detected Rules:');
      for (const r of sigmaResults) {
        lines.push(`${r.rule_title}:`, `• Level: ${r.rule_level}`, `• Source: ${r.rule_source}`, `• Author: ${r.rule_author}`, '');
      }
    }
  }

  if (crowdsourcedIds.length > 0) {
    lines.push(
      '',
      'Intrusion Detection Results:',
      'Statistics:',
      `• High: ${crowdsourcedIdsStats['high'] ?? 0}`,
      `• Medium: ${crowdsourcedIdsStats['medium'] ?? 0}`,
      `• Low: ${crowdsourcedIdsStats['low'] ?? 0}`,
      `• Info: ${crowdsourcedIdsStats['info'] ?? 0}`,
      '',
      'Alerts:'
    );
    for (const a of crowdsourcedIds) {
      lines.push(`• ${a.rule_msg}`, `  - Severity: ${a.alert_severity}`, `  - Category: ${a.rule_category}`, `  - Source: ${a.rule_source}`, '');
    }
  }

  if (yaraResults.length > 0) {
    lines.push('', 'YARA Detections:');
    for (const y of yaraResults) {
      lines.push(`• Rule: ${y.rule_name}`, `  - Description: ${y.description}`, `  - Ruleset: ${y.ruleset_name}`, `  - Source: ${y.source}`, '');
    }
  }

  const popularEngines = Object.entries(results).filter(([name]) => popularEngineNames.includes(name));
  if (popularEngines.length > 0) {
    lines.push('', 'Popular Engines Results:');
    for (const [engine, result] of popularEngines) {
      lines.push(`• ${engine}: ${result.result ?? 'Clean'} [${result.category ?? 'unknown'}]`);
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
