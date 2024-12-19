// src/formatters/file.ts
import { FormattedResult } from './types.js';
import { formatDateTime, formatDetectionResults } from './utils.js';
import { logToFile } from '../utils/logging.js';
import { RelationshipData } from '../types/virustotal.js';

interface SandboxVerdict {
  category: string;
  confidence: number;
  malware_classification?: string[];
  malware_names?: string[];
  sandbox_name: string;
}

interface CrowdsourcedIdsResult {
  alert_severity: string;
  rule_category: string;
  rule_id: string;
  rule_msg: string;
  rule_source: string;
  alert_context?: Array<{
    proto?: string;
    src_ip?: string;
    src_port?: number;
    dest_ip?: string;    // Add this
    dest_port?: number;  // Add this
    hostname?: string;   // Add this
    url?: string;       // Add this
  }>;
}

interface YaraResult {
  description: string;
  match_in_subfile: boolean;
  rule_name: string;
  ruleset_id: string;
  ruleset_name: string;
  source: string;
}

interface SigmaResult {
  rule_title: string;
  rule_source: string;
  rule_level: string;
  rule_description: string;
  rule_author: string;
  rule_id: string;
  match_context?: Array<{
    values: Record<string, string>;
  }>;
}

interface FileData {
  attributes?: any;
  relationships?: Record<string, RelationshipData>;
}

interface AnalysisStats {
  harmless: number;
  malicious: number;
  suspicious: number;
  undetected: number;
  timeout: number;
}

function formatRelationshipData(relType: string, item: any): string {
  const attrs = item.attributes || {};
  
  switch (relType) {
    case 'behaviours':
      const activities = [
        ...(attrs.processes_created || []),
        ...(attrs.command_executions || []),
        ...(attrs.activities_started || [])
      ].filter(Boolean);

      const files = [
        ...(attrs.files_opened || []),
        ...(attrs.files_written || [])
      ].filter(Boolean);

      const registry = [
        ...(attrs.registry_keys_opened || []),
        ...(attrs.registry_keys_set?.map((reg: any) => `${reg.key}: ${reg.value}`) || []),
        ...(attrs.registry_keys_deleted || [])
      ].filter(Boolean);

      const network = attrs.ids_results?.map((result: any) => {
        const ctx = result.alert_context || {};
        return `${result.rule_msg} (${ctx.protocol || 'unknown'} ${ctx.src_ip || ''}:${ctx.src_port || ''} -> ${ctx.dest_ip || ''}:${ctx.dest_port || ''})`;
      }) || [];

      return `  • Sandbox: ${attrs.sandbox_name || 'Unknown'}
    Activities (${activities.length}):${activities.length ? '\n      - ' + activities.slice(0, 5).join('\n      - ') + (activities.length > 5 ? '\n      ... and more' : '') : ' None'}
    Files (${files.length}):${files.length ? '\n      - ' + files.slice(0, 5).join('\n      - ') + (files.length > 5 ? '\n      ... and more' : '') : ' None'}
    Registry (${registry.length}):${registry.length ? '\n      - ' + registry.slice(0, 5).join('\n      - ') + (registry.length > 5 ? '\n      ... and more' : '') : ' None'}
    Network (${network.length}):${network.length ? '\n      - ' + network.slice(0, 5).join('\n      - ') + (network.length > 5 ? '\n      ... and more' : '') : ' None'}
    Verdicts: ${attrs.verdicts?.join(', ') || 'None'}`;

    case 'contacted_domains':
    case 'embedded_domains':
    case 'itw_domains':
      return `  • ${attrs.id || item.id}
    Categories: ${Object.entries(attrs.categories || {}).map(([k, v]) => `${k}: ${v}`).join(', ') || 'None'}
    Last Analysis Stats: ${attrs.last_analysis_stats ? 
      `🔴 ${attrs.last_analysis_stats.malicious} malicious, ✅ ${attrs.last_analysis_stats.harmless} harmless` : 
      'Unknown'}`;

    case 'contacted_ips':
    case 'embedded_ips':
    case 'itw_ips':
      return `  • ${attrs.ip_address || item.id}
    Country: ${attrs.country || 'Unknown'}
    AS Owner: ${attrs.as_owner || 'Unknown'}
    Last Analysis Stats: ${attrs.last_analysis_stats ? 
      `🔴 ${attrs.last_analysis_stats.malicious} malicious, ✅ ${attrs.last_analysis_stats.harmless} harmless` : 
      'Unknown'}`;

    case 'contacted_urls':
    case 'embedded_urls':
    case 'itw_urls':
      return `  • ${attrs.url || item.id}
    Last Analysis: ${attrs.last_analysis_date ? formatDateTime(attrs.last_analysis_date) : 'Unknown'}
    Reputation: ${attrs.reputation ?? 'Unknown'}`;

    case 'dropped_files':
      return `  • ${attrs.meaningful_name || attrs.names?.[0] || item.id}
    Type: ${attrs.type_description || attrs.type || 'Unknown'}
    Size: ${attrs.size ? formatFileSize(attrs.size) : 'Unknown'}
    First Seen: ${attrs.first_submission_date ? formatDateTime(attrs.first_submission_date) : 'Unknown'}
    Detection Stats: ${attrs.last_analysis_stats ? 
      `🔴 ${attrs.last_analysis_stats.malicious} malicious, ✅ ${attrs.last_analysis_stats.harmless} harmless` : 
      'Unknown'}`;

    case 'similar_files':
      return `  • ${attrs.meaningful_name || item.id}
    Type: ${attrs.type_description || attrs.type || 'Unknown'}
    Size: ${attrs.size ? formatFileSize(attrs.size) : 'Unknown'}
    First Seen: ${attrs.first_submission_date ? formatDateTime(attrs.first_submission_date) : 'Unknown'}`;

    case 'execution_parents':
      const stats = attrs.last_analysis_stats as AnalysisStats;
      const totalDetections = stats ? 
        Object.values(stats).reduce((a: number, b: number) => a + b, 0) : 0;
      return `  • ${attrs.meaningful_name || item.id}
    Type: ${attrs.type_description || attrs.type || 'Unknown'}
    First Seen: ${attrs.first_submission_date ? formatDateTime(attrs.first_submission_date) : 'Unknown'}
    Detection Ratio: ${stats ? `${stats.malicious}/${totalDetections}` : 'Unknown'}`;

    case 'related_threat_actors':
      return `  • ${attrs.name || item.id}
    Description: ${attrs.description || 'No description available'}`;

    default:
      return `  • ${item.id}`;
  }
}

export function formatFileResults(data: FileData): FormattedResult {
  try {
    const attributes = data?.attributes || {};
    const stats = attributes?.last_analysis_stats || {};
    const results = attributes?.last_analysis_results || {};
    const sandboxResults = attributes?.sandbox_verdicts || {};
    const sigmaResults = attributes?.sigma_analysis_results || [];
    const sigmaStats = attributes?.sigma_analysis_stats || {};
    const crowdsourcedIds = attributes?.crowdsourced_ids_results || [];
    const crowdsourcedIdsStats = attributes?.crowdsourced_ids_stats || {};
    const yaraResults = attributes?.crowdsourced_yara_results || [];
    
    let outputArray = [
      `📁 File Analysis Results`,
      `🔑 Hashes:`,
      `• SHA-256: ${attributes?.sha256 || 'Unknown'}`,
      `• SHA-1: ${attributes?.sha1 || 'Unknown'}`,
      `• MD5: ${attributes?.md5 || 'Unknown'}`,
      attributes?.vhash ? `• VHash: ${attributes.vhash}` : null,
      ``,
      `📄 File Information:`,
      `• Name: ${attributes?.meaningful_name || attributes?.names?.[0] || 'Unknown'}`,
      `• Type: ${attributes?.type_description || 'Unknown'}`,
      `• Size: ${attributes?.size ? formatFileSize(attributes.size) : 'Unknown'}`,
      `• First Seen: ${formatDateTime(attributes?.first_submission_date)}`,
      `• Last Modified: ${formatDateTime(attributes?.last_modification_date)}`,
      `• Times Submitted: ${attributes?.times_submitted || 0}`,
      `• Unique Sources: ${attributes?.unique_sources || 0}`,
      ``,
      `📊 Analysis Statistics:`,
      formatDetectionResults(stats),
    ].filter(Boolean);

    // Add reputation and votes
    const reputation = attributes?.reputation ?? 'N/A';
    const votes = attributes?.total_votes || {};
    outputArray.push(
      ``,
      `👥 Community Feedback:`,
      `• Reputation Score: ${reputation}`,
      `• Harmless Votes: ${votes.harmless || 0}`,
      `• Malicious Votes: ${votes.malicious || 0}`
    );

    // Add capabilities if available
    if (attributes?.capabilities_tags?.length > 0) {
      outputArray.push(
        ``,
        `⚡ Capabilities:`,
        ...attributes.capabilities_tags.map((tag: string) => `• ${formatCapabilityTag(tag)}`)
      );
    }

    // Add tags if available
    if (attributes?.tags?.length > 0) {
      outputArray.push(
        ``,
        `🏷️ Tags:`,
        ...attributes.tags.map((tag: string) => `• ${tag}`)
      );
    }

    // Add sandbox verdicts if available
    if (Object.keys(sandboxResults).length > 0) {
      outputArray.push(
        ``,
        `🔬 Sandbox Analysis Results:`
      );
      for (const [sandbox, verdict] of Object.entries(sandboxResults)) {
        const v = verdict as SandboxVerdict;
        outputArray.push(
          `${sandbox}:`,
          `• Category: ${v.category}`,
          `• Confidence: ${v.confidence}%`,
          ...(v.malware_classification ? [`• Classification: ${v.malware_classification.join(', ')}`] : []),
          ...(v.malware_names ? [`• Identified as: ${v.malware_names.join(', ')}`] : []),
          ``
        );
      }
    }

    // Add Sigma analysis results if available
    if (sigmaResults.length > 0 || Object.keys(sigmaStats).length > 0) {
      outputArray.push(
        ``,
        `🎯 Sigma Analysis:`,
        `Statistics:`,
        `• Critical: ${sigmaStats.critical || 0}`,
        `• High: ${sigmaStats.high || 0}`,
        `• Medium: ${sigmaStats.medium || 0}`,
        `• Low: ${sigmaStats.low || 0}`,
        ``
      );

      if (sigmaResults.length > 0) {
        outputArray.push(`Detected Rules:`);
        for (const result of sigmaResults) {
          const r = result as SigmaResult;
          outputArray.push(
            `${r.rule_title}:`,
            `• Level: ${r.rule_level}`,
            `• Source: ${r.rule_source}`,
            `• Description: ${r.rule_description}`,
            `• Author: ${r.rule_author}`,
            ``
          );
        }
      }
    }

    // Add crowdsourced IDS results if available
    if (crowdsourcedIds.length > 0) {
      outputArray.push(
        ``,
        `🛡️ Intrusion Detection Results:`,
        `Statistics:`,
        `• High: ${crowdsourcedIdsStats.high || 0}`,
        `• Medium: ${crowdsourcedIdsStats.medium || 0}`,
        `• Low: ${crowdsourcedIdsStats.low || 0}`,
        `• Info: ${crowdsourcedIdsStats.info || 0}`,
        ``
      );

      outputArray.push(`Alerts:`);
      for (const alert of crowdsourcedIds) {
        const a = alert as CrowdsourcedIdsResult;
        outputArray.push(
          `• ${a.rule_msg}`,
          `  - Severity: ${a.alert_severity}`,
          `  - Category: ${a.rule_category}`,
          `  - Source: ${a.rule_source}`,
          ``
        );
      }
    }

    // Add YARA results if available
    if (yaraResults.length > 0) {
      outputArray.push(
        ``,
        `🔍 YARA Detections:`
      );
      for (const yara of yaraResults) {
        const y = yara as YaraResult;
        outputArray.push(
          `• Rule: ${y.rule_name}`,
          `  - Description: ${y.description}`,
          `  - Ruleset: ${y.ruleset_name}`,
          `  - Source: ${y.source}`,
          ``
        );
      }
    }

    // Add popular engine results
    const popularEngines = Object.entries(results)
      .filter(([engine]) => ['Microsoft', 'Kaspersky', 'Symantec', 'McAfee'].includes(engine));

    if (popularEngines.length > 0) {
      outputArray.push(
        ``,
        `🔰 Popular Engines Results:`,
        ...popularEngines.map(([engine, result]: [string, any]) => 
          `• ${engine}: ${result?.result || 'Clean'} ${
            result?.category === 'malicious' ? '🔴' : 
            result?.category === 'suspicious' ? '⚠️' : '✅'
          }`
        )
      );
    }

    // Format relationships if available
    if (data.relationships) {
      outputArray.push('\n🔗 Relationships:');
      
      for (const [relType, relData] of Object.entries(data.relationships)) {
        const count = relData.meta?.count || (Array.isArray(relData.data) ? relData.data.length : 1);
        
        outputArray.push(`\n${relType} (${count} items):`);
        
        if (Array.isArray(relData.data)) {
          relData.data.forEach(item => {
            outputArray.push(formatRelationshipData(relType, item));
          });
        } else if (relData.data) {
          outputArray.push(formatRelationshipData(relType, relData.data));
        }
      }
    }

    return {
      type: "text",
      text: outputArray.filter(Boolean).join('\n')
    };
  } catch (error) {
    logToFile(`Error formatting file results: ${error}`);
    return {
      type: "text",
      text: "Error formatting file results"
    };
  }
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
  // Convert snake_case to Title Case and replace underscores with spaces
  return tag
    .split('_')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}
