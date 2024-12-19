// src/formatters/url.ts

import { FormattedResult } from './types.js';
import { formatDateTime, formatDetectionResults } from './utils.js';
import { logToFile } from '../utils/logging.js';
import { RelationshipData } from '../types/virustotal.js';

interface TrackerInstance {
  id: string;
  timestamp: number;
  url: string;
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
  total_votes?: {
    harmless: number;
    malicious: number;
  };
  favicon?: {
    dhash: string;
    raw_md5: string;
  };
  last_analysis_stats?: {
    harmless: number;
    malicious: number;
    suspicious: number;
    timeout: number;
    undetected: number;
  };
  last_analysis_results?: Record<string, {
    category: string;
    engine_name: string;
    method: string;
    result: string | null;
  }>;
}

export interface UrlData {
  id?: string;
  url?: string;
  attributes?: UrlAttributes;
  scan_id?: string;
  scan_date?: string;
  relationships?: Record<string, RelationshipData>;
}

function formatRelationshipData(relType: string, item: any): string {
  const attrs = item.attributes || {};
  
  switch (relType) {
    case 'communicating_files':
    case 'downloaded_files':
      return `  • ${attrs.meaningful_name || item.id}
    Type: ${attrs.type_description || attrs.type || 'Unknown'}
    First Seen: ${attrs.first_submission_date ? formatDateTime(attrs.first_submission_date) : 'Unknown'}`;

    case 'contacted_domains':
      return `  • ${attrs.id || item.id}
    Last DNS Resolution: ${attrs.last_dns_records_date ? formatDateTime(attrs.last_dns_records_date) : 'Unknown'}
    Categories: ${Object.entries(attrs.categories || {}).map(([k, v]) => `${k}: ${v}`).join(', ') || 'None'}`;

    case 'contacted_ips':
      return `  • ${attrs.ip_address || item.id}
    Country: ${attrs.country || 'Unknown'}
    AS Owner: ${attrs.as_owner || 'Unknown'}
    Last Analysis Stats: ${attrs.last_analysis_stats ? 
      `🔴 ${attrs.last_analysis_stats.malicious} malicious, ✅ ${attrs.last_analysis_stats.harmless} harmless` : 
      'Unknown'}`;

    case 'redirects_to':
    case 'redirecting_urls':
      return `  • ${attrs.url || item.id}
    Last Analysis: ${attrs.last_analysis_date ? formatDateTime(attrs.last_analysis_date) : 'Unknown'}
    Reputation: ${attrs.reputation ?? 'Unknown'}`;

    case 'related_threat_actors':
      return `  • ${attrs.name || item.id}
    Description: ${attrs.description || 'No description available'}`;

    default:
      return `  • ${item.id}`;
  }
}

export function formatUrlScanResults(data: UrlData): FormattedResult {
  try {
    const attributes = data?.attributes || {};
    const stats = attributes?.last_analysis_stats || {};
    const votes = attributes?.total_votes || { harmless: 0, malicious: 0 };
    const tags = attributes?.tags || [];
    const redirectionChain = attributes?.redirection_chain || [];
    const outgoingLinks = attributes?.outgoing_links || [];
    
    let outputArray = [
      `🔍 URL Analysis Results`,
      ``,
      `🌐 URL Information:`,
      `• URL: ${attributes?.url || data?.url || data?.id || 'Unknown URL'}`,
      attributes?.last_final_url && attributes.last_final_url !== attributes.url ? 
        `• Final URL: ${attributes.last_final_url}` : null,
      attributes?.title ? `• Page Title: ${attributes.title}` : null,
      `• First Seen: ${attributes.first_submission_date ? formatDateTime(attributes.first_submission_date) : 'N/A'}`,
      `• Last Analyzed: ${attributes.last_analysis_date ? formatDateTime(attributes.last_analysis_date) : 'N/A'}`,
      `• Times Submitted: ${attributes?.times_submitted || 0}`,
      ``,
      `📊 Analysis Statistics:`,
      formatDetectionResults(stats),
    ].filter(Boolean);

    // Add reputation and votes
    const reputation = attributes?.reputation ?? 'N/A';
    outputArray.push(
      ``,
      `👥 Community Feedback:`,
      `• Reputation Score: ${reputation}`,
      `• Harmless Votes: ${votes.harmless}`,
      `• Malicious Votes: ${votes.malicious}`
    );

    // Add HTTP response details
    if (attributes?.last_http_response_code) {
      outputArray.push(
        ``,
        `🌐 HTTP Response:`,
        `• Status Code: ${attributes.last_http_response_code}`,
        `• Content Length: ${formatSize(attributes.last_http_response_content_length || 0)}`,
        attributes.last_http_response_content_sha256 ? 
          `• Content SHA-256: ${attributes.last_http_response_content_sha256}` : null
      );
    }

    // Add categories if available
    if (attributes?.categories && Object.keys(attributes.categories).length > 0) {
      outputArray.push(
        ``,
        `🏷️ Categories:`,
        ...Object.entries(attributes.categories).map(([service, category]) => 
          `• ${service}: ${category}`
        )
      );
    }

    // Add redirection chain if available
    if (redirectionChain.length > 0) {
      outputArray.push(
        ``,
        `↪️ Redirection Chain:`,
        ...redirectionChain.map((url: string, index: number) => 
          `${index + 1}. ${url}`
        )
      );
    }

    // Add outgoing links if available
    if (outgoingLinks.length > 0) {
      outputArray.push(
        ``,
        `🔗 Outgoing Links:`,
        ...outgoingLinks.slice(0, 5).map((url: string) => `• ${url}`),
        outgoingLinks.length > 5 ? 
          `... and ${outgoingLinks.length - 5} more` : null
      );
    }

    // Add trackers if available
    if (attributes?.trackers && Object.keys(attributes.trackers).length > 0) {
      outputArray.push(
        ``,
        `📡 Trackers:`
      );
      for (const [tracker, instances] of Object.entries(attributes.trackers)) {
        if (Array.isArray(instances)) {
          outputArray.push(
            `${tracker}:`,
            ...instances.map((instance: TrackerInstance) => 
              `• ID: ${instance.id}${instance.url ? `\n  URL: ${instance.url}` : ''}`
            )
          );
        }
      }
    }

    // Add targeted brand if available
    if (attributes?.targeted_brand && Object.keys(attributes.targeted_brand).length > 0) {
      outputArray.push(
        ``,
        `🎯 Targeted Brands:`,
        ...Object.entries(attributes.targeted_brand).map(([source, brand]) => 
          `• ${source}: ${brand}`
        )
      );
    }

    // Add meta information if available
    if (attributes?.html_meta && Object.keys(attributes.html_meta).length > 0) {
      const relevantMeta = ['description', 'keywords', 'author'];
      const metaEntries = Object.entries(attributes.html_meta)
        .filter(([key]) => relevantMeta.includes(key));
      
      if (metaEntries.length > 0) {
        outputArray.push(
          ``,
          `📝 Meta Information:`
        );
        for (const [key, values] of metaEntries) {
          if (Array.isArray(values) && values.length > 0) {
            outputArray.push(`• ${key}: ${values[0]}`);
          }
        }
      }
    }

    // Add favicon information if available
    if (attributes?.favicon) {
      outputArray.push(
        ``,
        `🖼️ Favicon:`,
        `• Hash: ${attributes.favicon.dhash}`,
        `• MD5: ${attributes.favicon.raw_md5}`
      );
    }

    // Add tags if available
    if (tags.length > 0) {
      outputArray.push(
        ``,
        `🏷️ Tags:`,
        ...tags.map((tag: string) => `• ${tag}`)
      );
    }

    // Add HTTP response headers if available
    if (attributes?.last_http_response_headers && 
        Object.keys(attributes.last_http_response_headers).length > 0) {
      const importantHeaders = ['server', 'content-type', 'x-powered-by', 'x-frame-options', 'x-xss-protection'];
      const relevantHeaders = Object.entries(attributes.last_http_response_headers)
        .filter(([key]) => importantHeaders.includes(key.toLowerCase()));
      
      if (relevantHeaders.length > 0) {
        outputArray.push(
          ``,
          `📋 Important HTTP Headers:`
        );
        for (const [key, value] of relevantHeaders) {
          outputArray.push(`• ${key}: ${value}`);
        }
      }
    }

    // Add HTTP response cookies if available
    if (attributes?.last_http_response_cookies && 
        Object.keys(attributes.last_http_response_cookies).length > 0) {
      outputArray.push(
        ``,
        `🍪 Cookies:`,
        ...Object.entries(attributes.last_http_response_cookies)
          .map(([name, value]) => `• ${name}: ${value}`)
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
    logToFile(`Error formatting URL scan results: ${error}`);
    return {
      type: "text",
      text: "Error formatting URL scan results"
    };
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
