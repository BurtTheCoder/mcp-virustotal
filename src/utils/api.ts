import { AxiosInstance, AxiosError } from 'axios';
import axios from 'axios';
import { logToFile } from './logging.js';

export interface VirusTotalErrorResponse {
  error?: {
    message?: string;
  };
}

// Helper Function to Query VirusTotal API
export async function queryVirusTotal(
  axiosInstance: AxiosInstance, 
  endpoint: string, 
  method: 'get' | 'post' = 'get', 
  data?: any,
  params?: Record<string, string | number | boolean>
) {
  if (!endpoint) {
    throw new Error('Endpoint is required');
  }
  try {
    // Log minimal request details
    logToFile(`${method.toUpperCase()} ${endpoint}`);
    
    if (params) {
      // Log only param keys, not values
      logToFile(`Request params: ${Object.keys(params).join(', ')}`);
    }
    
    const response = method === 'get' 
      ? await axiosInstance.get(endpoint, { params })
      : await axiosInstance.post(endpoint, data, { params });

    // Log minimal response info
    logToFile(`Response status: ${response.status}`);
    
    return response.data;
  } catch (error: any) {
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError<VirusTotalErrorResponse>;
      // Log only essential error info
      logToFile(`API Error: ${axiosError.response?.status} - ${
        axiosError.response?.data?.error?.message || axiosError.message
      }`);
      throw new Error(`VirusTotal API error: ${
        axiosError.response?.data?.error?.message || axiosError.message
      }`);
    }
    throw error;
  }
}

// Helper function to encode URL for VirusTotal API
export function encodeUrlForVt(url: string): string {
  return Buffer.from(url).toString('base64url');
}

// Helper function to get all available relationships for each type
export const RELATIONSHIPS = {
  url: [
    "analyses", "comments", "communicating_files", "contacted_domains", 
    "contacted_ips", "downloaded_files", "graphs", "last_serving_ip_address",
    "network_location", "referrer_files", "referrer_urls", "redirecting_urls",
    "redirects_to", "related_comments", "related_references", "related_threat_actors",
    "submissions"
  ],
  file: [
    "analyses", "behaviours", "bundled_files", "carbonblack_children",
    "carbonblack_parents", "ciphered_bundled_files", "ciphered_parents",
    "clues", "collections", "comments", "compressed_parents", "contacted_domains",
    "contacted_ips", "contacted_urls", "dropped_files", "email_attachments",
    "email_parents", "embedded_domains", "embedded_ips", "embedded_urls",
    "execution_parents", "graphs", "itw_domains", "itw_ips", "itw_urls",
    "memory_pattern_domains", "memory_pattern_ips", "memory_pattern_urls",
    "overlay_children", "overlay_parents", "pcap_children", "pcap_parents",
    "pe_resource_children", "pe_resource_parents", "related_references",
    "related_threat_actors", "similar_files", "submissions", "screenshots",
    "urls_for_embedded_js", "votes"
  ],
  ip: [
    "comments", "communicating_files", "downloaded_files", "graphs",
    "historical_ssl_certificates", "historical_whois", "related_comments",
    "related_references", "related_threat_actors", "referrer_files",
    "resolutions", "urls"
  ],
  domain: [
    "caa_records", "cname_records", "comments", "communicating_files",
    "downloaded_files", "graphs", "historical_ssl_certificates", "historical_whois",
    "immediate_parent", "mx_records", "ns_records", "parent", "referrer_files",
    "related_comments", "related_references", "related_threat_actors",
    "resolutions", "soa_records", "siblings", "subdomains", "urls", "user_votes"
  ]
} as const;

// Helper function to get relationships query parameter
export function getRelationshipsParam(type: keyof typeof RELATIONSHIPS): string {
  return RELATIONSHIPS[type].join(',');
}
