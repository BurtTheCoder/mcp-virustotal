// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

import axios, { AxiosInstance, AxiosError } from 'axios';
import { VirusTotalError } from '../types.js';
import { logToFile } from './logging.js';

interface VirusTotalErrorResponse {
  error?: {
    code?: string;
    message?: string;
  };
}

/**
 * Send a request to the VirusTotal (or proxy) API and return the parsed response body.
 *
 * @throws {VirusTotalError} on any HTTP / network failure
 */
export async function queryVirusTotal(
  client: AxiosInstance,
  endpoint: string,
  method: 'get' | 'post' = 'get',
  data?: unknown,
  params?: Record<string, string | number | boolean>
): Promise<unknown> {
  if (!endpoint) {
    throw new VirusTotalError('endpoint is required');
  }

  logToFile(`${method.toUpperCase()} ${endpoint}`);

  try {
    const response =
      method === 'get'
        ? await client.get(endpoint, { params })
        : await client.post(endpoint, data, { params });

    logToFile(`Response ${response.status} ${endpoint}`);
    return response.data;
  } catch (error: unknown) {
    if (axios.isAxiosError(error)) {
      const axiosError = error as AxiosError<VirusTotalErrorResponse>;
      const statusCode = axiosError.response?.status;
      const apiMessage =
        axiosError.response?.data?.error?.message ?? axiosError.message;

      logToFile(`API error ${statusCode ?? 'network'}: ${apiMessage}`);
      throw new VirusTotalError(`VirusTotal API error: ${apiMessage}`, statusCode);
    }

    throw error;
  }
}

/**
 * Encode a plain URL to the base64url identifier used by the VirusTotal v3 API.
 */
export function encodeUrlForVt(url: string): string {
  return Buffer.from(url).toString('base64url');
}

/**
 * All recognised relationship names grouped by resource type.
 */
export const RELATIONSHIPS = {
  url: [
    'analyses',
    'comments',
    'communicating_files',
    'contacted_domains',
    'contacted_ips',
    'downloaded_files',
    'graphs',
    'last_serving_ip_address',
    'network_location',
    'referrer_files',
    'referrer_urls',
    'redirecting_urls',
    'redirects_to',
    'related_comments',
    'related_references',
    'related_threat_actors',
    'submissions',
  ],
  file: [
    'analyses',
    'behaviours',
    'bundled_files',
    'carbonblack_children',
    'carbonblack_parents',
    'ciphered_bundled_files',
    'ciphered_parents',
    'clues',
    'collections',
    'comments',
    'compressed_parents',
    'contacted_domains',
    'contacted_ips',
    'contacted_urls',
    'dropped_files',
    'email_attachments',
    'email_parents',
    'embedded_domains',
    'embedded_ips',
    'embedded_urls',
    'execution_parents',
    'graphs',
    'itw_domains',
    'itw_ips',
    'itw_urls',
    'memory_pattern_domains',
    'memory_pattern_ips',
    'memory_pattern_urls',
    'overlay_children',
    'overlay_parents',
    'pcap_children',
    'pcap_parents',
    'pe_resource_children',
    'pe_resource_parents',
    'related_references',
    'related_threat_actors',
    'similar_files',
    'submissions',
    'screenshots',
    'urls_for_embedded_js',
    'votes',
  ],
  ip: [
    'comments',
    'communicating_files',
    'downloaded_files',
    'graphs',
    'historical_ssl_certificates',
    'historical_whois',
    'related_comments',
    'related_references',
    'related_threat_actors',
    'referrer_files',
    'resolutions',
    'urls',
  ],
  domain: [
    'caa_records',
    'cname_records',
    'comments',
    'communicating_files',
    'downloaded_files',
    'graphs',
    'historical_ssl_certificates',
    'historical_whois',
    'immediate_parent',
    'mx_records',
    'ns_records',
    'parent',
    'referrer_files',
    'related_comments',
    'related_references',
    'related_threat_actors',
    'resolutions',
    'soa_records',
    'siblings',
    'subdomains',
    'urls',
    'user_votes',
  ],
} as const;

/**
 * Return the comma-joined list of all relationship names for a resource type.
 * Used as the `relationships` query parameter in VT API calls.
 */
export function getRelationshipsParam(type: keyof typeof RELATIONSHIPS): string {
  return RELATIONSHIPS[type].join(',');
}
