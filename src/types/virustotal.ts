// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

export interface AnalysisStats {
  malicious: number;
  suspicious: number;
  undetected: number;
  harmless: number;
  timeout: number;
}

export interface RelationshipItem {
  type: string;
  id: string;
  attributes?: {
    hostname?: string;
    ip_address?: string;
    url?: string;
    name?: string;
    value?: string;
    date?: string | number;
    resolver?: string;
    host_name?: string;
    host_name_last_analysis_stats?: AnalysisStats;
    ip_address_last_analysis_stats?: AnalysisStats;
    type_description?: string;
    type?: string;
    first_submission_date?: number;
    last_analysis_date?: number;
    reputation?: number;
    meaningful_name?: string;
    [key: string]: unknown;
  };
  context_attributes?: {
    url?: string;
    timestamp?: number;
  };
  error?: {
    code: string;
    message: string;
  };
  formattedOutput?: string;
}

export interface RelationshipData {
  data: RelationshipItem | RelationshipItem[];
  meta?: {
    count?: number;
  };
  links?: {
    self?: string;
    related?: string;
    next?: string;
  };
}

export interface BaseAttributes {
  last_analysis_date?: number;
  last_analysis_stats?: AnalysisStats;
  reputation?: number;
  total_votes?: {
    harmless: number;
    malicious: number;
  };
}

export interface DomainAttributes extends BaseAttributes {
  categories?: Record<string, string>;
  last_dns_records?: Array<{
    type: string;
    value: string;
    ttl: number;
  }>;
  threat_severity?: {
    threat_severity_level: string;
    level_description?: string;
    threat_severity_data?: {
      num_detections: number;
      belongs_to_bad_collection: boolean;
    };
    last_analysis_date?: string;
  };
  popularity_ranks?: Record<string, { rank: number }>;
  whois?: string;
  creation_date?: number;
  last_modification_date?: number;
}

export interface DomainData {
  type?: string;
  id?: string;
  attributes?: DomainAttributes;
  relationships?: Record<string, RelationshipData>;
}

export interface VirusTotalResponse<T> {
  data: {
    type?: string;
    id?: string;
    attributes?: T;
    relationships?: Record<string, RelationshipData>;
  };
}

export type DomainResponse = VirusTotalResponse<DomainAttributes>;
