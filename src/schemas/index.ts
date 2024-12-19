import { z } from "zod";

// Common Schema for Pagination
export const PaginationSchema = z.object({
  limit: z.number().min(1).max(40).optional().default(10),
  cursor: z.string().optional(),
});

// Tool Schemas
export const GetUrlReportArgsSchema = z.object({
  url: z.string().url("Must be a valid URL").describe("The URL to analyze"),
});

export const GetUrlRelationshipArgsSchema = z.object({
  url: z.string().url("Must be a valid URL").describe("The URL to get relationships for"),
  relationship: z.enum([
    "analyses", "comments", "communicating_files", "contacted_domains", 
    "contacted_ips", "downloaded_files", "graphs", "last_serving_ip_address",
    "network_location", "referrer_files", "referrer_urls", "redirecting_urls",
    "redirects_to", "related_comments", "related_references", "related_threat_actors",
    "submissions"
  ]).describe("Type of relationship to query"),
}).merge(PaginationSchema);

export const GetFileReportArgsSchema = z.object({
  hash: z
    .string()
    .regex(/^[a-fA-F0-9]{32,64}$/, "Must be a valid MD5, SHA-1, or SHA-256 hash")
    .describe("MD5, SHA-1 or SHA-256 hash of the file"),
});

export const GetFileRelationshipArgsSchema = z.object({
  hash: z
    .string()
    .regex(/^[a-fA-F0-9]{32,64}$/, "Must be a valid MD5, SHA-1, or SHA-256 hash")
    .describe("MD5, SHA-1 or SHA-256 hash of the file"),
  relationship: z.enum([
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
  ]).describe("Type of relationship to query"),
}).merge(PaginationSchema);

export const GetIpReportArgsSchema = z.object({
  ip: z
    .string()
    .ip("Must be a valid IP address")
    .describe("IP address to analyze"),
});

export const GetIpRelationshipArgsSchema = z.object({
  ip: z
    .string()
    .ip("Must be a valid IP address")
    .describe("IP address to analyze"),
  relationship: z.enum([
    "comments", "communicating_files", "downloaded_files", "graphs",
    "historical_ssl_certificates", "historical_whois", "related_comments",
    "related_references", "related_threat_actors", "referrer_files",
    "resolutions", "urls"
  ]).describe("Type of relationship to query"),
}).merge(PaginationSchema);

// Define available domain relationships
export const DomainRelationships = [
  "caa_records",
  "cname_records",
  "comments",
  "communicating_files",
  "downloaded_files",
  "historical_ssl_certificates",
  "historical_whois",
  "immediate_parent",
  "mx_records",
  "ns_records",
  "parent",
  "referrer_files",
  "related_comments",
  "related_references",
  "related_threat_actors",
  "resolutions",
  "soa_records",
  "siblings",
  "subdomains",
  "urls",
  "user_votes"
] as const;

export const GetDomainReportArgsSchema = z.object({
  domain: z
    .string()
    .regex(/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/, "Must be a valid domain name")
    .describe("Domain name to analyze"),
  relationships: z.array(z.enum(DomainRelationships))
    .optional()
    .describe("Optional array of relationships to include in the report"),
});

export const GetDomainRelationshipArgsSchema = z.object({
  domain: z
    .string()
    .regex(/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/, "Must be a valid domain name")
    .describe("Domain name to analyze"),
  relationship: z.enum(DomainRelationships).describe("Type of relationship to query"),
}).merge(PaginationSchema);
