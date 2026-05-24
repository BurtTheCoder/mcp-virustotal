import { z } from 'zod';
import { RELATIONSHIPS } from '../utils/api.js';

// Common Schema for Pagination
export const PaginationSchema = z.object({
  limit: z.number().min(1).max(40).optional().default(10),
  cursor: z.string().optional(),
});

// Tool Schemas
export const GetUrlReportArgsSchema = z.object({
  url: z.string().url('Must be a valid URL').describe('The URL to analyze'),
});

export const GetUrlRelationshipArgsSchema = z.object({
  url: z.string().url('Must be a valid URL').describe('The URL to get relationships for'),
  relationship: z.enum(RELATIONSHIPS.url).describe('Type of relationship to query'),
}).merge(PaginationSchema);

export const GetFileReportArgsSchema = z.object({
  hash: z
    .string()
    .regex(/^[a-fA-F0-9]{32,64}$/, 'Must be a valid MD5, SHA-1, or SHA-256 hash')
    .describe('MD5, SHA-1 or SHA-256 hash of the file'),
});

export const GetFileRelationshipArgsSchema = z.object({
  hash: z
    .string()
    .regex(/^[a-fA-F0-9]{32,64}$/, 'Must be a valid MD5, SHA-1, or SHA-256 hash')
    .describe('MD5, SHA-1 or SHA-256 hash of the file'),
  relationship: z.enum(RELATIONSHIPS.file).describe('Type of relationship to query'),
}).merge(PaginationSchema);

export const GetIpReportArgsSchema = z.object({
  ip: z
    .string()
    .ip('Must be a valid IP address')
    .describe('IP address to analyze'),
});

export const GetIpRelationshipArgsSchema = z.object({
  ip: z
    .string()
    .ip('Must be a valid IP address')
    .describe('IP address to analyze'),
  relationship: z.enum(RELATIONSHIPS.ip).describe('Type of relationship to query'),
}).merge(PaginationSchema);

export const GetDomainReportArgsSchema = z.object({
  domain: z
    .string()
    .regex(/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/, 'Must be a valid domain name')
    .describe('Domain name to analyze'),
  relationships: z.array(z.enum(RELATIONSHIPS.domain))
    .optional()
    .describe('Optional array of relationships to include in the report'),
});

export const GetDomainRelationshipArgsSchema = z.object({
  domain: z
    .string()
    .regex(/^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/, 'Must be a valid domain name')
    .describe('Domain name to analyze'),
  relationship: z.enum(RELATIONSHIPS.domain).describe('Type of relationship to query'),
}).merge(PaginationSchema);
