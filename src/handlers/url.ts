import { z } from 'zod';
import {
  queryVirusTotal,
  queryVirusTotalWithRelationships,
  encodeUrlForVt,
  VirusTotalApiError,
} from '../utils/api.js';
import { formatUrlScanResults } from '../formatters/index.js';
import { GetUrlReportArgsSchema, GetUrlRelationshipArgsSchema } from '../schemas/index.js';
import { logToFile } from '../utils/logging.js';

const DEFAULT_RELATIONSHIPS = [
  'communicating_files',
  'contacted_domains',
  'contacted_ips',
  'downloaded_files',
  'redirects_to',
  'redirecting_urls',
  'related_threat_actors',
] as const;

const POLL_INTERVAL_MS = 5000;
const POLL_MAX_ATTEMPTS = 12; // ~60s total

async function waitForAnalysis(analysisId: string): Promise<void> {
  for (let attempt = 0; attempt < POLL_MAX_ATTEMPTS; attempt++) {
    const response = await queryVirusTotal(`/analyses/${analysisId}`);
    const status = response?.data?.attributes?.status;
    if (status === 'completed') return;
    logToFile(`Analysis ${analysisId} status=${status}, retrying in ${POLL_INTERVAL_MS}ms`);
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  throw new Error(
    `URL analysis ${analysisId} did not complete within ${(POLL_MAX_ATTEMPTS * POLL_INTERVAL_MS) / 1000}s`,
  );
}

export async function handleGetUrlReport(args: z.infer<typeof GetUrlReportArgsSchema>) {
  const { url } = args;
  const encodedUrl = encodeUrlForVt(url);

  let report;
  try {
    logToFile(`Fetching cached URL report for ${url}`);
    report = await queryVirusTotalWithRelationships(`/urls/${encodedUrl}`, DEFAULT_RELATIONSHIPS);
  } catch (error) {
    if (error instanceof VirusTotalApiError && error.status === 404) {
      logToFile(`No cached report for ${url}; submitting for scan`);
      const scanResponse = await queryVirusTotal(
        '/urls',
        'post',
        new URLSearchParams({ url }),
      );
      await waitForAnalysis(scanResponse.data.id);
      report = await queryVirusTotalWithRelationships(`/urls/${encodedUrl}`, DEFAULT_RELATIONSHIPS);
    } else {
      throw error;
    }
  }

  return {
    content: [
      formatUrlScanResults({
        id: report.data?.id,
        url,
        attributes: report.data?.attributes,
        relationships: report.data?.relationships,
      }),
    ],
  };
}

export async function handleGetUrlRelationship(args: z.infer<typeof GetUrlRelationshipArgsSchema>) {
  const { url, relationship, limit, cursor } = args;
  const encodedUrl = encodeUrlForVt(url);

  const params: Record<string, string | number> = { limit };
  if (cursor) params.cursor = cursor;

  logToFile(`Fetching ${relationship} for URL: ${url}`);
  const result = await queryVirusTotal(
    `/urls/${encodedUrl}/${relationship}`,
    'get',
    undefined,
    params,
  );

  return {
    content: [
      formatUrlScanResults({
        url,
        relationships: {
          [relationship]: {
            data: result.data,
            meta: result.meta,
          },
        },
      }),
    ],
  };
}
