// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

export function formatDateTime(timestamp: number | string | null): string {
  if (!timestamp) return 'N/A';
  try {
    const date = typeof timestamp === 'number' ? new Date(timestamp * 1000) : new Date(timestamp);
    return date.toLocaleString();
  } catch {
    return 'Invalid Date';
  }
}

export function formatPercentage(num: number, total: number): string {
  if (total === 0) return '0.0%';
  return `${((num / total) * 100).toFixed(1)}%`;
}

export function formatDetectionResults(results: {
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
} | null): string {
  const malicious = results?.malicious ?? 0;
  const suspicious = results?.suspicious ?? 0;
  const harmless = results?.harmless ?? 0;
  const undetected = results?.undetected ?? 0;
  const total = malicious + suspicious + harmless + undetected;

  if (total === 0) return 'No detection results available';

  return [
    'Detection Results:',
    `Malicious: ${malicious} (${formatPercentage(malicious, total)})`,
    `Suspicious: ${suspicious} (${formatPercentage(suspicious, total)})`,
    `Clean: ${harmless} (${formatPercentage(harmless, total)})`,
    `Undetected: ${undetected} (${formatPercentage(undetected, total)})`,
    `Total Scans: ${total}`,
  ].join('\n');
}
