// Unit tests for the formatters. Run after `npm run build`.
// Uses node:test so we avoid adding test-framework deps.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  formatSearchResults,
  formatBehaviourSummary,
  formatCollectionResults,
  formatFileResults,
  formatUrlScanResults,
  formatIpResults,
  formatDomainResults,
  formatDetectionResults,
  formatDateTime,
} from '../build/formatters/index.js';

// ---------- utilities ----------

test('formatDateTime handles unix seconds, ISO strings, and null', () => {
  assert.match(formatDateTime(1700000000), /2023|2024/);
  assert.match(formatDateTime('2024-01-15T00:00:00Z'), /2024/);
  assert.equal(formatDateTime(null), 'N/A');
});

test('formatDetectionResults handles empty stats and a real distribution', () => {
  assert.match(formatDetectionResults({}), /No detection results available/);
  const text = formatDetectionResults({ malicious: 3, suspicious: 1, harmless: 50, undetected: 20 });
  assert.match(text, /Malicious: 3/);
  assert.match(text, /Total Scans: 74/);
});

// ---------- search ----------

test('formatSearchResults: empty results', () => {
  const out = formatSearchResults('nothing-here', [], {});
  assert.match(out.text, /Query: nothing-here/);
  assert.match(out.text, /No matching objects found/);
});

test('formatSearchResults: mixed file/url/domain/ip/comment items', () => {
  const out = formatSearchResults('test', [
    { type: 'file', id: 'abc', attributes: { meaningful_name: 'evil.exe', type_description: 'PE', sha256: 'abc', last_analysis_stats: { malicious: 5, harmless: 60, undetected: 5, suspicious: 0 } } },
    { type: 'url', id: 'urlid', attributes: { url: 'https://bad.example', title: 'Bad' } },
    { type: 'domain', id: 'bad.example' },
    { type: 'ip_address', id: '1.2.3.4', attributes: { as_owner: 'EvilCo', country: 'XX' } },
    { type: 'comment', id: 'cm1', attributes: { text: 'This file is malicious — see thread' } },
  ], { cursor: 'next-cursor' });
  assert.match(out.text, /file • evil.exe/);
  assert.match(out.text, /url • https:\/\/bad.example/);
  assert.match(out.text, /domain • bad.example/);
  assert.match(out.text, /ip • 1.2.3.4/);
  assert.match(out.text, /EvilCo \(XX\)/);
  assert.match(out.text, /comment • cm1/);
  assert.match(out.text, /cursor: next-cursor/);
});

// ---------- behaviour summary ----------

test('formatBehaviourSummary: minimal/empty payload does not crash', () => {
  const out = formatBehaviourSummary('deadbeef', {});
  assert.match(out.text, /Sandbox Behaviour Summary/);
  assert.match(out.text, /deadbeef/);
});

test('formatBehaviourSummary: full payload renders sections + proto field', () => {
  const out = formatBehaviourSummary('h1', {
    verdicts: ['malware'],
    tags: ['persistence', 'ransom'],
    mitre_attack_techniques: [
      { id: 'T1059', signature_description: 'Command and Scripting Interpreter', severity: 'HIGH' },
    ],
    processes_created: ['cmd.exe /c whoami', 'powershell.exe -enc ...'],
    files_dropped: [{ path: 'C:\\Users\\victim\\evil.exe', sha256: 'abc' }],
    registry_keys_set: [{ key: 'HKLM\\Run\\Evil', value: 'C:\\evil.exe' }],
    dns_lookups: [{ hostname: 'c2.example', resolved_ips: ['1.2.3.4'] }],
    ids_results: [
      {
        rule_msg: 'C2 Beacon',
        alert_severity: 'high',
        alert_context: [{ proto: 'TCP', src_ip: '10.0.0.1', src_port: 4444, dest_ip: '1.2.3.4', dest_port: 443 }],
      },
    ],
  });
  assert.match(out.text, /Verdicts: malware/);
  assert.match(out.text, /T1059 \[HIGH\]/);
  assert.match(out.text, /cmd.exe \/c whoami/);
  assert.match(out.text, /C:\\Users\\victim\\evil.exe \(abc\)/);
  assert.match(out.text, /HKLM\\Run\\Evil = C:\\evil.exe/);
  assert.match(out.text, /c2.example → 1.2.3.4/);
  assert.match(out.text, /C2 Beacon \[high\]/);
  assert.match(out.text, /TCP 10.0.0.1:4444 → 1.2.3.4:443/);
});

// ---------- collection ----------

test('formatCollectionResults: threat-actor with counts and relationships', () => {
  const out = formatCollectionResults({
    type: 'collection',
    id: 'threat-actor--example',
    attributes: {
      name: 'APT Example',
      collection_type: 'threat-actor',
      description: 'A well-known nation-state actor.',
      aliases: ['Group X', 'Actor Y'],
      tags: ['nation-state'],
      threat_categories: ['espionage'],
      motivations: ['intelligence-gathering'],
      source_region: 'XX',
      targeted_regions: ['US', 'EU'],
      targeted_industries: ['finance', 'energy'],
      files_count: 42,
      urls_count: 7,
      domains_count: 3,
      ip_addresses_count: 5,
      references_count: 12,
      creation_date: 1700000000,
      last_modification_date: 1710000000,
    },
    relationships: {
      files: { data: [{ id: 'f1', attributes: { meaningful_name: 'sample.exe' } }, { id: 'f2', attributes: {} }], meta: { count: 2 } },
    },
  });
  assert.match(out.text, /Collection: APT Example/);
  assert.match(out.text, /threat-actor/);
  assert.match(out.text, /Aliases: Group X, Actor Y/);
  assert.match(out.text, /Files: 42/);
  assert.match(out.text, /sample.exe/);
});

test('formatCollectionResults: minimal payload', () => {
  const out = formatCollectionResults({ id: 'x', attributes: {} });
  assert.match(out.text, /Collection: x/);
});

// ---------- file (the proto fix) ----------

test('formatFileResults: behaviours relationship reads alert_context.proto (not .protocol)', () => {
  const out = formatFileResults({
    attributes: { sha256: 'h', md5: 'm', sha1: 's' },
    relationships: {
      behaviours: {
        data: [{
          id: 'b1',
          attributes: {
            sandbox_name: 'TestBox',
            ids_results: [{
              rule_msg: 'Beacon',
              alert_context: { proto: 'UDP', src_ip: '10.0.0.1', src_port: 5000, dest_ip: '8.8.8.8', dest_port: 53 },
            }],
          },
        }],
        meta: { count: 1 },
      },
    },
  });
  // The protocol should render as UDP (not "unknown" — which was the old protocol/proto mismatch bug).
  assert.match(out.text, /UDP 10.0.0.1:5000 -> 8.8.8.8:53/);
  assert.doesNotMatch(out.text, /unknown 10.0.0.1/);
});

test('formatFileResults: minimal payload does not throw', () => {
  const out = formatFileResults({});
  assert.match(out.text, /File Analysis Results/);
});

// ---------- url / ip / domain ----------

test('formatUrlScanResults: handles missing relationships', () => {
  const out = formatUrlScanResults({ url: 'https://example.com', attributes: { last_analysis_stats: { malicious: 0, harmless: 90, undetected: 5, suspicious: 0 } } });
  assert.match(out.text, /URL Analysis Results/);
  assert.match(out.text, /example.com/);
});

test('formatIpResults: minimal', () => {
  const out = formatIpResults({ id: '1.1.1.1', attributes: {} });
  assert.match(out.text, /IP Address Analysis/);
  assert.match(out.text, /1.1.1.1/);
});

test('formatDomainResults: minimal', () => {
  const out = formatDomainResults({ id: 'example.com', attributes: {} });
  assert.match(out.text, /Domain Analysis Results/);
  assert.match(out.text, /example.com/);
});
