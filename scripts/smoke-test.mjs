#!/usr/bin/env node
// Live smoke test against the VirusTotal API. Requires VIRUSTOTAL_API_KEY.
// Paces calls at ~20s to stay under the 500/day, 4/min public quota.
// Usage: npm run smoke
import { initVirusTotalClient } from '../build/utils/api.js';
import {
  handleGetUrlReport,
  handleGetUrlRelationship,
  handleGetFileReport,
  handleGetFileRelationship,
  handleGetFileBehaviourSummary,
  handleGetIpReport,
  handleGetIpRelationship,
  handleGetDomainReport,
  handleGetDomainRelationship,
  handleSearch,
  handleGetCollection,
} from '../build/handlers/index.js';

if (!process.env.VIRUSTOTAL_API_KEY) {
  console.error('Set VIRUSTOTAL_API_KEY first');
  process.exit(1);
}

initVirusTotalClient();

const PACING_MS = 20000;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Known-good IOCs
const EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
const WANNACRY_SHA256 = 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa';

let pass = 0;
let fail = 0;
const failures = [];

async function run(name, fn) {
  const start = Date.now();
  try {
    const result = await fn();
    const text = result?.content?.[0]?.text || '';
    const lines = text.split('\n');
    console.log(`\n✓ ${name} — ${Date.now() - start}ms, ${text.length} chars, ${lines.length} lines`);
    console.log(lines.slice(0, 6).join('\n').replace(/^/gm, '    '));
    if (lines.length > 6) console.log(`    … (${lines.length - 6} more lines)`);
    pass++;
  } catch (err) {
    console.log(`\n✗ ${name}\n    ${err.message}`);
    failures.push({ name, message: err.message });
    fail++;
  }
}

const tests = [
  ['get_domain_report (google.com)', () => handleGetDomainReport({ domain: 'google.com' })],
  ['get_domain_relationship (subdomains)', () => handleGetDomainRelationship({ domain: 'google.com', relationship: 'subdomains', limit: 5 })],
  ['get_ip_report (8.8.8.8)', () => handleGetIpReport({ ip: '8.8.8.8' })],
  ['get_ip_relationship (resolutions)', () => handleGetIpRelationship({ ip: '8.8.8.8', relationship: 'resolutions', limit: 5 })],
  ['get_url_report (https://www.google.com)', () => handleGetUrlReport({ url: 'https://www.google.com' })],
  ['get_url_relationship (contacted_domains)', () => handleGetUrlRelationship({ url: 'https://www.google.com', relationship: 'contacted_domains', limit: 5 })],
  ['get_file_report (EICAR)', () => handleGetFileReport({ hash: EICAR_SHA256 })],
  ['get_file_relationship (similar_files)', () => handleGetFileRelationship({ hash: EICAR_SHA256, relationship: 'similar_files', limit: 5 })],
  ['get_file_behaviour_summary (WannaCry)', () => handleGetFileBehaviourSummary({ hash: WANNACRY_SHA256 })],
  ['search_vt (query: google.com)', () => handleSearch({ query: 'google.com', limit: 5 })],
  ['get_collection (probably-404)', () => handleGetCollection({ id: 'threat-actor--apt28' })],
];

console.log(`\nRunning ${tests.length} live smoke tests (pacing ${PACING_MS / 1000}s between calls)…`);
console.log(`Expected duration: ~${Math.round((tests.length * PACING_MS) / 1000)}s\n`);

let first = true;
for (const [name, fn] of tests) {
  if (!first) await sleep(PACING_MS);
  first = false;
  await run(name, fn);
}

console.log(`\n\n=== ${pass} passed, ${fail} failed ===`);
if (failures.length) {
  console.log('\nFailures:');
  for (const f of failures) console.log(`  - ${f.name}: ${f.message}`);
}
process.exit(fail > 0 ? 1 : 0);
