import { FormattedResult } from './types.js';
import { logToFile } from '../utils/logging.js';

const PREVIEW = 10;

function section(title: string, items: any[] | undefined, render: (item: any) => string): string[] {
  if (!items || items.length === 0) return [];
  const preview = items.slice(0, PREVIEW).map(render).filter(Boolean);
  const more = items.length > PREVIEW ? `    … and ${items.length - PREVIEW} more` : null;
  return [`${title} (${items.length}):`, ...preview.map((line) => `  - ${line}`), ...(more ? [more] : []), ''];
}

export function formatBehaviourSummary(hash: string, data: any): FormattedResult {
  try {
    if (!data) {
      return { type: 'text', text: `No sandbox behaviour summary available for ${hash}.` };
    }

    const lines: string[] = [
      `🧪 Sandbox Behaviour Summary`,
      `File: ${hash}`,
      '',
    ];

    if (data.verdicts?.length) {
      lines.push(`Verdicts: ${data.verdicts.join(', ')}`, '');
    }
    if (data.tags?.length) {
      lines.push(`Behaviour Tags: ${data.tags.join(', ')}`, '');
    }
    if (data.mitre_attack_techniques?.length) {
      lines.push('🎯 MITRE ATT&CK Techniques:');
      for (const t of data.mitre_attack_techniques.slice(0, PREVIEW)) {
        const id = t.id || t.signature_id || 'T?';
        const name = t.signature_description || t.description || '';
        const severity = t.severity ? ` [${t.severity}]` : '';
        lines.push(`  - ${id}${severity} ${name}`.trim());
      }
      if (data.mitre_attack_techniques.length > PREVIEW) {
        lines.push(`    … and ${data.mitre_attack_techniques.length - PREVIEW} more`);
      }
      lines.push('');
    }

    lines.push(
      ...section('🔧 Processes Created', data.processes_created, (p) => String(p)),
      ...section('💉 Processes Injected', data.processes_injected, (p) => String(p)),
      ...section('💀 Processes Terminated', data.processes_terminated, (p) => String(p)),
      ...section('⌨️  Command Executions', data.command_executions, (c) => String(c)),
      ...section('📂 Files Opened', data.files_opened, (f) => String(f)),
      ...section('✏️  Files Written', data.files_written, (f) => String(f)),
      ...section('📦 Files Dropped', data.files_dropped, (f) => `${f.path || ''} ${f.sha256 ? `(${f.sha256})` : ''}`.trim()),
      ...section('🗑️  Files Deleted', data.files_deleted, (f) => String(f)),
      ...section('🔑 Registry Keys Opened', data.registry_keys_opened, (r) => String(r)),
      ...section('📝 Registry Keys Set', data.registry_keys_set, (r) => `${r.key || ''} = ${r.value || ''}`.trim()),
      ...section('🧹 Registry Keys Deleted', data.registry_keys_deleted, (r) => String(r)),
      ...section('🌐 DNS Lookups', data.dns_lookups, (d) => `${d.hostname || ''}${d.resolved_ips?.length ? ` → ${d.resolved_ips.join(', ')}` : ''}`.trim()),
      ...section('📡 IP Traffic', data.ip_traffic, (t) => `${t.transport_layer_protocol || ''} ${t.destination_ip || ''}:${t.destination_port || ''}`.trim()),
      ...section('🌍 HTTP Conversations', data.http_conversations, (h) => `${h.request_method || 'GET'} ${h.url || ''}`.trim()),
      ...section('🔒 Mutexes Created', data.mutexes_created, (m) => String(m)),
      ...section('📚 Modules Loaded', data.modules_loaded, (m) => String(m)),
    );

    if (data.ids_results?.length) {
      lines.push(`🛡️  IDS Alerts (${data.ids_results.length}):`);
      for (const r of data.ids_results.slice(0, PREVIEW)) {
        const ctx = r.alert_context?.[0] || {};
        lines.push(
          `  - ${r.rule_msg || r.rule_id || 'alert'} [${r.alert_severity || 'info'}]`,
          `      ${ctx.proto || ''} ${ctx.src_ip || ''}:${ctx.src_port || ''} → ${ctx.dest_ip || ''}:${ctx.dest_port || ''}`.replace(/\s+/g, ' ').trim(),
        );
      }
      if (data.ids_results.length > PREVIEW) {
        lines.push(`    … and ${data.ids_results.length - PREVIEW} more`);
      }
      lines.push('');
    }

    if (data.signature_matches?.length) {
      lines.push(`🚨 Signature Matches (${data.signature_matches.length}):`);
      for (const s of data.signature_matches.slice(0, PREVIEW)) {
        lines.push(`  - ${s.id || ''} [${s.severity || 'info'}] ${s.description || ''}`.trim());
      }
      if (data.signature_matches.length > PREVIEW) {
        lines.push(`    … and ${data.signature_matches.length - PREVIEW} more`);
      }
    }

    return { type: 'text', text: lines.join('\n').trimEnd() };
  } catch (error) {
    logToFile(`Error formatting behaviour summary: ${error}`);
    return { type: 'text', text: 'Error formatting behaviour summary' };
  }
}
