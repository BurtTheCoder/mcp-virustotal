import { AxiosInstance } from 'axios';
import { queryVirusTotal } from '../utils/api.js';
import { formatDomainResults } from '../formatters/index.js';
import { GetDomainReportArgsSchema } from '../schemas/index.js';
import { logToFile } from '../utils/logging.js';
import { RelationshipItem, RelationshipData, DomainResponse } from '../types/virustotal.js';

// Default relationships to fetch if none specified
const DEFAULT_RELATIONSHIPS = [
    'historical_whois',
    'historical_ssl_certificates',
    'resolutions',
    'communicating_files',
    'downloaded_files',
    'referrer_files'
] as const;

function formatDate(dateStr: string | number): string {
    try {
        if (typeof dateStr === 'number') {
            return new Date(dateStr * 1000).toLocaleDateString();
        }
        return new Date(dateStr).toLocaleDateString();
    } catch {
        return 'Unknown';
    }
}

function formatRelationshipData(relType: string, item: RelationshipItem): string {
    const attrs = item.attributes || {};
    
    switch (relType) {
        case 'resolutions':
            return `  • IP: ${attrs.ip_address} (${attrs.date ? new Date(Number(attrs.date) * 1000).toLocaleDateString() : 'Unknown'})
    Host: ${attrs.host_name || 'Unknown'}
    Analysis Stats:
    - IP: 🔴 ${attrs.ip_address_last_analysis_stats?.malicious || 0} malicious, ✅ ${attrs.ip_address_last_analysis_stats?.harmless || 0} harmless
    - Host: 🔴 ${attrs.host_name_last_analysis_stats?.malicious || 0} malicious, ✅ ${attrs.host_name_last_analysis_stats?.harmless || 0} harmless`;
            
        case 'communicating_files':
            return `  • ${attrs.meaningful_name || item.id}
    Type: ${attrs.type_description || attrs.type || 'Unknown'}
    First Seen: ${attrs.first_submission_date ? new Date(attrs.first_submission_date * 1000).toLocaleDateString() : 'Unknown'}`;
            
        case 'downloaded_files':
            return `  • ${attrs.meaningful_name || item.id}
    Type: ${attrs.type_description || attrs.type || 'Unknown'}
    First Seen: ${attrs.first_submission_date ? new Date(attrs.first_submission_date * 1000).toLocaleDateString() : 'Unknown'}`;
            
        case 'urls':
            return `  • ${attrs.url || item.id}
    Last Analysis: ${attrs.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toLocaleDateString() : 'Unknown'}
    Reputation: ${attrs.reputation ?? 'Unknown'}`;

        case 'historical_whois':
            const whoisMap = attrs.whois_map || {};
            const whoisInfo = [];
            if (whoisMap['Registrar']) whoisInfo.push(`Registrar: ${whoisMap['Registrar']}`);
            if (whoisMap['Creation Date']) whoisInfo.push(`Created: ${formatDate(whoisMap['Creation Date'])}`);
            if (whoisMap['Registry Expiry Date']) whoisInfo.push(`Expires: ${formatDate(whoisMap['Registry Expiry Date'])}`);
            if (whoisMap['Updated Date']) whoisInfo.push(`Updated: ${formatDate(whoisMap['Updated Date'])}`);
            if (whoisMap['Registrant Organization']) whoisInfo.push(`Organization: ${whoisMap['Registrant Organization']}`);
            if (attrs.registrar_name) whoisInfo.push(`Registrar: ${attrs.registrar_name}`);
            return `  • WHOIS Record from ${formatDate(attrs.last_updated || '')}${whoisInfo.length ? '\n    ' + whoisInfo.join('\n    ') : ''}`;

        case 'historical_ssl_certificates':
            const certInfo = [];
            if (attrs.subject?.CN) certInfo.push(`Subject: ${attrs.subject.CN}`);
            if (attrs.issuer?.CN) certInfo.push(`Issuer: ${attrs.issuer.CN}`);
            if (attrs.validity?.not_before) certInfo.push(`Valid From: ${formatDate(attrs.validity.not_before)}`);
            if (attrs.validity?.not_after) certInfo.push(`Valid Until: ${formatDate(attrs.validity.not_after)}`);
            if (attrs.serial_number) certInfo.push(`Serial: ${attrs.serial_number}`);
            const altNames = attrs.extensions?.subject_alternative_name;
            if (altNames && altNames.length) certInfo.push(`Alt Names: ${altNames.join(', ')}`);
            return `  • SSL Certificate${certInfo.length ? '\n    ' + certInfo.join('\n    ') : ''}`;

        case 'referrer_files':
            const stats = attrs.last_analysis_stats || {};
            const totalDetections = (Object.values(stats) as number[]).reduce((a, b) => a + b, 0);
            return `  • ${attrs.meaningful_name || item.id}
    Type: ${attrs.type_description || attrs.type || 'Unknown'}
    Detection Ratio: ${attrs.last_analysis_stats ? 
        `${attrs.last_analysis_stats.malicious}/${totalDetections}` : 
        'Unknown'}`;
            
        default:
            if (attrs.hostname) return `  • ${attrs.hostname}`;
            if (attrs.ip_address) return `  • ${attrs.ip_address}`;
            if (attrs.url) return `  • ${attrs.url}`;
            if (attrs.value) return `  • ${attrs.value}`;
            return `  • ${item.id}`;
    }
}

export async function handleGetDomainReport(axiosInstance: AxiosInstance, args: unknown) {
    const parsedArgs = GetDomainReportArgsSchema.safeParse(args);
    if (!parsedArgs.success) {
        throw new Error("Invalid domain format");
    }

    const { domain, relationships = DEFAULT_RELATIONSHIPS } = parsedArgs.data;

    // First get the basic domain report
    logToFile('Getting domain report...');
    const basicReport = await queryVirusTotal(
        axiosInstance,
        `/domains/${domain}`,
        'get'
    ) as DomainResponse;

    // Then get full data for specified relationships
    const relationshipData: Record<string, RelationshipData> = {};
    
    for (const relType of relationships) {
        logToFile(`Getting full data for ${relType}...`);
        try {
            const response = await queryVirusTotal(
                axiosInstance,
                `/domains/${domain}/${relType}`,
                'get'
            );

            // Format the relationship data
            if (Array.isArray(response.data)) {
                relationshipData[relType] = {
                    data: response.data.map((item: RelationshipItem) => ({
                        ...item,
                        formattedOutput: formatRelationshipData(relType, item)
                    })),
                    meta: response.meta
                };
            } else if (response.data) {
                relationshipData[relType] = {
                    data: {
                        ...response.data,
                        formattedOutput: formatRelationshipData(relType, response.data)
                    },
                    meta: response.meta
                };
            }
        } catch (error) {
            logToFile(`Error fetching ${relType} data: ${error}`);
            // Continue with other relationships even if one fails
        }
    }

    // Combine the basic report with detailed relationships
    const combinedData = {
        ...basicReport.data,
        relationships: relationshipData
    };

    return {
        content: [
            formatDomainResults(combinedData)
        ],
    };
}
