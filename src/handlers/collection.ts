import { z } from 'zod';
import { queryVirusTotal, queryVirusTotalWithRelationships } from '../utils/api.js';
import { formatCollectionResults } from '../formatters/index.js';
import { GetCollectionArgsSchema } from '../schemas/index.js';
import { logToFile } from '../utils/logging.js';

export async function handleGetCollection(args: z.infer<typeof GetCollectionArgsSchema>) {
  const { id, relationships } = args;
  logToFile(`Getting collection ${id}${relationships ? ` with relationships: ${relationships.join(',')}` : ''}`);

  const result = relationships && relationships.length > 0
    ? await queryVirusTotalWithRelationships(`/collections/${id}`, relationships)
    : await queryVirusTotal(`/collections/${id}`);

  return {
    content: [formatCollectionResults(result.data)],
  };
}
