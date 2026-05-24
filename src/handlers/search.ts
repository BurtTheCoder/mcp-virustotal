import { z } from 'zod';
import { queryVirusTotal } from '../utils/api.js';
import { formatSearchResults } from '../formatters/index.js';
import { SearchArgsSchema } from '../schemas/index.js';
import { logToFile } from '../utils/logging.js';

export async function handleSearch(args: z.infer<typeof SearchArgsSchema>) {
  const { query, limit, cursor } = args;

  const params: Record<string, string | number> = { query, limit };
  if (cursor) params.cursor = cursor;

  logToFile(`Searching VT corpus: ${query}`);
  const result = await queryVirusTotal('/search', 'get', undefined, params);

  return {
    content: [formatSearchResults(query, result.data, result.meta)],
  };
}
