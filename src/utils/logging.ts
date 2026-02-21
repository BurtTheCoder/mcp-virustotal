// SPDX-License-Identifier: MIT
// Copyright (c) 2024 TocharianOU Contributors

/**
 * Write a timestamped diagnostic message to stderr.
 *
 * Deliberately avoids file-system logging so the server is deployable without
 * write permissions and keeps stdout clean for MCP JSON-RPC frames.
 */
export function logToFile(message: string): void {
  const timestamp = new Date().toISOString();
  process.stderr.write(`[${timestamp}] ${message}\n`);
}
