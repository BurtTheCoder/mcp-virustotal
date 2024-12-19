// utils/logging.ts

import fs from "fs";
import path from "path";
import { fileURLToPath } from 'url';

// Get the directory name of the current module
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Create logs directory in project root
const logsDir = path.join(__dirname, '..', '..', 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
}

const logFilePath = path.join(logsDir, "mcp-virustotal-server.log");

export function logToFile(message: string) {
  try {
    const timestamp = new Date().toISOString();
    const formattedMessage = `[${timestamp}] ${message}\n`;
    fs.appendFileSync(logFilePath, formattedMessage, "utf8");
    console.error(formattedMessage.trim());
  } catch (error) {
    console.error(`Failed to write to log file: ${error}`);
  }
}
