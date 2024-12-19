// utils/logging.ts

import fs from "fs";
import path from "path";
import { fileURLToPath } from 'url';

// Get the directory name of the current module
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Create logs directory in project root
const logsDir = path.join(__dirname, '..', '..', 'logs');

// Ensure logs directory exists with proper error handling
function ensureLogDirectory() {
  try {
    if (!fs.existsSync(logsDir)) {
      fs.mkdirSync(logsDir, { recursive: true });
    }
    return true;
  } catch (error) {
    console.error(`Failed to create logs directory: ${error}`);
    // Try to use a fallback directory in /tmp or user's home
    try {
      const tmpDir = process.platform === 'win32' 
        ? process.env.TEMP || process.env.TMP || 'C:\\Windows\\Temp'
        : '/tmp';
      const fallbackDir = path.join(tmpDir, 'mcp-virustotal-logs');
      if (!fs.existsSync(fallbackDir)) {
        fs.mkdirSync(fallbackDir, { recursive: true });
      }
      return fallbackDir;
    } catch (fallbackError) {
      console.error(`Failed to create fallback logs directory: ${fallbackError}`);
      return false;
    }
  }
}

// Initialize logging
const logDir = ensureLogDirectory();
const logFilePath = logDir === true 
  ? path.join(logsDir, "mcp-virustotal-server.log")
  : logDir 
    ? path.join(logDir, "mcp-virustotal-server.log")
    : null;

export function logToFile(message: string) {
  const timestamp = new Date().toISOString();
  const formattedMessage = `[${timestamp}] ${message}\n`;
  
  // Always log to console
  console.error(formattedMessage.trim());
  
  // Attempt to log to file if we have a valid path
  if (logFilePath) {
    try {
      fs.appendFileSync(logFilePath, formattedMessage, "utf8");
    } catch (error) {
      console.error(`Failed to write to log file: ${error}`);
    }
  }
}
