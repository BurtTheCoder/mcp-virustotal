#!/bin/bash

# Load environment variables from .env file
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Set HTTP transport mode
export MCP_TRANSPORT=http
export MCP_HTTP_PORT=${MCP_HTTP_PORT:-3000}
export MCP_HTTP_HOST=${MCP_HTTP_HOST:-localhost}

echo "Starting VirusTotal MCP Server in HTTP Streamable mode..."
echo "Port: $MCP_HTTP_PORT"
echo "Host: $MCP_HTTP_HOST"
echo ""

# Start the server
node build/index.js

