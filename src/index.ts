#!/usr/bin/env node
/**
 * mailcow-mcp-server
 *
 * MCP server for Mailcow administration and mail-server reputation management.
 * Transport: stdio (local). Configuration comes from environment variables:
 *
 *   MAILCOW_BASE_URL        https://mail.example.com
 *   MAILCOW_API_KEY         read-write API key from Mailcow
 *   MAIL_SSH_HOST           mail host for shell-based tools (optional)
 *   MAIL_SSH_USER           default: root
 *   MAIL_SSH_PORT           default: 22
 *   MAIL_SSH_KEY_PATH       path to a private key, or
 *   MAIL_SSH_PASSWORD       password auth
 *   MAIL_SSH_KEY_PASSPHRASE optional passphrase for the key
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { SERVER_NAME, SERVER_VERSION } from "./constants.js";
import { registerReadTools } from "./tools/mailcow-read.js";
import { registerWriteTools } from "./tools/mailcow-write.js";
import { registerShellTools } from "./tools/server-shell.js";
import { registerReputationTools } from "./tools/reputation.js";
import { sshConfigured } from "./services/ssh.js";

const server = new McpServer({
  name: SERVER_NAME,
  version: SERVER_VERSION,
});

registerReadTools(server);
registerWriteTools(server);
registerShellTools(server);
registerReputationTools(server);

async function main(): Promise<void> {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    process.stdout.write(
      `${SERVER_NAME} v${SERVER_VERSION}\n\n` +
        `An MCP server exposing Mailcow administration and mail reputation analysis over stdio.\n\n` +
        `Required env: MAILCOW_BASE_URL, MAILCOW_API_KEY\n` +
        `Optional env: MAIL_SSH_HOST, MAIL_SSH_USER, MAIL_SSH_PORT, MAIL_SSH_KEY_PATH,\n` +
        `              MAIL_SSH_PASSWORD, MAIL_SSH_KEY_PASSPHRASE\n\n` +
        `Register it in Claude Desktop's config under mcpServers. See README.md.\n`
    );
    return;
  }

  if (!process.env.MAILCOW_BASE_URL || !process.env.MAILCOW_API_KEY) {
    console.error(
      "ERROR: MAILCOW_BASE_URL and MAILCOW_API_KEY are required. " +
        "Create an API key in Mailcow under System > Configuration > Access > API, " +
        "and allow-list this machine's public IP on that key."
    );
    process.exit(1);
  }

  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(
    `${SERVER_NAME} v${SERVER_VERSION} ready on stdio · Mailcow ${process.env.MAILCOW_BASE_URL} · ` +
      `SSH ${sshConfigured() ? `enabled (${process.env.MAIL_SSH_HOST})` : "disabled"}`
  );
}

main().catch((error) => {
  console.error("Fatal:", error instanceof Error ? error.message : String(error));
  process.exit(1);
});
