#!/usr/bin/env node
/**
 * mailcow-mcp-server
 *
 * MCP server for Mailcow administration and mail-server reputation management.
 *
 * Transport is stdio by default (for local/Claude Desktop use). Set
 * MCP_TRANSPORT=http to instead serve the MCP Streamable HTTP transport over
 * an authenticated HTTP endpoint (used for the hosted Railway deployment, so
 * a cloud session can reach this server directly without a device bridge).
 * Local/stdio behavior is completely unchanged unless MCP_TRANSPORT=http is
 * explicitly set.
 *
 * Configuration comes from environment variables:
 *
 *   MAILCOW_BASE_URL        https://mail.example.com
 *   MAILCOW_API_KEY         read-write API key from Mailcow
 *   MAIL_SSH_HOST           mail host for shell-based tools (optional)
 *   MAIL_SSH_USER           default: root
 *   MAIL_SSH_PORT           default: 22
 *   MAIL_SSH_KEY_PATH       path to a private key, or
 *   MAIL_SSH_PASSWORD       password auth
 *   MAIL_SSH_KEY_PASSPHRASE optional passphrase for the key
 *
 *   MCP_TRANSPORT            "stdio" (default) or "http"
 *   MCP_HTTP_TOKEN           required shared secret when MCP_TRANSPORT=http.
 *                            A request is authorized if it either sends
 *                            "Authorization: Bearer <token>" to /mcp, or is
 *                            addressed to /mcp/<token>. The header form is
 *                            preferred; the path form exists so the endpoint
 *                            can be added through claude.ai's custom-connector
 *                            dialog, which accepts a URL and offers no place
 *                            to put a static token. A /mcp/<token> URL is
 *                            itself a secret — see checkAuth() below.
 *   PORT                     HTTP port to listen on (default 8080; Railway
 *                            sets this automatically)
 */

import { randomUUID, timingSafeEqual, webcrypto } from "node:crypto";
import express, { type Request, type Response } from "express";

// The MCP SDK's HTTP transport expects the WHATWG Web Crypto API on
// globalThis (globalThis.crypto), which is only a built-in global on
// Node 20+. Polyfill it from node:crypto's webcrypto on older runtimes
// (e.g. Node 18, which Railway's build may select) so initialize doesn't
// fail with "crypto is not defined". No-op wherever it's already global.
if (!(globalThis as { crypto?: unknown }).crypto) {
  (globalThis as { crypto?: unknown }).crypto = webcrypto;
}
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { SERVER_NAME, SERVER_VERSION } from "./constants.js";
import { registerReadTools } from "./tools/mailcow-read.js";
import { registerWriteTools } from "./tools/mailcow-write.js";
import { registerShellTools } from "./tools/server-shell.js";
import { registerReputationTools } from "./tools/reputation.js";
import { sshConfigured } from "./services/ssh.js";

/** Build a fresh McpServer instance with every tool family registered. */
function buildServer(): McpServer {
  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  registerReadTools(server);
  registerWriteTools(server);
  registerShellTools(server);
  registerReputationTools(server);

  return server;
}

function statusLine(transportLabel: string): string {
  return (
    `${SERVER_NAME} v${SERVER_VERSION} ready on ${transportLabel} · Mailcow ${process.env.MAILCOW_BASE_URL} · ` +
    `SSH ${sshConfigured() ? `enabled (${process.env.MAIL_SSH_HOST})` : "disabled"}`
  );
}

async function runStdio(): Promise<void> {
  const server = buildServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(statusLine("stdio"));
}

/**
 * Constant-time string comparison. timingSafeEqual throws on unequal
 * lengths, so guard on length first — that leaks only the length, which an
 * attacker can vary freely anyway.
 */
function safeEqual(provided: string, expected: string): boolean {
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Auth check for the HTTP transport. A request is authorized if EITHER:
 *
 *   - it sends "Authorization: Bearer <token>" matching MCP_HTTP_TOKEN, or
 *   - it was routed via /mcp/:token and that path segment matches.
 *
 * The header form is the original and the preferred one — use it for
 * scripted/curl clients. The path form exists because claude.ai's
 * "Add custom connector" dialog accepts only a URL: its one authentication
 * option is OAuth, which this single-user server deliberately doesn't
 * implement, so there is nowhere to put a static bearer token. Putting the
 * token in the path lets the URL carry its own credential.
 *
 * Consequence worth being explicit about: a /mcp/<token> URL IS the secret.
 * It should be treated exactly like the token — not pasted into shared docs,
 * issues, or chat logs. It will also appear in HTTP access logs at any proxy
 * that records full request paths (Railway's edge included), which a bearer
 * header would not. That is the trade for being connectable from the UI.
 */
function checkAuth(req: Request, res: Response): boolean {
  const token = process.env.MCP_HTTP_TOKEN ?? "";
  const header = String(req.headers["authorization"] ?? "");
  const pathToken =
    typeof req.params?.token === "string" ? req.params.token : "";

  const ok =
    safeEqual(header, `Bearer ${token}`) ||
    (pathToken.length > 0 && safeEqual(pathToken, token));

  if (!ok) {
    res.status(401).json({
      jsonrpc: "2.0",
      error: { code: -32001, message: "Unauthorized" },
      id: null,
    });
    return false;
  }
  return true;
}

async function runHttp(): Promise<void> {
  if (!process.env.MCP_HTTP_TOKEN) {
    console.error(
      "ERROR: MCP_HTTP_TOKEN is required when MCP_TRANSPORT=http. " +
        "Set it to a long random secret; clients must send it as " +
        "'Authorization: Bearer <token>'."
    );
    process.exit(1);
  }

  const app = express();
  app.use(express.json());

  // Per-session transports, keyed by the MCP session ID issued on
  // initialize. Each session gets its own McpServer instance so sessions
  // never share in-memory state with one another.
  const transports: Record<string, StreamableHTTPServerTransport> = {};

  const handleMcpPost = async (req: Request, res: Response) => {
    if (!checkAuth(req, res)) return;

    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    let transport: StreamableHTTPServerTransport;

    if (sessionId && transports[sessionId]) {
      transport = transports[sessionId];
    } else if (!sessionId && isInitializeRequest(req.body)) {
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (sid) => {
          transports[sid] = transport;
        },
      });
      transport.onclose = () => {
        if (transport.sessionId) delete transports[transport.sessionId];
      };

      const server = buildServer();
      await server.connect(transport);
    } else {
      res.status(400).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Bad Request: no valid session ID provided" },
        id: null,
      });
      return;
    }

    await transport.handleRequest(req, res, req.body);
  };

  const handleSessionRequest = async (req: Request, res: Response) => {
    if (!checkAuth(req, res)) return;
    const sessionId = req.headers["mcp-session-id"] as string | undefined;
    if (!sessionId || !transports[sessionId]) {
      res.status(400).send("Invalid or missing session ID");
      return;
    }
    await transports[sessionId].handleRequest(req, res);
  };

  // Two ways in, both behind the same checkAuth():
  //   /mcp        with "Authorization: Bearer <token>"  — original, preferred
  //   /mcp/<token>                                      — for the claude.ai
  //                                                       connector dialog,
  //                                                       which takes a URL
  //                                                       and nothing else
  app.post("/mcp", handleMcpPost);
  app.post("/mcp/:token", handleMcpPost);
  app.get("/mcp", handleSessionRequest);
  app.get("/mcp/:token", handleSessionRequest);
  app.delete("/mcp", handleSessionRequest);
  app.delete("/mcp/:token", handleSessionRequest);

  // Unauthenticated liveness probe only — no Mailcow data, no session state.
  app.get("/health", (_req: Request, res: Response) => {
    res.status(200).send("ok");
  });

  const port = Number(process.env.PORT) || 8080;
  app.listen(port, () => {
    console.error(statusLine(`http :${port}`));
  });
}

async function main(): Promise<void> {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    process.stdout.write(
      `${SERVER_NAME} v${SERVER_VERSION}\n\n` +
        `An MCP server exposing Mailcow administration and mail reputation analysis\n` +
        `over stdio (default) or the MCP Streamable HTTP transport (MCP_TRANSPORT=http).\n\n` +
        `Required env: MAILCOW_BASE_URL, MAILCOW_API_KEY\n` +
        `Optional env: MAIL_SSH_HOST, MAIL_SSH_USER, MAIL_SSH_PORT, MAIL_SSH_KEY_PATH,\n` +
        `              MAIL_SSH_PASSWORD, MAIL_SSH_KEY_PASSPHRASE\n` +
        `HTTP mode env: MCP_TRANSPORT=http, MCP_HTTP_TOKEN (required bearer token), PORT\n\n` +
        `Register it in Claude Desktop's config under mcpServers for stdio use.\n` +
        `See README.md.\n`
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

  if (process.env.MCP_TRANSPORT === "http") {
    await runHttp();
  } else {
    await runStdio();
  }
}

main().catch((error) => {
  console.error("Fatal:", error instanceof Error ? error.message : String(error));
  process.exit(1);
});
