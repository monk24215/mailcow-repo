/**
 * SSH client for the mail host.
 *
 * Mailcow runs its services in Docker containers, so most useful commands are
 * `docker exec` into postfix-mailcow / rspamd-mailcow. Container names are
 * resolved at runtime because the compose project prefix varies by install.
 */

import { readFileSync } from "node:fs";
import { Client, type ConnectConfig } from "ssh2";
import { SSH_TIMEOUT_MS, READONLY_COMMAND_PATTERNS } from "../constants.js";
import type { SshResult } from "../types.js";

function connectConfig(): ConnectConfig {
  const host = process.env.MAIL_SSH_HOST;
  if (!host) {
    throw new Error(
      "MAIL_SSH_HOST is not set. Set MAIL_SSH_HOST, MAIL_SSH_USER and either " +
        "MAIL_SSH_KEY_PATH or MAIL_SSH_PASSWORD to enable server-shell tools."
    );
  }
  const cfg: ConnectConfig = {
    host,
    port: parseInt(process.env.MAIL_SSH_PORT || "22", 10),
    username: process.env.MAIL_SSH_USER || "root",
    readyTimeout: 20000,
    keepaliveInterval: 5000,
  };
  // MAIL_SSH_KEY takes the private key's own PEM/OpenSSH content directly —
  // for environments like a hosted container where there's no local
  // filesystem path that makes sense to point at (a key checked out on one
  // machine and a path baked into another machine's env is exactly how this
  // broke: MAIL_SSH_KEY_PATH held a Windows path that doesn't exist inside a
  // Linux container). Checked before MAIL_SSH_KEY_PATH; both may set
  // MAIL_SSH_KEY_PASSPHRASE.
  const keyContent = process.env.MAIL_SSH_KEY;
  const keyPath = process.env.MAIL_SSH_KEY_PATH;
  if (keyContent) {
    cfg.privateKey = keyContent;
    if (process.env.MAIL_SSH_KEY_PASSPHRASE) {
      cfg.passphrase = process.env.MAIL_SSH_KEY_PASSPHRASE;
    }
  } else if (keyPath) {
    // Windows sets USERPROFILE, not HOME, so ~ must fall back to it or the
    // path never resolves and the failure looks like a missing key file.
    const home = process.env.HOME || process.env.USERPROFILE;
    const resolved = home ? keyPath.replace(/^~(?=[/\\]|$)/, home) : keyPath;
    try {
      cfg.privateKey = readFileSync(resolved);
    } catch (err) {
      throw new Error(
        `Cannot read SSH key at ${resolved}: ${err instanceof Error ? err.message : String(err)}. ` +
          `Use an absolute path in MAIL_SSH_KEY_PATH (in claude_desktop_config.json, escape backslashes: C:\\\\Users\\\\you\\\\.ssh\\\\id_ed25519) ` +
          `— or set MAIL_SSH_KEY to the key's own content instead of a path (e.g. for a hosted deployment with no relevant local filesystem).`
      );
    }
    if (process.env.MAIL_SSH_KEY_PASSPHRASE) {
      cfg.passphrase = process.env.MAIL_SSH_KEY_PASSPHRASE;
    }
  } else if (process.env.MAIL_SSH_PASSWORD) {
    cfg.password = process.env.MAIL_SSH_PASSWORD;
  } else {
    throw new Error("Set MAIL_SSH_KEY, MAIL_SSH_KEY_PATH, or MAIL_SSH_PASSWORD for SSH authentication.");
  }
  return cfg;
}

/** True when SSH credentials are configured. */
export function sshConfigured(): boolean {
  return Boolean(
    process.env.MAIL_SSH_HOST &&
      (process.env.MAIL_SSH_KEY || process.env.MAIL_SSH_KEY_PATH || process.env.MAIL_SSH_PASSWORD)
  );
}

/** True when a command matches the read-only allow-list. */
export function isReadOnlyCommand(command: string): boolean {
  const parts = command.split(/\s*(?:\||;|&&)\s*/);
  return parts.every((part) => READONLY_COMMAND_PATTERNS.some((re) => re.test(part)));
}

/** Execute a single command on the mail host and capture its output. */
export function runRemote(command: string, timeoutMs: number = SSH_TIMEOUT_MS): Promise<SshResult> {
  const cfg = connectConfig();
  const started = Date.now();

  return new Promise<SshResult>((resolve, reject) => {
    const conn = new Client();
    let settled = false;
    let stdout = "";
    let stderr = "";

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      conn.end();
      reject(new Error(`SSH command timed out after ${timeoutMs}ms: ${command.slice(0, 120)}`));
    }, timeoutMs);

    const finish = (result: SshResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      conn.end();
      resolve(result);
    };

    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      conn.end();
      reject(err);
    };

    conn.on("ready", () => {
      conn.exec(command, (err, stream) => {
        if (err) return fail(err);
        stream
          .on("close", (code: number | null) => {
            finish({
              command,
              exit_code: code ?? -1,
              stdout,
              stderr,
              duration_ms: Date.now() - started,
            });
          })
          .on("data", (chunk: Buffer) => {
            stdout += chunk.toString("utf8");
          });
        stream.stderr.on("data", (chunk: Buffer) => {
          stderr += chunk.toString("utf8");
        });
      });
    });

    conn.on("error", (err) => {
      fail(
        new Error(
          `SSH connection to ${cfg.username}@${cfg.host}:${cfg.port} failed: ${err.message}. ` +
            "Verify MAIL_SSH_HOST/USER and that this machine's key is authorized on the mail host."
        )
      );
    });

    conn.connect(cfg);
  });
}

const containerCache = new Map<string, string>();

/**
 * Resolve the running container name for a Mailcow service suffix
 * (e.g. "postfix-mailcow" -> "mailcowdockerized-postfix-mailcow-1").
 */
export async function resolveContainer(service: string): Promise<string> {
  const cached = containerCache.get(service);
  if (cached) return cached;
  const res = await runRemote(
    `docker ps --filter "name=${service}" --format '{{.Names}}' | head -n 1`,
    20000
  );
  const name = res.stdout.trim().split("\n")[0]?.trim();
  if (!name) {
    throw new Error(
      `No running container matching "${service}" on the mail host. ` +
        `Check \`docker ps\` output — is Mailcow up, and does the SSH user have Docker access?`
    );
  }
  containerCache.set(service, name);
  return name;
}

/** Run a command inside a Mailcow container. */
export async function runInContainer(
  service: string,
  command: string,
  timeoutMs: number = SSH_TIMEOUT_MS
): Promise<SshResult> {
  const container = await resolveContainer(service);
  return runRemote(`docker exec ${container} ${command}`, timeoutMs);
}

/** Fetch container logs since a relative time expression such as "24h" or "30m". */
export async function containerLogs(
  service: string,
  since: string,
  timeoutMs: number = SSH_TIMEOUT_MS
): Promise<string> {
  const container = await resolveContainer(service);
  const safeSince = since.replace(/[^0-9a-zA-Z:.\-+]/g, "");
  const res = await runRemote(
    `docker logs --since ${safeSince} ${container} 2>&1`,
    timeoutMs
  );
  return res.stdout || res.stderr;
}
