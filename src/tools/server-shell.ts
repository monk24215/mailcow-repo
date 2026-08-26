/** SSH tools against the mail host: Postfix, Rspamd, Docker, and host state. */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { runRemote, runInContainer, containerLogs, isReadOnlyCommand, sshConfigured } from "../services/ssh.js";
import { ok, guard, j, type ToolResponse } from "./helpers.js";

const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

function requireSsh(): ToolResponse | null {
  if (sshConfigured()) return null;
  return {
    content: [
      {
        type: "text",
        text:
          "Error: SSH is not configured. Set MAIL_SSH_HOST, MAIL_SSH_USER, and either " +
          "MAIL_SSH_KEY_PATH or MAIL_SSH_PASSWORD, then restart the server. " +
          "The Mailcow API tools work without SSH.",
      },
    ],
    isError: true,
  };
}

export function registerShellTools(server: McpServer): void {
  server.registerTool(
    "mailsrv_postfix_queue",
    {
      title: "Postfix Queue (via SSH)",
      description: `Run postqueue -p inside the postfix-mailcow container and summarize it.

More detailed than the API's queue view: shows per-message sizes, arrival times, and
the verbatim deferral text from the remote MTA, including entries the API view truncates.

Args:
  - verbose (boolean): Include the raw postqueue output. Default false.

Returns JSON: { "queue_depth": number, "kilobytes": number, "raw": string|null }

Use mailcow_get_queue for the structured per-recipient breakdown; use this when you
need the exact bytes-and-timestamps view or the API is unavailable.`,
      inputSchema: {
        verbose: z.boolean().default(false).describe("Include raw postqueue output"),
      },
      annotations: READ_ANNOTATIONS,
    },
    guard(async ({ verbose }): Promise<ToolResponse> => {
      const blocked = requireSsh();
      if (blocked) return blocked;
      const res = await runInContainer("postfix-mailcow", "postqueue -p");
      const out = res.stdout || res.stderr;
      const tail = out.trim().split("\n").pop() ?? "";
      const m = /--\s*([\d.]+)\s*Kbytes in (\d+) Request/i.exec(tail);
      const output = {
        queue_depth: m ? parseInt(m[2], 10) : out.includes("Mail queue is empty") ? 0 : null,
        kilobytes: m ? parseFloat(m[1]) : 0,
        raw: verbose ? out : null,
      };
      const text = `## Postfix queue\n\n${tail || "Mail queue is empty"}\n\n${verbose ? "```\n" + out + "\n```" : ""}`;
      return ok(text, output as Record<string, unknown>, "Set verbose=false to omit the raw dump.");
    })
  );

  server.registerTool(
    "mailsrv_rspamd_stats",
    {
      title: "Rspamd Statistics (via SSH)",
      description: `Run rspamc stat inside the rspamd-mailcow container.

Reports messages scanned, spam/ham/greylisted counts, learned Bayes tokens, and
per-action totals since the last restart. The spam-to-ham ratio on OUTBOUND scanning
is a direct measure of whether your own content is tripping filters before it leaves.

Args: none.

Returns JSON: { "raw": string, "parsed": { "<stat>": string } }`,
      inputSchema: {},
      annotations: READ_ANNOTATIONS,
    },
    guard(async (): Promise<ToolResponse> => {
      const blocked = requireSsh();
      if (blocked) return blocked;
      const res = await runInContainer("rspamd-mailcow", "rspamc stat");
      const raw = res.stdout || res.stderr;
      const parsed: Record<string, string> = {};
      for (const line of raw.split("\n")) {
        const m = /^([A-Za-z][A-Za-z0-9 _()/-]*?):\s+(.+)$/.exec(line.trim());
        if (m) parsed[m[1].trim()] = m[2].trim();
      }
      return ok(`## Rspamd stats\n\n\`\`\`\n${raw}\n\`\`\``, { raw, parsed });
    })
  );

  server.registerTool(
    "mailsrv_mail_log",
    {
      title: "Mail Log Search (via SSH)",
      description: `Search the postfix-mailcow container log over a time window.

This reaches further back than the Mailcow API's Redis-backed log view, which is
capped at a few thousand lines. Use it for "what happened yesterday" questions.

Args:
  - since (string): Docker relative time, e.g. "24h", "90m", "2025-01-15T00:00:00". Default "6h".
  - pattern (string, optional): Case-insensitive regex to filter lines (applied with grep -Ei on the host).
  - max_lines (number): Cap on returned lines, 1-2000. Default 300.

Returns JSON: { "since": string, "pattern": string|null, "matched": number, "lines": string[] }

Examples:
  - "Show Gmail deferrals since yesterday" -> since="24h", pattern="gmail.*(deferred|4\\\\.7)"
  - "Any hard bounces from Microsoft?" -> pattern="(outlook|hotmail).*status=bounced"`,
      inputSchema: {
        since: z.string().default("6h").describe("Docker --since expression"),
        pattern: z.string().optional().describe("Case-insensitive regex filter"),
        max_lines: z.number().int().min(1).max(2000).default(300).describe("Max lines to return"),
      },
      annotations: READ_ANNOTATIONS,
    },
    guard(async ({ since, pattern, max_lines }): Promise<ToolResponse> => {
      const blocked = requireSsh();
      if (blocked) return blocked;
      const raw = await containerLogs("postfix-mailcow", since, 120000);
      let lines = raw.split("\n").filter(Boolean);
      let matched = lines.length;
      if (pattern) {
        let re: RegExp;
        try {
          re = new RegExp(pattern, "i");
        } catch (err) {
          return ok(`Error: invalid regex "${pattern}": ${err instanceof Error ? err.message : String(err)}`);
        }
        lines = lines.filter((l) => re.test(l));
        matched = lines.length;
      }
      const shown = lines.slice(-max_lines);
      const output = { since, pattern: pattern ?? null, matched, lines: shown };
      return ok(
        `## postfix log — last ${since}${pattern ? `, matching /${pattern}/i` : ""}\n\n` +
          `${matched} matching line(s), showing last ${shown.length}\n\n\`\`\`\n${shown.join("\n")}\n\`\`\``,
        output,
        "Narrow 'since', add a 'pattern', or lower 'max_lines'."
      );
    })
  );

  server.registerTool(
    "mailsrv_host_health",
    {
      title: "Mail Host Health (via SSH)",
      description: `Host-level health for the mail server: load, memory, disk, and container states.

A mail host that is out of disk or swapping will defer mail without any remote MTA
being involved — check here before concluding a provider is throttling you.

Args: none.

Returns JSON: { "uptime": string, "load": string, "memory": string, "disk": string, "containers": string }`,
      inputSchema: {},
      annotations: READ_ANNOTATIONS,
    },
    guard(async (): Promise<ToolResponse> => {
      const blocked = requireSsh();
      if (blocked) return blocked;
      const res = await runRemote(
        "echo '### UPTIME'; uptime; echo '### MEM'; free -h; echo '### DISK'; df -h; " +
          "echo '### CONTAINERS'; docker ps --format '{{.Names}}\\t{{.Status}}'"
      );
      const raw = res.stdout || res.stderr;
      const section = (name: string): string => {
        const m = new RegExp(`### ${name}\\n([\\s\\S]*?)(?=\\n### |$)`).exec(raw);
        return m ? m[1].trim() : "";
      };
      const output = {
        uptime: section("UPTIME"),
        load: section("UPTIME"),
        memory: section("MEM"),
        disk: section("DISK"),
        containers: section("CONTAINERS"),
      };
      return ok(`## Mail host health\n\n\`\`\`\n${raw}\n\`\`\``, output);
    })
  );

  server.registerTool(
    "mailsrv_run",
    {
      title: "Run a Command on the Mail Host",
      description: `Execute an arbitrary command over SSH on the mail host.

Read-only commands (docker ps/logs/inspect, postqueue -p, rspamc stat, cat/grep/tail,
df/free/uptime, dig/host, systemctl status, fail2ban-client status) run directly.
Anything else — writes, restarts, package installs, postsuper, config edits — requires
confirm=true, so state the exact command to the user and get agreement first.

Args:
  - command (string, required): Shell command to run. Runs as MAIL_SSH_USER.
  - confirm (boolean): Required true for any command outside the read-only allow-list. Default false.
  - timeout_ms (number): Command timeout, 1000-300000. Default 60000.

Returns JSON: { "command": string, "exit_code": number, "stdout": string, "stderr": string, "duration_ms": number }

A non-zero exit_code is returned as data, not as an error — read stderr for the cause.`,
      inputSchema: {
        command: z.string().min(1).max(4000).describe("Command to execute on the mail host"),
        confirm: z.boolean().default(false).describe("Required true for non-read-only commands"),
        timeout_ms: z.number().int().min(1000).max(300000).default(60000).describe("Timeout in milliseconds"),
      },
      annotations: {
        readOnlyHint: false,
        destructiveHint: true,
        idempotentHint: false,
        openWorldHint: true,
      },
    },
    guard(async ({ command, confirm, timeout_ms }): Promise<ToolResponse> => {
      // The confirmation guard runs before the connectivity check, so a dangerous
      // command is refused on its own merits rather than incidentally.
      if (!isReadOnlyCommand(command) && !confirm) {
        return {
          content: [
            {
              type: "text",
              text:
                `Refused: "${command}" is not on the read-only allow-list and was called without confirm=true.\n\n` +
                `Show this exact command to the user, explain what it changes, and call again with confirm=true once they agree.`,
            },
          ],
          isError: true,
        };
      }
      const blocked = requireSsh();
      if (blocked) return blocked;
      const res = await runRemote(command, timeout_ms);
      const text =
        `## ${command}\n\nexit=${res.exit_code} (${res.duration_ms}ms)\n\n` +
        (res.stdout ? `**stdout**\n\`\`\`\n${res.stdout}\n\`\`\`\n` : "") +
        (res.stderr ? `**stderr**\n\`\`\`\n${res.stderr}\n\`\`\`` : "");
      return ok(text, res as unknown as Record<string, unknown>, "Pipe the command through head/tail to reduce output.");
    })
  );

  server.registerTool(
    "mailsrv_dns_check",
    {
      title: "DNS Check from the Mail Host",
      description: `Resolve the DNS records that govern sending authentication, from the mail host itself.

Checks SPF (TXT at the domain), DKIM (TXT at {selector}._domainkey), DMARC (TXT at
_dmarc), MX, A, and the PTR record of the sending IP. Running these from the mail host
rather than locally catches split-horizon and stale-resolver problems.

Cross-check the DKIM result against mailcow_get_dkim — the two must match exactly.

Args:
  - domain (string, required): Domain to check.
  - dkim_selector (string): Selector to query. Default 'dkim'.
  - sending_ip (string, optional): IP to reverse-resolve. Defaults to the host's outbound IP.

Returns JSON: { "domain": string, "spf": string, "dkim": string, "dmarc": string,
"mx": string, "a": string, "sending_ip": string, "ptr": string, "raw": string }`,
      inputSchema: {
        domain: z.string().min(3).describe("Domain to check"),
        dkim_selector: z.string().default("dkim").describe("DKIM selector"),
        sending_ip: z.string().optional().describe("IP to reverse-resolve"),
      },
      annotations: READ_ANNOTATIONS,
    },
    guard(async ({ domain, dkim_selector, sending_ip }): Promise<ToolResponse> => {
      const blocked = requireSsh();
      if (blocked) return blocked;
      const d = domain.replace(/[^A-Za-z0-9.\-]/g, "");
      const sel = dkim_selector.replace(/[^A-Za-z0-9._\-]/g, "");
      const ipCmd = sending_ip
        ? `echo ${sending_ip.replace(/[^0-9a-fA-F:.]/g, "")}`
        : `curl -s --max-time 5 https://ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}'`;
      const cmd = [
        `echo '### SPF'; dig +short TXT ${d} | grep -i spf`,
        `echo '### DKIM'; dig +short TXT ${sel}._domainkey.${d}`,
        `echo '### DMARC'; dig +short TXT _dmarc.${d}`,
        `echo '### MX'; dig +short MX ${d}`,
        `echo '### A'; dig +short A ${d}`,
        `echo '### IP'; ${ipCmd}`,
      ].join("; ");
      const res = await runRemote(cmd, 45000);
      const raw = res.stdout || res.stderr;
      const section = (name: string): string => {
        const m = new RegExp(`### ${name}\\n([\\s\\S]*?)(?=\\n### |$)`).exec(raw);
        return m ? m[1].trim() : "";
      };
      const ip = section("IP").split("\n")[0]?.trim() ?? "";
      let ptr = "";
      if (ip && /^[0-9.]+$/.test(ip)) {
        const ptrRes = await runRemote(`dig +short -x ${ip}`, 20000);
        ptr = (ptrRes.stdout || "").trim();
      }
      const output = {
        domain: d,
        spf: section("SPF"),
        dkim: section("DKIM"),
        dmarc: section("DMARC"),
        mx: section("MX"),
        a: section("A"),
        sending_ip: ip,
        ptr,
        raw,
      };
      const flags: string[] = [];
      if (!output.spf) flags.push("No SPF record found.");
      if (!output.dkim) flags.push(`No DKIM TXT at ${sel}._domainkey.${d}.`);
      if (!output.dmarc) flags.push("No DMARC record found.");
      if (!ptr) flags.push("No PTR record for the sending IP — most large providers require one.");
      const header = flags.length ? `**Issues:**\n${flags.map((f) => `- ${f}`).join("\n")}\n\n` : "All core records present.\n\n";
      return ok(`## DNS check — ${d}\n\n${header}${j(output)}`, output);
    })
  );
}
