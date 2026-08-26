/**
 * Verifies live connectivity before you register the server with Claude.
 * Reads credentials from the environment (or a .env file in this directory).
 *
 * Run: node scripts/selftest.mjs
 */

import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const envPath = join(here, "..", ".env");

if (existsSync(envPath)) {
  for (const line of readFileSync(envPath, "utf8").split("\n")) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
    if (m && !process.env[m[1]]) {
      process.env[m[1]] = m[2].replace(/^["']|["']$/g, "");
    }
  }
  console.log(`Loaded ${envPath}`);
}

let failures = 0;
const pass = (m) => console.log(`  PASS  ${m}`);
const fail = (m) => {
  console.log(`  FAIL  ${m}`);
  failures += 1;
};

console.log("\n=== Mailcow API ===");
const base = (process.env.MAILCOW_BASE_URL || "").replace(/\/+$/, "");
const key = process.env.MAILCOW_API_KEY;

if (!base) fail("MAILCOW_BASE_URL is not set");
if (!key) fail("MAILCOW_API_KEY is not set");

if (base && key) {
  try {
    const res = await fetch(`${base}/api/v1/get/status/version`, {
      headers: { "X-API-Key": key, Accept: "application/json" },
      signal: AbortSignal.timeout(20000),
    });
    if (res.status === 401 || res.status === 403) {
      fail(
        `HTTP ${res.status} — key rejected. In Mailcow: System > Configuration > Access > API. ` +
          `Check the key value AND that this machine's public IP is in the key's allowed-IP list.`
      );
    } else if (!res.ok) {
      fail(`HTTP ${res.status} from ${base}/api/v1/get/status/version`);
    } else {
      const body = await res.json();
      pass(`Connected to Mailcow ${body?.version ?? "(version unknown)"}`);

      // Confirm the key is read-write, not read-only, without changing anything:
      // a write route with an empty body returns 401 for ro keys and a validation
      // response for rw keys.
      const probe = await fetch(`${base}/api/v1/edit/mailq`, {
        method: "POST",
        headers: { "X-API-Key": key, "Content-Type": "application/json" },
        body: JSON.stringify({ action: "" }),
        signal: AbortSignal.timeout(20000),
      });
      if (probe.status === 401 || probe.status === 403) {
        fail("Key appears to be READ-ONLY. Management tools will fail. Create a read-write key.");
      } else {
        pass("Key accepts write routes (read-write)");
      }

      const q = await fetch(`${base}/api/v1/get/mailq/all`, {
        headers: { "X-API-Key": key },
        signal: AbortSignal.timeout(20000),
      });
      if (q.ok) {
        const queue = await q.json();
        pass(`Queue readable — ${Array.isArray(queue) ? queue.length : 0} message(s) queued`);
      } else {
        fail(`Queue read returned HTTP ${q.status}`);
      }

      const logs = await fetch(`${base}/api/v1/get/logs/postfix/50`, {
        headers: { "X-API-Key": key },
        signal: AbortSignal.timeout(20000),
      });
      if (logs.ok) {
        const entries = await logs.json();
        const n = Array.isArray(entries) ? entries.length : 0;
        if (n > 0) pass(`Postfix log readable — ${n} recent entries`);
        else fail("Postfix log returned no entries (reputation analysis will be empty)");
      } else {
        fail(`Postfix log read returned HTTP ${logs.status}`);
      }
    }
  } catch (err) {
    fail(`Cannot reach ${base}: ${err.message}`);
  }
}

console.log("\n=== SSH ===");
if (!process.env.MAIL_SSH_HOST) {
  console.log("  SKIP  MAIL_SSH_HOST not set — server-shell tools will be unavailable");
} else {
  try {
    const { runRemote, resolveContainer } = await import("../dist/services/ssh.js");
    const res = await runRemote("echo ok", 20000);
    if (res.stdout.trim() === "ok") pass(`SSH to ${process.env.MAIL_SSH_HOST} works`);
    else fail(`SSH connected but returned unexpected output: ${res.stdout}`);

    const docker = await runRemote("docker ps --format '{{.Names}}' | wc -l", 20000);
    const count = parseInt(docker.stdout.trim(), 10);
    if (Number.isFinite(count) && count > 0) pass(`Docker accessible — ${count} container(s) running`);
    else fail("Docker not accessible to this SSH user (add them to the docker group, or use root)");

    for (const svc of ["postfix-mailcow", "rspamd-mailcow"]) {
      try {
        const name = await resolveContainer(svc);
        pass(`Resolved ${svc} -> ${name}`);
      } catch (err) {
        fail(`${svc}: ${err.message}`);
      }
    }
  } catch (err) {
    fail(`SSH failed: ${err.message}`);
  }
}

console.log(
  `\n${failures === 0 ? "All checks passed. Register the server with Claude." : `${failures} check(s) failed — fix these before registering.`}\n`
);
process.exit(failures === 0 ? 0 : 1);
