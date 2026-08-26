/**
 * Boots the server over stdio and lists its tools. No network calls to Mailcow.
 * Run: node scripts/smoke-test.mjs
 */

import { spawn } from "node:child_process";

const child = spawn("node", ["dist/index.js"], {
  stdio: ["pipe", "pipe", "pipe"],
  env: {
    ...process.env,
    MAILCOW_BASE_URL: process.env.MAILCOW_BASE_URL || "https://mail.example.invalid",
    MAILCOW_API_KEY: process.env.MAILCOW_API_KEY || "smoke-test-key",
  },
});

let buffer = "";
const pending = new Map();

child.stdout.on("data", (chunk) => {
  buffer += chunk.toString();
  let idx;
  while ((idx = buffer.indexOf("\n")) >= 0) {
    const line = buffer.slice(0, idx).trim();
    buffer = buffer.slice(idx + 1);
    if (!line) continue;
    try {
      const msg = JSON.parse(line);
      const resolve = pending.get(msg.id);
      if (resolve) {
        pending.delete(msg.id);
        resolve(msg);
      }
    } catch {
      /* ignore non-JSON */
    }
  }
});

child.stderr.on("data", (c) => process.stderr.write(`[server] ${c}`));

let nextId = 1;
function send(method, params = {}) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, resolve);
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    setTimeout(() => reject(new Error(`timeout waiting for ${method}`)), 10000);
  });
}

try {
  const init = await send("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "smoke-test", version: "1.0.0" },
  });
  console.log("initialize ->", init.result?.serverInfo?.name, init.result?.serverInfo?.version);

  child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");

  const list = await send("tools/list");
  const tools = list.result?.tools ?? [];
  console.log(`\n${tools.length} tools registered:\n`);

  let bad = 0;
  for (const t of tools) {
    const ann = t.annotations ?? {};
    const flag = ann.readOnlyHint ? "read " : ann.destructiveHint ? "DESTR" : "write";
    console.log(`  [${flag}] ${t.name}`);
    if (!t.description || t.description.length < 60) {
      console.log(`         ^ description too short`);
      bad += 1;
    }
    if (!t.inputSchema) {
      console.log(`         ^ missing inputSchema`);
      bad += 1;
    }
  }

  // Confirm the destructive guard fires without a live Mailcow.
  const guarded = await send("tools/call", {
    name: "mailcow_manage_queue",
    arguments: { action: "delete_all" },
  });
  const text = guarded.result?.content?.[0]?.text ?? "";
  const guardOk = guarded.result?.isError === true && text.includes("confirm=true");
  console.log(`\n${guardOk ? "PASS" : "FAIL"}  destructive action refused without confirm=true`);
  if (!guardOk) bad += 1;

  const guarded2 = await send("tools/call", {
    name: "mailsrv_run",
    arguments: { command: "rm -rf /var/vmail" },
  });
  const text2 = guarded2.result?.content?.[0]?.text ?? "";
  const guard2Ok = guarded2.result?.isError === true && text2.includes("confirm=true");
  console.log(`${guard2Ok ? "PASS" : "FAIL"}  non-allow-listed shell command refused without confirm=true`);
  if (!guard2Ok) bad += 1;

  const allowed = await send("tools/call", {
    name: "mailsrv_run",
    arguments: { command: "docker ps" },
  });
  const text3 = allowed.result?.content?.[0]?.text ?? "";
  const allowOk = text3.includes("SSH is not configured");
  console.log(`${allowOk ? "PASS" : "FAIL"}  allow-listed command passes the guard and reports missing SSH config`);
  if (!allowOk) bad += 1;

  child.kill();
  process.exit(bad === 0 ? 0 : 1);
} catch (err) {
  console.error("smoke test failed:", err.message);
  child.kill();
  process.exit(1);
}
