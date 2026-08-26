/** Mutating Mailcow API tools. Destructive actions are gated behind confirm=true. */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { apiPost, apiGet, allSucceeded, formatActionResults } from "../services/mailcow.js";
import { ok, guard, j, requireConfirm, type ToolResponse } from "./helpers.js";

const WRITE_ANNOTATIONS = {
  readOnlyHint: false,
  destructiveHint: false,
  idempotentHint: false,
  openWorldHint: true,
} as const;

const DESTRUCTIVE_ANNOTATIONS = {
  readOnlyHint: false,
  destructiveHint: true,
  idempotentHint: false,
  openWorldHint: true,
} as const;

function report(results: Awaited<ReturnType<typeof apiPost>>, what: string): ToolResponse {
  const success = allSucceeded(results);
  const text = `${success ? "OK" : "FAILED"} — ${what}\n\n${formatActionResults(results)}`;
  return ok(text, { success, action: what, results } as Record<string, unknown>);
}

export function registerWriteTools(server: McpServer): void {
  server.registerTool(
    "mailcow_manage_domain",
    {
      title: "Create, Update, or Delete a Domain",
      description: `Manage mail domains.

Args:
  - action ('create'|'update'|'delete', required)
  - domain (string, required): Domain name. For update, may be a comma-separated list.
  - attributes (object, optional): Fields to set. Common keys:
      description (string), aliases (number), mailboxes (number), maxquota (MB),
      quota (MB), active (0|1), rl_value (number), rl_frame ('s'|'m'|'h'|'d'),
      relayhost (id), relay_all_recipients (0|1), backupmx (0|1), gal (0|1),
      dkim_selector (string), key_size (1024|2048|3072|4096)
  - confirm (boolean): Required true for delete. Default false.

Returns JSON: { "success": boolean, "results": array }

Note: deleting a domain destroys every mailbox and all stored mail under it.
Warmup-relevant: setting rl_value/rl_frame here is how you cap outbound volume per domain.`,
      inputSchema: {
        action: z.enum(["create", "update", "delete"]).describe("Operation to perform"),
        domain: z.string().min(1).describe("Domain name, or comma-separated list for update/delete"),
        attributes: z.record(z.unknown()).optional().describe("Domain attributes to set"),
        confirm: z.boolean().default(false).describe("Required true for delete"),
      },
      annotations: DESTRUCTIVE_ANNOTATIONS,
    },
    guard(async ({ action, domain, attributes, confirm }): Promise<ToolResponse> => {
      const items = domain.split(",").map((d) => d.trim()).filter(Boolean);
      if (action === "delete") {
        const blocked = requireConfirm(confirm, `delete domain(s) ${items.join(", ")} and all their mailboxes`);
        if (blocked) return blocked;
        return report(await apiPost("delete", "domain", items), `delete domain ${items.join(", ")}`);
      }
      if (action === "create") {
        const body = { domain: items[0], ...(attributes ?? {}) };
        return report(await apiPost("add", "domain", body), `create domain ${items[0]}`);
      }
      return report(
        await apiPost("edit", "domain", { items, attr: attributes ?? {} }),
        `update domain ${items.join(", ")}`
      );
    })
  );

  server.registerTool(
    "mailcow_manage_mailbox",
    {
      title: "Create, Update, or Delete a Mailbox",
      description: `Manage mailboxes.

Args:
  - action ('create'|'update'|'delete', required)
  - mailbox (string, required): Full address, or comma-separated list for update/delete.
  - password (string, optional): Required for create; optional on update to change it.
  - attributes (object, optional): Common keys:
      name (string), quota (MB), active (0|1), force_pw_update (0|1),
      tls_enforce_in (0|1), tls_enforce_out (0|1), sogo_access (0|1),
      imap_access (0|1), pop3_access (0|1), smtp_access (0|1),
      sieve_access (0|1), quarantine_notification ('never'|'hourly'|'daily'|'weekly')
  - confirm (boolean): Required true for delete. Default false.

For create, the address is split into local_part and domain automatically.

Returns JSON: { "success": boolean, "results": array }`,
      inputSchema: {
        action: z.enum(["create", "update", "delete"]).describe("Operation to perform"),
        mailbox: z.string().min(3).describe("Full mailbox address, e.g. bounces@example.com"),
        password: z.string().min(1).optional().describe("Password (required on create)"),
        attributes: z.record(z.unknown()).optional().describe("Mailbox attributes"),
        confirm: z.boolean().default(false).describe("Required true for delete"),
      },
      annotations: DESTRUCTIVE_ANNOTATIONS,
    },
    guard(async ({ action, mailbox, password, attributes, confirm }): Promise<ToolResponse> => {
      const items = mailbox.split(",").map((m) => m.trim()).filter(Boolean);

      if (action === "delete") {
        const blocked = requireConfirm(confirm, `delete mailbox(es) ${items.join(", ")} and all stored mail`);
        if (blocked) return blocked;
        return report(await apiPost("delete", "mailbox", items), `delete mailbox ${items.join(", ")}`);
      }

      if (action === "create") {
        const addr = items[0];
        if (!addr.includes("@")) return ok("Error: mailbox must be a full address like user@example.com");
        if (!password) return ok("Error: password is required when creating a mailbox.");
        const [local_part, domain] = [addr.slice(0, addr.lastIndexOf("@")), addr.split("@").pop()!];
        const body = {
          local_part,
          domain,
          password,
          password2: password,
          quota: 3072,
          active: 1,
          ...(attributes ?? {}),
        };
        return report(await apiPost("add", "mailbox", body), `create mailbox ${addr}`);
      }

      const attr: Record<string, unknown> = { ...(attributes ?? {}) };
      if (password) {
        attr.password = password;
        attr.password2 = password;
      }
      return report(await apiPost("edit", "mailbox", { items, attr }), `update mailbox ${items.join(", ")}`);
    })
  );

  server.registerTool(
    "mailcow_manage_alias",
    {
      title: "Create, Update, or Delete an Alias",
      description: `Manage address aliases.

Args:
  - action ('create'|'update'|'delete', required)
  - address (string): Alias address for create/update, e.g. abuse@example.com or @example.com for catch-all.
  - goto (string): Destination address(es), comma-separated. Required for create.
  - alias_ids (string, optional): Comma-separated numeric alias IDs, required for update/delete (from mailcow_list_aliases).
  - attributes (object, optional): active (0|1), sogo_visible (0|1), public_comment (string).
  - confirm (boolean): Required true for delete. Default false.

Returns JSON: { "success": boolean, "results": array }`,
      inputSchema: {
        action: z.enum(["create", "update", "delete"]).describe("Operation to perform"),
        address: z.string().optional().describe("Alias address (create/update)"),
        goto: z.string().optional().describe("Destination address(es), comma-separated"),
        alias_ids: z.string().optional().describe("Comma-separated alias IDs for update/delete"),
        attributes: z.record(z.unknown()).optional().describe("Alias attributes"),
        confirm: z.boolean().default(false).describe("Required true for delete"),
      },
      annotations: DESTRUCTIVE_ANNOTATIONS,
    },
    guard(async ({ action, address, goto, alias_ids, attributes, confirm }): Promise<ToolResponse> => {
      if (action === "create") {
        if (!address || !goto) return ok("Error: both 'address' and 'goto' are required to create an alias.");
        return report(
          await apiPost("add", "alias", { address, goto, active: 1, ...(attributes ?? {}) }),
          `create alias ${address} -> ${goto}`
        );
      }
      if (!alias_ids) return ok("Error: 'alias_ids' is required. Get IDs from mailcow_list_aliases.");
      const items = alias_ids.split(",").map((i) => i.trim()).filter(Boolean);

      if (action === "delete") {
        const blocked = requireConfirm(confirm, `delete alias id(s) ${items.join(", ")}`);
        if (blocked) return blocked;
        return report(await apiPost("delete", "alias", items), `delete alias ${items.join(", ")}`);
      }
      const attr: Record<string, unknown> = { ...(attributes ?? {}) };
      if (address) attr.address = address;
      if (goto) attr.goto = goto;
      return report(await apiPost("edit", "alias", { items, attr }), `update alias ${items.join(", ")}`);
    })
  );

  server.registerTool(
    "mailcow_manage_dkim",
    {
      title: "Generate, Duplicate, or Delete a DKIM Key",
      description: `Manage DKIM signing keys.

WARNING: deleting or regenerating a key breaks signing for every message in flight
until the new public key propagates in DNS. Provider reputation is scored partly on
authentication consistency, so an unplanned rotation mid-campaign causes a visible
delivery dip. Publish the new TXT record BEFORE switching selectors where possible.

Args:
  - action ('generate'|'duplicate'|'delete', required)
  - domain (string, required): Target domain. For duplicate, this is the source.
  - target_domain (string): Destination domain for 'duplicate'.
  - selector (string): Selector for 'generate'. Default 'dkim'.
  - key_size (1024|2048|3072|4096): Key length for 'generate'. Default 2048.
  - confirm (boolean): Required true for generate (overwrites) and delete. Default false.

Returns JSON: { "success": boolean, "results": array, "dkim_txt": string|null }
On generate, dkim_txt is the DNS record to publish at {selector}._domainkey.{domain}.`,
      inputSchema: {
        action: z.enum(["generate", "duplicate", "delete"]).describe("Operation to perform"),
        domain: z.string().min(1).describe("Domain name"),
        target_domain: z.string().optional().describe("Destination domain for duplicate"),
        selector: z.string().default("dkim").describe("DKIM selector"),
        key_size: z.union([z.literal(1024), z.literal(2048), z.literal(3072), z.literal(4096)])
          .default(2048)
          .describe("Key length in bits"),
        confirm: z.boolean().default(false).describe("Required true for generate and delete"),
      },
      annotations: DESTRUCTIVE_ANNOTATIONS,
    },
    guard(async ({ action, domain, target_domain, selector, key_size, confirm }): Promise<ToolResponse> => {
      if (action === "delete") {
        const blocked = requireConfirm(confirm, `delete the DKIM key for ${domain} (signing stops immediately)`);
        if (blocked) return blocked;
        return report(await apiPost("delete", "dkim", [domain]), `delete DKIM key for ${domain}`);
      }
      if (action === "duplicate") {
        if (!target_domain) return ok("Error: 'target_domain' is required for duplicate.");
        return report(
          await apiPost("add", "dkim_duplicate", { from_domain: domain, to_domain: target_domain }),
          `duplicate DKIM key ${domain} -> ${target_domain}`
        );
      }
      const blocked = requireConfirm(
        confirm,
        `generate a new DKIM key for ${domain} (selector "${selector}") — this replaces any existing key for that selector`
      );
      if (blocked) return blocked;
      const results = await apiPost("add", "dkim", {
        domains: domain,
        dkim_selector: selector,
        key_size,
      });
      let dkim_txt: string | null = null;
      try {
        const rec = await apiGet<Record<string, unknown>>(`dkim/${encodeURIComponent(domain)}`);
        dkim_txt = typeof rec?.dkim_txt === "string" ? rec.dkim_txt : null;
      } catch {
        dkim_txt = null;
      }
      const base = report(results, `generate DKIM key for ${domain}`);
      const extra = dkim_txt
        ? `\n\nPublish this TXT record at ${selector}._domainkey.${domain}:\n\n${dkim_txt}`
        : "\n\nCould not read back the public key — call mailcow_get_dkim to fetch it.";
      return ok(
        (base.content[0]?.text ?? "") + extra,
        { ...(base.structuredContent ?? {}), dkim_txt } as Record<string, unknown>
      );
    })
  );

  server.registerTool(
    "mailcow_manage_queue",
    {
      title: "Flush or Delete the Mail Queue",
      description: `Act on the Postfix queue.

Args:
  - action ('flush'|'delete_all', required):
      flush      -> postqueue -f, retries every deferred message immediately.
      delete_all -> postsuper -d ALL, permanently discards every queued message.
  - confirm (boolean): Required true for delete_all. Default false.

Reputation note: flushing a queue full of messages a provider is already deferring
re-sends them all at once and can escalate a soft throttle into a hard block. Flush
only after the underlying cause is fixed, or when the deferral was transient.

Returns JSON: { "success": boolean, "results": array }`,
      inputSchema: {
        action: z.enum(["flush", "delete_all"]).describe("Queue operation"),
        confirm: z.boolean().default(false).describe("Required true for delete_all"),
      },
      annotations: DESTRUCTIVE_ANNOTATIONS,
    },
    guard(async ({ action, confirm }): Promise<ToolResponse> => {
      if (action === "delete_all") {
        const blocked = requireConfirm(confirm, "permanently delete every message in the mail queue");
        if (blocked) return blocked;
        return report(await apiPost("delete", "mailq", { action: "super_delete" }), "delete entire mail queue");
      }
      return report(await apiPost("edit", "mailq", { action: "flush" }), "flush mail queue");
    })
  );

  server.registerTool(
    "mailcow_manage_quarantine",
    {
      title: "Release, Learn, or Delete Quarantined Mail",
      description: `Act on quarantined messages.

Args:
  - action ('release'|'learn_ham'|'delete', required)
  - ids (string, required): Comma-separated quarantine item IDs from mailcow_get_quarantine.
  - confirm (boolean): Required true for delete. Default false.

Returns JSON: { "success": boolean, "results": array }`,
      inputSchema: {
        action: z.enum(["release", "learn_ham", "delete"]).describe("Quarantine operation"),
        ids: z.string().min(1).describe("Comma-separated quarantine item IDs"),
        confirm: z.boolean().default(false).describe("Required true for delete"),
      },
      annotations: DESTRUCTIVE_ANNOTATIONS,
    },
    guard(async ({ action, ids, confirm }): Promise<ToolResponse> => {
      const items = ids.split(",").map((i) => i.trim()).filter(Boolean);
      if (action === "delete") {
        const blocked = requireConfirm(confirm, `permanently delete quarantine item(s) ${items.join(", ")}`);
        if (blocked) return blocked;
        return report(await apiPost("delete", "qitem", items), `delete quarantine items ${items.join(", ")}`);
      }
      const body = { items, attr: { action: action === "release" ? "release" : "learnham" } };
      return report(await apiPost("edit", "qitem", body), `${action} quarantine items ${items.join(", ")}`);
    })
  );

  server.registerTool(
    "mailcow_set_ratelimit",
    {
      title: "Set a Send Rate Limit",
      description: `Set the outbound rate limit for a domain or mailbox.

This is the primary throttle for warmup. rl_value is the number of messages allowed
per rl_frame window ('s' second, 'm' minute, 'h' hour, 'd' day).

Args:
  - scope ('domain'|'mailbox', required)
  - target (string, required): Domain name or mailbox address. Comma-separated for several.
  - rl_value (number, required): Messages allowed per frame. Use 0 to remove the limit.
  - rl_frame ('s'|'m'|'h'|'d'): Time window. Default 'h'.

Returns JSON: { "success": boolean, "results": array }

Example: 500 sends/day during week one -> rl_value=500, rl_frame='d'.`,
      inputSchema: {
        scope: z.enum(["domain", "mailbox"]).describe("What to limit"),
        target: z.string().min(1).describe("Domain name or mailbox address"),
        rl_value: z.number().int().min(0).max(1000000).describe("Messages per frame; 0 removes the limit"),
        rl_frame: z.enum(["s", "m", "h", "d"]).default("h").describe("Time window"),
      },
      annotations: WRITE_ANNOTATIONS,
    },
    guard(async ({ scope, target, rl_value, rl_frame }): Promise<ToolResponse> => {
      const items = target.split(",").map((t) => t.trim()).filter(Boolean);
      const resource = scope === "domain" ? "rl-domain" : "rl-mbox";
      const results = await apiPost("edit", resource, { items, attr: { rl_value, rl_frame } });
      return report(results, `set ${scope} rate limit ${rl_value}/${rl_frame} on ${items.join(", ")}`);
    })
  );

  server.registerTool(
    "mailcow_manage_policy",
    {
      title: "Add or Remove an Allow/Block Entry",
      description: `Add or remove a sender allowlist or blocklist entry for a domain.

Args:
  - action ('add'|'remove', required)
  - domain (string, required): Domain the policy belongs to.
  - sender (string): Exact address or wildcard pattern, e.g. "*@spammer.tld". Required for add.
  - list ('wl'|'bl'): Allowlist or blocklist. Required for add.
  - policy_ids (string): Comma-separated policy IDs for remove (from mailcow_get_policy).
  - confirm (boolean): Required true for remove. Default false.

Returns JSON: { "success": boolean, "results": array }`,
      inputSchema: {
        action: z.enum(["add", "remove"]).describe("Operation to perform"),
        domain: z.string().min(1).describe("Domain the policy applies to"),
        sender: z.string().optional().describe("Address or wildcard pattern"),
        list: z.enum(["wl", "bl"]).optional().describe("Allowlist or blocklist"),
        policy_ids: z.string().optional().describe("Comma-separated policy IDs for remove"),
        confirm: z.boolean().default(false).describe("Required true for remove"),
      },
      annotations: DESTRUCTIVE_ANNOTATIONS,
    },
    guard(async ({ action, domain, sender, list, policy_ids, confirm }): Promise<ToolResponse> => {
      if (action === "add") {
        if (!sender || !list) return ok("Error: 'sender' and 'list' are required to add a policy.");
        return report(
          await apiPost("add", "domain-policy", { domain, object_from: sender, object_list: list }),
          `add ${list === "wl" ? "allowlist" : "blocklist"} entry ${sender} on ${domain}`
        );
      }
      if (!policy_ids) return ok("Error: 'policy_ids' is required to remove a policy. Get IDs from mailcow_get_policy.");
      const items = policy_ids.split(",").map((i) => i.trim()).filter(Boolean);
      const blocked = requireConfirm(confirm, `remove policy entr(ies) ${items.join(", ")} from ${domain}`);
      if (blocked) return blocked;
      return report(await apiPost("delete", "domain-policy", items), `remove policy ${items.join(", ")}`);
    })
  );

  server.registerTool(
    "mailcow_edit_fail2ban",
    {
      title: "Edit Netfilter/Fail2ban Settings",
      description: `Change ban thresholds or unban an address.

Args:
  - attributes (object, required): Any of:
      ban_time (seconds), max_attempts (number), retry_window (seconds),
      netban_ipv4 (CIDR bits), netban_ipv6 (CIDR bits),
      whitelist (newline-separated IPs/CIDRs), blacklist (newline-separated IPs/CIDRs),
      unban (IP address to lift a ban on), ban (IP address to ban permanently)

Returns JSON: { "success": boolean, "results": array }

Setting 'whitelist' or 'blacklist' REPLACES the existing list — read the current
value with mailcow_get_fail2ban first and send the full merged list.`,
      inputSchema: {
        attributes: z.record(z.unknown()).describe("Fail2ban attributes to set"),
      },
      annotations: WRITE_ANNOTATIONS,
    },
    guard(async ({ attributes }): Promise<ToolResponse> => {
      const results = await apiPost("edit", "fail2ban", { items: ["none"], attr: attributes });
      return report(results, `edit fail2ban settings (${Object.keys(attributes).join(", ")})`);
    })
  );
}
