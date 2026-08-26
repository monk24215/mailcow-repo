/** Composite reputation tools built on top of the API and SSH layers. */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { apiGet } from "../services/mailcow.js";
import { containerLogs, sshConfigured, runInContainer } from "../services/ssh.js";
import {
  parseDeliveryEvents,
  aggregateDeliveries,
  logEntriesToText,
  bucketsToMarkdown,
} from "../services/analysis.js";
import { ok, guard, j, type ToolResponse } from "./helpers.js";
import type { MailqEntry, DeliveryBucket } from "../types.js";

const READ_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
} as const;

/** Fetch postfix log text from whichever source is requested and available. */
async function getPostfixLogText(
  source: "api" | "ssh" | "auto",
  since: string,
  count: number
): Promise<{ text: string; used: "api" | "ssh" }> {
  const wantSsh = source === "ssh" || (source === "auto" && sshConfigured());
  if (wantSsh) {
    try {
      const text = await containerLogs("postfix-mailcow", since, 120000);
      return { text, used: "ssh" };
    } catch (err) {
      if (source === "ssh") throw err;
    }
  }
  const entries = await apiGet<unknown>(`logs/postfix/${count}`);
  return { text: logEntriesToText(entries), used: "api" };
}

/** Severity ordering for surfacing the worst finding first. */
const SEVERITY_RANK: Record<string, number> = { critical: 3, warning: 2, info: 1 };

export function registerReputationTools(server: McpServer): void {
  server.registerTool(
    "reputation_delivery_breakdown",
    {
      title: "Delivery Breakdown by Provider",
      description: `Parse Postfix delivery attempts and report delivery outcomes PER RECIPIENT, grouped by mailbox provider, with the remote MTA's own words for each failure, classified.

This is the core reputation instrument. Sending reputation is scored per receiving
provider, so an aggregate bounce rate hides the thing that matters: Gmail deferring
while everyone else accepts means a Google-specific reputation problem, and the
remedy is different from a blocklist hit.

CRITICAL — read the recipient columns, not the attempt columns. Postfix retries a
deferred address for days, so one permanently refused subscriber can generate 150+
attempts. Judging by attempts turns a dozen dead addresses into what looks like a
provider-wide block. 'unique_recipients' and 'delivery_rate' are the real numbers;
'attempts' and 'attempts_per_recipient' exist to expose retry storms.

Failure categories assigned: blocklisted, reputation_block, throttled, auth_failure,
greylisted, user_unknown, mailbox_full, domain_error, connection_error, tls_error, other.

Args:
  - source ('auto'|'api'|'ssh'): Where to read logs. 'api' uses Mailcow's Redis log (recent, capped);
    'ssh' reads container logs (deeper history, needs SSH). Default 'auto'.
  - since (string): Time window for the ssh source, e.g. "24h", "7d". Default "24h".
  - count (number): Log lines to pull for the api source, 100-10000. Default 5000.
  - group_by ('provider'|'domain'): Grouping key. Default 'provider'.
  - min_volume (number): Omit groups with fewer than this many UNIQUE RECIPIENTS. Default 1.

Returns JSON:
{
  "source_used": "api"|"ssh",
  "window": string,
  "events_parsed": number,          // MTA attempts, not people
  "unique_recipients": number,      // people
  "attempts_per_recipient": number, // >=5 means retries are inflating attempt counts
  "totals": { "sent": number, "deferred": number, "bounced": number, "expired": number,
              "deferral_rate": number, "bounce_rate": number,
              "recipients_delivered": number, "recipient_delivery_rate": number },
  "groups": [{ "key": string,
               "unique_recipients": number, "recipients_delivered": number,
               "recipients_deferred": number, "recipients_bounced": number,
               "delivery_rate": number, "attempts_per_recipient": number,
               "total": number, "sent": number, "deferred": number, "bounced": number,
               "top_reasons": [{ "category": string, "severity": string, "count": number, "sample": string }] }],
  "alerts": string[]
}

Reading the result: judge a provider only at 20+ unique recipients. Below that the
percentages are noise. Recipients failed >=2% or undelivered >=5% at a major provider
is the threshold worth acting on. Category 'throttled' concentrated on one provider
means slow down. 'reputation_block' or 'blocklisted' across a meaningful share of a
provider's recipients means stop and fix the cause — but the same category affecting
two or three addresses is a suppression task, not a campaign-level problem.`,
      inputSchema: {
        source: z.enum(["auto", "api", "ssh"]).default("auto").describe("Log source"),
        since: z.string().default("24h").describe("Time window for the ssh source"),
        count: z.number().int().min(100).max(10000).default(5000).describe("Log lines for the api source"),
        group_by: z.enum(["provider", "domain"]).default("provider").describe("Grouping key"),
        min_volume: z.number().int().min(1).default(1).describe("Minimum attempts per group"),
      },
      annotations: READ_ANNOTATIONS,
    },
    guard(async ({ source, since, count, group_by, min_volume }): Promise<ToolResponse> => {
      const { text, used } = await getPostfixLogText(source, since, count);
      const events = parseDeliveryEvents(text);

      if (events.length === 0) {
        return ok(
          `No delivery events parsed from the ${used} log source` +
            (used === "ssh" ? ` over the last ${since}` : ` in the last ${count} lines`) +
            `. Either nothing has been sent in that window, or the log source is empty. ` +
            `Try a longer window, or source="ssh" for deeper history.`,
          { source_used: used, events_parsed: 0, groups: [], alerts: [] }
        );
      }

      const all = aggregateDeliveries(events, group_by);
      const groups = all.filter((g) => g.unique_recipients >= min_volume);

      const totals = events.reduce(
        (acc, e) => {
          if (e.status === "sent") acc.sent += 1;
          else if (e.status === "deferred") acc.deferred += 1;
          else if (e.status === "bounced") acc.bounced += 1;
          else if (e.status === "expired") acc.expired += 1;
          return acc;
        },
        { sent: 0, deferred: 0, bounced: 0, expired: 0 }
      );
      const total = events.length;

      // Alerts are scored on people, not packets. A provider refusing 2 addresses
      // is not a provider-wide block, however many times Postfix retried them.
      const alerts: string[] = [];
      const RECIPIENT_ALERT_FLOOR = 20;
      for (const g of groups) {
        const failRate = g.unique_recipients
          ? Number(((g.recipients_bounced / g.unique_recipients) * 100).toFixed(2))
          : 0;
        const stuckRate = g.unique_recipients
          ? Number(((g.recipients_deferred / g.unique_recipients) * 100).toFixed(2))
          : 0;

        if (g.unique_recipients >= RECIPIENT_ALERT_FLOOR) {
          if (failRate >= 2) {
            alerts.push(`${g.key}: ${g.recipients_bounced}/${g.unique_recipients} recipients failed (${failRate}%).`);
          }
          if (stuckRate >= 5) {
            alerts.push(`${g.key}: ${g.recipients_deferred}/${g.unique_recipients} recipients undelivered (${stuckRate}%).`);
          }
        }

        // A critical rejection is reported at any volume, but always carries the
        // recipient count so a 2-address block is not mistaken for an outage.
        for (const r of g.top_reasons) {
          if (r.severity === "critical") {
            alerts.push(
              `${g.key} (${g.unique_recipients} recipient${g.unique_recipients === 1 ? "" : "s"}): ${r.category} — "${r.sample}"`
            );
          }
        }

        if (g.attempts_per_recipient >= 10) {
          alerts.push(
            `${g.key}: retry storm — ${g.total} attempts for ${g.unique_recipients} recipient(s) ` +
              `(${g.attempts_per_recipient}× each). Suppress these addresses; the retries waste connections and look bad to the receiver.`
          );
        }
      }

      const uniqueOverall = new Set(events.map((e) => e.recipient)).size;
      const deliveredOverall = groups.reduce((s, g) => s + g.recipients_delivered, 0);
      const recipientsInGroups = groups.reduce((s, g) => s + g.unique_recipients, 0);

      const output = {
        source_used: used,
        window: used === "ssh" ? since : `last ${count} log lines`,
        events_parsed: total,
        unique_recipients: uniqueOverall,
        attempts_per_recipient: uniqueOverall ? Number((total / uniqueOverall).toFixed(1)) : 0,
        totals: {
          ...totals,
          deferral_rate: Number(((totals.deferred / total) * 100).toFixed(2)),
          bounce_rate: Number((((totals.bounced + totals.expired) / total) * 100).toFixed(2)),
          recipients_delivered: deliveredOverall,
          recipient_delivery_rate: recipientsInGroups
            ? Number(((deliveredOverall / recipientsInGroups) * 100).toFixed(2))
            : 0,
        },
        groups,
        alerts,
      };

      const md = [
        `## Delivery breakdown — ${output.window} (${used})`,
        "",
        `**${uniqueOverall} unique recipients** · ${deliveredOverall} delivered ` +
          `(${output.totals.recipient_delivery_rate}% of those shown)`,
        "",
        `${total} MTA attempts across them — ${output.attempts_per_recipient}× per recipient` +
          (output.attempts_per_recipient >= 5
            ? `. High: retries are inflating the attempt counts below.`
            : "."),
        "",
        alerts.length ? `### Alerts\n${alerts.map((a) => `- ${a}`).join("\n")}\n` : "No threshold alerts.\n",
        bucketsToMarkdown(groups, group_by === "provider" ? "Provider" : "Domain"),
      ].join("\n");

      return ok(md, output as unknown as Record<string, unknown>, "Raise 'min_volume' or group_by='provider'.");
    })
  );

  server.registerTool(
    "reputation_snapshot",
    {
      title: "Reputation Snapshot",
      description: `One-call health read across every signal this server can see: container state, queue depth and composition, delivery outcomes by provider, self-imposed rate limiting, Rspamd throughput, and active netfilter bans.

Run this first when asked "how is our sending doing" or before starting a send.

Args:
  - since (string): Window for the log analysis. Default "24h".
  - include_ssh (boolean): Include SSH-sourced sections (deeper logs, Rspamd stats). Default true when SSH is configured.

Returns JSON:
{
  "generated_at": string,
  "containers": { "unhealthy": string[] },
  "queue": { "depth": number, "by_queue": object, "top_domains": array, "oldest_minutes": number|null },
  "delivery": { "totals": object, "worst_providers": array, "alerts": string[] },
  "self_throttled": number,          // messages Mailcow itself rate-limited in the window
  "rspamd": object|null,
  "bans": { "active": number },
  "verdict": "healthy"|"watch"|"degraded"|"critical",
  "findings": [{ "severity": string, "message": string }]
}

Verdict thresholds: critical if any provider shows a reputation_block/blocklisted
category or a container is down; degraded if bounce rate >=2% or queue depth is
climbing with deferrals; watch if deferral rate >=5% anywhere; otherwise healthy.`,
      inputSchema: {
        since: z.string().default("24h").describe("Analysis window"),
        include_ssh: z.boolean().default(true).describe("Include SSH-sourced sections"),
      },
      annotations: READ_ANNOTATIONS,
    },
    guard(async ({ since, include_ssh }): Promise<ToolResponse> => {
      const useSsh = include_ssh && sshConfigured();
      const findings: Array<{ severity: string; message: string }> = [];

      const [containersRes, queueRes, ratelimitedRes, fail2banRes] = await Promise.allSettled([
        apiGet<Record<string, Record<string, unknown>>>("status/containers"),
        apiGet<unknown>("mailq/all"),
        apiGet<unknown>("logs/ratelimited/500"),
        apiGet<Record<string, unknown>>("fail2ban"),
      ]);

      // Containers
      const unhealthy: string[] = [];
      if (containersRes.status === "fulfilled" && containersRes.value) {
        for (const [name, info] of Object.entries(containersRes.value)) {
          if (String((info as Record<string, unknown>)?.state ?? "") !== "running") unhealthy.push(name);
        }
      }
      if (unhealthy.length) {
        findings.push({ severity: "critical", message: `Containers not running: ${unhealthy.join(", ")}` });
      }

      // Queue
      const queue: MailqEntry[] =
        queueRes.status === "fulfilled" && Array.isArray(queueRes.value) ? (queueRes.value as MailqEntry[]) : [];
      const byQueue: Record<string, number> = {};
      const domainCounts = new Map<string, number>();
      let oldest = 0;
      for (const e of queue) {
        byQueue[e.queue_name ?? "unknown"] = (byQueue[e.queue_name ?? "unknown"] ?? 0) + 1;
        if (e.arrival_time && e.arrival_time > 0) {
          const age = Date.now() / 1000 - e.arrival_time;
          if (age > oldest) oldest = age;
        }
        for (const r of e.recipients ?? []) {
          const addr = (r.address ?? "").toLowerCase();
          const dom = addr.includes("@") ? addr.split("@").pop()! : "unknown";
          domainCounts.set(dom, (domainCounts.get(dom) ?? 0) + 1);
        }
      }
      const deferredInQueue = byQueue["deferred"] ?? 0;
      if (deferredInQueue > 100) {
        findings.push({ severity: "warning", message: `${deferredInQueue} messages sitting in the deferred queue.` });
      }

      // Delivery analysis
      let deliveryTotals: Record<string, number> = {};
      let worst: DeliveryBucket[] = [];
      let alerts: string[] = [];
      try {
        const { text } = await getPostfixLogText(useSsh ? "ssh" : "api", since, 5000);
        const events = parseDeliveryEvents(text);
        if (events.length) {
          const groups = aggregateDeliveries(events, "provider");
          const sent = events.filter((e) => e.status === "sent").length;
          const deferred = events.filter((e) => e.status === "deferred").length;
          const bounced = events.filter((e) => e.status === "bounced" || e.status === "expired").length;
          deliveryTotals = {
            attempts: events.length,
            sent,
            deferred,
            bounced,
            deferral_rate: Number(((deferred / events.length) * 100).toFixed(2)),
            bounce_rate: Number(((bounced / events.length) * 100).toFixed(2)),
          };
          // Judged on recipients, so a handful of refused addresses cannot
          // present as a provider-wide failure.
          worst = groups
            .filter((g) => g.unique_recipients >= 20)
            .sort((a, b) => a.delivery_rate - b.delivery_rate)
            .slice(0, 5);
          for (const g of worst) {
            const failRate = Number(((g.recipients_bounced / g.unique_recipients) * 100).toFixed(2));
            const stuckRate = Number(((g.recipients_deferred / g.unique_recipients) * 100).toFixed(2));
            if (failRate >= 2) {
              findings.push({
                severity: "warning",
                message: `${g.key}: ${g.recipients_bounced}/${g.unique_recipients} recipients failed (${failRate}%).`,
              });
              alerts.push(`${g.key} failed ${failRate}%`);
            }
            if (stuckRate >= 5) {
              findings.push({
                severity: "warning",
                message: `${g.key}: ${g.recipients_deferred}/${g.unique_recipients} recipients undelivered (${stuckRate}%).`,
              });
              alerts.push(`${g.key} undelivered ${stuckRate}%`);
            }
            for (const r of g.top_reasons) {
              if (r.severity === "critical") {
                findings.push({
                  severity: "critical",
                  message: `${g.key} (${g.unique_recipients} recipients): ${r.category} — "${r.sample}"`,
                });
                alerts.push(`${g.key} ${r.category}`);
              }
            }
          }

          // Retry storms are reported separately at any volume — they are a
          // suppression task, not a reputation verdict.
          for (const g of groups) {
            if (g.attempts_per_recipient >= 10 && g.total >= 50) {
              findings.push({
                severity: "info",
                message:
                  `${g.key}: ${g.total} attempts for ${g.unique_recipients} recipient(s) ` +
                  `(${g.attempts_per_recipient}× each) — suppress these addresses.`,
              });
            }
          }
        }
      } catch (err) {
        findings.push({
          severity: "info",
          message: `Delivery log analysis unavailable: ${err instanceof Error ? err.message : String(err)}`,
        });
      }

      // Self-throttling
      const selfThrottled =
        ratelimitedRes.status === "fulfilled" && Array.isArray(ratelimitedRes.value)
          ? ratelimitedRes.value.length
          : 0;
      if (selfThrottled > 0) {
        findings.push({
          severity: "info",
          message: `${selfThrottled} recent messages hit Mailcow's own rate limit — raise the limit or slow the sender.`,
        });
      }

      // Rspamd
      let rspamd: Record<string, string> | null = null;
      if (useSsh) {
        try {
          const res = await runInContainer("rspamd-mailcow", "rspamc stat", 30000);
          rspamd = {};
          for (const line of (res.stdout || "").split("\n")) {
            const m = /^([A-Za-z][A-Za-z0-9 _()/-]*?):\s+(.+)$/.exec(line.trim());
            if (m) rspamd[m[1].trim()] = m[2].trim();
          }
        } catch {
          rspamd = null;
        }
      }

      // Bans
      let activeBans = 0;
      if (fail2banRes.status === "fulfilled") {
        const b = fail2banRes.value?.active_bans;
        activeBans = Array.isArray(b) ? b.length : 0;
      }

      const hasCritical = findings.some((f) => f.severity === "critical");
      const hasWarning = findings.some((f) => f.severity === "warning");
      const verdict = hasCritical
        ? "critical"
        : hasWarning && (deliveryTotals.bounce_rate ?? 0) >= 2
          ? "degraded"
          : hasWarning
            ? "watch"
            : "healthy";

      const output = {
        generated_at: new Date().toISOString(),
        window: since,
        containers: { unhealthy },
        queue: {
          depth: queue.length,
          by_queue: byQueue,
          top_domains: [...domainCounts.entries()]
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([domain, count]) => ({ domain, count })),
          oldest_minutes: oldest ? Math.round(oldest / 60) : null,
        },
        delivery: { totals: deliveryTotals, worst_providers: worst, alerts },
        self_throttled: selfThrottled,
        rspamd,
        bans: { active: activeBans },
        verdict,
        findings,
      };

      const md = [
        `## Reputation snapshot — ${verdict.toUpperCase()}`,
        `_${output.generated_at} · window ${since} · ${useSsh ? "API + SSH" : "API only"}_`,
        "",
        findings.length
          ? `### Findings\n` +
            findings
              .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0))
              .map((f) => `- **${f.severity}** — ${f.message}`)
              .join("\n")
          : "No findings. All monitored signals within normal range.",
        "",
        `### Queue`,
        `Depth ${queue.length}${oldest ? `, oldest ${Math.round(oldest / 60)} min` : ""} · ${Object.entries(byQueue).map(([k, v]) => `${k}=${v}`).join(", ") || "empty"}`,
        "",
        `### Delivery (${since})`,
        deliveryTotals.attempts
          ? `${deliveryTotals.attempts} attempts · ${deliveryTotals.sent} sent · defer ${deliveryTotals.deferral_rate}% · bounce ${deliveryTotals.bounce_rate}%`
          : "No delivery events in the window.",
        worst.length ? "\n" + bucketsToMarkdown(worst, "Provider") : "",
        "",
        `### Other`,
        `Self-throttled: ${selfThrottled} · Active bans: ${activeBans}${rspamd ? ` · Rspamd scanned: ${rspamd["Messages scanned"] ?? "n/a"}` : ""}`,
      ].join("\n");

      return ok(md, output as unknown as Record<string, unknown>, "Shorten 'since' or set include_ssh=false.");
    })
  );

  server.registerTool(
    "reputation_warmup_status",
    {
      title: "Warmup Status",
      description: `Compare actual send volume against the configured rate limits and the provider-by-provider acceptance rate, to answer "can we increase volume yet".

Warmup discipline is per-provider: a domain can be fully warmed at Google while
Microsoft is still throttling. This reports readiness separately for each.

Args:
  - domain (string, optional): Restrict volume figures to this sending domain.
  - since (string): Window to measure. Default "24h".

Returns JSON:
{
  "window": string,
  "configured_limits": { "domains": array, "mailboxes": array },
  "volume": { "attempts": number, "sent": number },
  "by_provider": [{ "provider": string, "recipients": number, "delivered": number,
                    "delivery_rate": number, "undelivered_rate": number, "failed_rate": number,
                    "attempts": number, "attempts_per_recipient": number,
                    "recommendation": "increase"|"hold"|"reduce"|"stop"|"insufficient_data" }],
  "overall_recommendation": string
}

Recommendation logic per provider, all measured on unique recipients:
'insufficient_data' below 20 recipients — no verdict is issued on thin volume;
'stop' on a critical failure category affecting a provider with 20+ recipients;
'reduce' at failed >=2% or undelivered >=10%; 'hold' at undelivered >=5%;
'increase' when clean across at least 50 recipients.`,
      inputSchema: {
        domain: z.string().optional().describe("Sending domain to scope volume to"),
        since: z.string().default("24h").describe("Measurement window"),
      },
      annotations: READ_ANNOTATIONS,
    },
    guard(async ({ domain, since }): Promise<ToolResponse> => {
      const [rlDomains, rlMailboxes] = await Promise.all([
        apiGet<unknown>("rl-domain/all").catch(() => []),
        apiGet<unknown>("rl-mbox/all").catch(() => []),
      ]);

      const { text, used } = await getPostfixLogText("auto", since, 8000);
      let events = parseDeliveryEvents(text);
      if (domain) {
        const needle = domain.toLowerCase();
        // Postfix logs the envelope sender on the message line, not the delivery line,
        // so scope by matching the domain anywhere in the surrounding log text instead.
        const relevantQids = new Set(
          text
            .split("\n")
            .filter((l) => l.toLowerCase().includes(`from=<`) && l.toLowerCase().includes(needle))
            .map((l) => /(?:^|\s)([A-F0-9]{8,20}|[0-9a-zA-Z]{10,16}):\s+from=/.exec(l)?.[1])
            .filter((q): q is string => Boolean(q))
        );
        if (relevantQids.size > 0) {
          events = events.filter((e) => relevantQids.has(e.queue_id));
        }
      }

      const groups = aggregateDeliveries(events, "provider");

      // Volume floor for a verdict. Below this a provider's numbers are noise —
      // one refused address out of three is 33% "failure" and means nothing.
      const VERDICT_FLOOR = 20;

      const byProvider = groups.map((g) => {
        const failRate = g.unique_recipients
          ? Number(((g.recipients_bounced / g.unique_recipients) * 100).toFixed(2))
          : 0;
        const stuckRate = g.unique_recipients
          ? Number(((g.recipients_deferred / g.unique_recipients) * 100).toFixed(2))
          : 0;
        // A critical rejection only halts sending if it affects a real slice of
        // the audience. Nine subscribers at one ISP is a suppression task, not
        // a reason to stop the campaign.
        const critical =
          g.top_reasons.some((r) => r.severity === "critical") && g.unique_recipients >= VERDICT_FLOOR;

        let recommendation: "increase" | "hold" | "reduce" | "stop" | "insufficient_data";
        if (g.unique_recipients < VERDICT_FLOOR) recommendation = "insufficient_data";
        else if (critical) recommendation = "stop";
        else if (failRate >= 2 || stuckRate >= 10) recommendation = "reduce";
        else if (stuckRate >= 5) recommendation = "hold";
        else if (g.unique_recipients >= 50) recommendation = "increase";
        else recommendation = "hold";

        return {
          provider: g.key,
          recipients: g.unique_recipients,
          delivered: g.recipients_delivered,
          delivery_rate: g.delivery_rate,
          failed_rate: failRate,
          undelivered_rate: stuckRate,
          attempts: g.total,
          attempts_per_recipient: g.attempts_per_recipient,
          top_reasons: g.top_reasons,
          recommendation,
        };
      });

      // Only providers that cleared the volume floor get a vote.
      const scored = byProvider.filter((p) => p.recommendation !== "insufficient_data");
      const anyStop = scored.some((p) => p.recommendation === "stop");
      const anyReduce = scored.some((p) => p.recommendation === "reduce");
      const allIncrease = scored.length > 0 && scored.every((p) => p.recommendation === "increase");
      const overall = scored.length === 0
        ? `INSUFFICIENT DATA — no provider reached ${VERDICT_FLOOR} recipients in this window. Send more before drawing conclusions.`
        : anyStop
          ? "STOP — a provider is issuing reputation-level rejections across a meaningful share of its audience. Fix the cause before sending more."
          : anyReduce
            ? "REDUCE — cut volume to the affected providers and hold the rest at current levels."
            : allIncrease
              ? "INCREASE — every provider with enough volume to judge is accepting cleanly. A 30-50% step up is reasonable."
              : "HOLD — keep volume flat for another cycle and re-measure.";

      const output = {
        window: `${since} (${used})`,
        scoped_domain: domain ?? null,
        configured_limits: { domains: rlDomains, mailboxes: rlMailboxes },
        volume: {
          attempts: events.length,
          sent: events.filter((e) => e.status === "sent").length,
        },
        by_provider: byProvider,
        overall_recommendation: overall,
      };

      const md = [
        `## Warmup status — ${since}${domain ? ` · ${domain}` : ""}`,
        "",
        `**${overall}**`,
        "",
        `Volume: ${output.volume.attempts} attempts, ${output.volume.sent} accepted.`,
        "",
        "| Provider | Recipients | Delivered | Delivery % | Undelivered % | Failed % | Action |",
        "|---|---:|---:|---:|---:|---:|---|",
        ...byProvider.map(
          (p) =>
            `| ${p.provider} | ${p.recipients} | ${p.delivered} | ${p.delivery_rate}% | ` +
            `${p.undelivered_rate}% | ${p.failed_rate}% | ${p.recommendation} |`
        ),
        "",
        "### Configured rate limits",
        j({ domains: rlDomains, mailboxes: rlMailboxes }),
      ].join("\n");

      return ok(md, output as unknown as Record<string, unknown>, "Shorten the window.");
    })
  );

  server.registerTool(
    "reputation_auth_audit",
    {
      title: "Authentication Audit",
      description: `Cross-check what Mailcow is signing with against what DNS actually publishes, and report authentication failures seen in the delivery log.

Catches the specific failure mode where a DKIM key exists in Mailcow but the DNS TXT
record is stale, missing, or truncated — mail still leaves, signs, and then fails
verification at the receiver, which reads as forgery and tanks reputation fast.

Requires SSH for the DNS half; without it, reports the Mailcow-side key only.

Args:
  - domain (string, required): Domain to audit.
  - since (string): Window for scanning the log for auth failures. Default "24h".

Returns JSON:
{
  "domain": string,
  "mailcow_dkim": { "selector": string, "dkim_txt": string, "length": string }|null,
  "dns": { "spf": string, "dkim": string, "dmarc": string, "ptr": string }|null,
  "dkim_matches_dns": boolean|null,
  "auth_failures_in_log": [{ "count": number, "sample": string }],
  "issues": string[]
}`,
      inputSchema: {
        domain: z.string().min(3).describe("Domain to audit"),
        since: z.string().default("24h").describe("Log window for auth failures"),
      },
      annotations: READ_ANNOTATIONS,
    },
    guard(async ({ domain, since }): Promise<ToolResponse> => {
      const issues: string[] = [];

      const dkimRecord = await apiGet<Record<string, unknown>>(
        `dkim/${encodeURIComponent(domain)}`
      ).catch(() => ({}) as Record<string, unknown>);
      const hasKey = dkimRecord && Object.keys(dkimRecord).length > 0;
      if (!hasKey) issues.push(`No DKIM key configured in Mailcow for ${domain}.`);

      const selector = String(dkimRecord?.dkim_selector ?? "dkim");
      let dns: Record<string, string> | null = null;
      let matches: boolean | null = null;

      if (sshConfigured()) {
        const d = domain.replace(/[^A-Za-z0-9.\-]/g, "");
        const sel = selector.replace(/[^A-Za-z0-9._\-]/g, "");
        const { runRemote } = await import("../services/ssh.js");
        const res = await runRemote(
          `echo '### SPF'; dig +short TXT ${d} | grep -i spf; ` +
            `echo '### DKIM'; dig +short TXT ${sel}._domainkey.${d}; ` +
            `echo '### DMARC'; dig +short TXT _dmarc.${d}`,
          45000
        );
        const raw = res.stdout || "";
        const section = (name: string): string => {
          const m = new RegExp(`### ${name}\\n([\\s\\S]*?)(?=\\n### |$)`).exec(raw);
          return m ? m[1].trim() : "";
        };
        dns = { spf: section("SPF"), dkim: section("DKIM"), dmarc: section("DMARC"), ptr: "" };

        if (!dns.spf) issues.push(`No SPF TXT record published for ${domain}.`);
        if (!dns.dmarc) issues.push(`No DMARC record at _dmarc.${domain}.`);
        if (!dns.dkim) {
          issues.push(`No DKIM TXT record at ${sel}._domainkey.${domain} — signed mail will fail verification.`);
          matches = false;
        } else if (hasKey) {
          const strip = (s: string): string => s.replace(/["\s]/g, "").toLowerCase();
          const mailcowKey = strip(String(dkimRecord?.dkim_txt ?? ""));
          const dnsKey = strip(dns.dkim);
          const pubMatch = /p=([a-z0-9+/=]+)/i;
          const a = pubMatch.exec(mailcowKey)?.[1];
          const b = pubMatch.exec(dnsKey)?.[1];
          matches = Boolean(a && b && a === b);
          if (!matches) {
            issues.push(
              `DKIM public key in DNS does not match the key Mailcow signs with. ` +
                `Republish the value from mailcow_get_dkim at ${sel}._domainkey.${domain}.`
            );
          }
        }
      } else {
        issues.push("SSH not configured — DNS side of the audit was skipped.");
      }

      const authFailures: Array<{ count: number; sample: string }> = [];
      try {
        const { text } = await getPostfixLogText("auto", since, 5000);
        const events = parseDeliveryEvents(text).filter(
          (e) => e.status !== "sent" && /\b(spf|dkim|dmarc|unauthenticated|5\.7\.2[0-9])\b/i.test(e.reason)
        );
        const counts = new Map<string, number>();
        for (const e of events) {
          const key = e.reason.replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, "<ip>").slice(0, 200);
          counts.set(key, (counts.get(key) ?? 0) + 1);
        }
        for (const [sample, count] of [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10)) {
          authFailures.push({ count, sample });
        }
        if (authFailures.length) {
          issues.push(`${authFailures.reduce((s, f) => s + f.count, 0)} authentication-related rejections in the last ${since}.`);
        }
      } catch {
        /* log unavailable; issues already capture the important parts */
      }

      const output = {
        domain,
        mailcow_dkim: hasKey
          ? { selector, dkim_txt: String(dkimRecord?.dkim_txt ?? ""), length: String(dkimRecord?.length ?? "") }
          : null,
        dns,
        dkim_matches_dns: matches,
        auth_failures_in_log: authFailures,
        issues,
      };

      const md = [
        `## Authentication audit — ${domain}`,
        "",
        issues.length ? `### Issues\n${issues.map((i) => `- ${i}`).join("\n")}` : "No issues found.",
        "",
        `DKIM selector: \`${selector}\`${matches === null ? "" : matches ? " · DNS matches Mailcow ✓" : " · **DNS does NOT match Mailcow**"}`,
        "",
        j(output),
      ].join("\n");

      return ok(md, output as unknown as Record<string, unknown>);
    })
  );
}
