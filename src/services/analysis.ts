/**
 * Postfix log parsing and delivery/reputation aggregation.
 *
 * Postfix delivery lines look like:
 *   postfix/smtp[123]: A1B2C3: to=<x@gmail.com>, relay=gmail-smtp-in.l.google.com[142.250.1.1]:25,
 *   delay=1.2, delays=0.1/0/0.5/0.6, dsn=2.0.0, status=sent (250 2.0.0 OK ...)
 */

import { PROVIDER_MAP, REASON_PATTERNS, CHARACTER_LIMIT } from "../constants.js";
import type { DeliveryEvent, DeliveryBucket } from "../types.js";

const DELIVERY_RE =
  /(?:^|\s)(?<qid>[A-F0-9]{8,20}|[0-9a-zA-Z]{10,16}):\s+to=<(?<to>[^>]*)>.*?(?:relay=(?<relay>[^,]*),)?.*?dsn=(?<dsn>\d\.\d\.\d+),\s*status=(?<status>\w+)\s*(?<reason>\(.*\))?/;

/** Map a recipient domain to its mailbox provider bucket. */
export function providerFor(domain: string): string {
  const d = domain.toLowerCase();
  return PROVIDER_MAP[d] ?? d;
}

/** Categories that take priority when the response is temporary (4.x.x). */
const TEMP_PRIORITY = ["greylisted", "throttled", "connection_error"];

/**
 * Pull the remote MTA's own SMTP reply code out of a rejection string.
 *
 * This matters more than it looks. Postfix records a connect-time or
 * RCPT-stage refusal as a *deferral* with a 4.x.x DSN even when the remote
 * server plainly said 554 — "refused to talk to me: 554 ... poor reputation"
 * carries dsn=4.x.x. Trusting the DSN there downgrades a hard reputation
 * rejection into a throttle and buries the finding.
 */
export function extractSmtpCode(reason: string): string {
  const m = /(?:^|[\s:])([45]\d{2})(?:[\s-]|$)/.exec(reason);
  return m ? m[1] : "";
}

/**
 * Classify a remote-MTA response string into a reputation-relevant category.
 *
 * Permanence is decided by the remote's own reply code when it states one, and
 * only falls back to Postfix's DSN otherwise. A genuine 4.x.x is a slow-down
 * signal; a 5.x.x is a refusal. Gmail's 421-4.7.28 throttle contains the word
 * "unsolicited" and must not read as a hard block. Blocklist hits outrank
 * both, because a deferral citing an RBL is still an RBL problem.
 */
export function classifyReason(reason: string, dsn = ""): { category: string; severity: string } {
  const remoteCode = extractSmtpCode(reason);
  // The remote's own code wins; the Postfix DSN is only a fallback.
  dsn = remoteCode ? `${remoteCode[0]}.0.0` : dsn;
  const blocklist = REASON_PATTERNS.find((p) => p.category === "blocklisted")!;
  if (blocklist.pattern.test(reason)) {
    return { category: blocklist.category, severity: blocklist.severity };
  }

  const ordered = dsn.startsWith("4")
    ? [
        // TEMP_PRIORITY order wins here, not the order they appear in the table:
        // "Greylisted, try again later" must not be swallowed by the throttle pattern.
        ...TEMP_PRIORITY.map((c) => REASON_PATTERNS.find((p) => p.category === c)).filter(
          (p): p is (typeof REASON_PATTERNS)[number] => Boolean(p)
        ),
        ...REASON_PATTERNS.filter((p) => !TEMP_PRIORITY.includes(p.category)),
      ]
    : REASON_PATTERNS;

  for (const { category, pattern, severity } of ordered) {
    if (category === "blocklisted") continue;
    if (pattern.test(reason)) {
      // A temporary response never counts as a permanent reputation block.
      if (category === "reputation_block" && dsn.startsWith("4")) {
        return { category: "throttled", severity: "warning" };
      }
      return { category, severity };
    }
  }
  return { category: "other", severity: "info" };
}

/** Strip volatile identifiers so similar rejection texts collapse into one bucket. */
export function normalizeReason(reason: string): string {
  return reason
    .replace(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g, "<ip>")
    .replace(/\b[0-9a-f]{16,}\b/gi, "<id>")
    .replace(/\b[A-Z0-9]{10,}\b/g, "<id>")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 220);
}

/** Parse raw Postfix log text into structured delivery events. */
export function parseDeliveryEvents(logText: string): DeliveryEvent[] {
  const events: DeliveryEvent[] = [];
  for (const line of logText.split("\n")) {
    if (!line.includes("status=")) continue;
    const m = DELIVERY_RE.exec(line);
    if (!m?.groups) continue;
    const to = (m.groups.to || "").toLowerCase();
    const domain = to.includes("@") ? to.split("@").pop()! : "unknown";
    const rawStatus = (m.groups.status || "other").toLowerCase();
    const status = (["sent", "deferred", "bounced", "expired"].includes(rawStatus)
      ? rawStatus
      : "other") as DeliveryEvent["status"];
    events.push({
      queue_id: m.groups.qid || "",
      recipient: to,
      recipient_domain: domain,
      provider: providerFor(domain),
      status,
      dsn: m.groups.dsn || "",
      reason: (m.groups.reason || "").replace(/^\(|\)$/g, "").trim(),
      relay: (m.groups.relay || "").trim(),
    });
  }
  return events;
}

/** Group delivery events by provider or by recipient domain. */
export function aggregateDeliveries(
  events: DeliveryEvent[],
  groupBy: "provider" | "domain",
  topReasons = 3
): DeliveryBucket[] {
  const groups = new Map<string, DeliveryEvent[]>();
  for (const e of events) {
    const key = groupBy === "provider" ? e.provider : e.recipient_domain;
    const list = groups.get(key);
    if (list) list.push(e);
    else groups.set(key, [e]);
  }

  const buckets: DeliveryBucket[] = [];
  for (const [key, list] of groups) {
    const sent = list.filter((e) => e.status === "sent").length;
    const deferred = list.filter((e) => e.status === "deferred").length;
    const bounced = list.filter((e) => e.status === "bounced").length;
    const expired = list.filter((e) => e.status === "expired").length;
    const total = list.length;

    // Collapse attempts down to people. One recipient retried 169 times is one
    // recipient, and the outcome that counts is the best one they ever got:
    // a success anywhere means the message reached them.
    const byRecipient = new Map<string, { delivered: boolean; hardFailed: boolean }>();
    for (const e of list) {
      const rec = byRecipient.get(e.recipient) ?? { delivered: false, hardFailed: false };
      if (e.status === "sent") rec.delivered = true;
      if (e.status === "bounced" || e.status === "expired") rec.hardFailed = true;
      byRecipient.set(e.recipient, rec);
    }
    const uniqueRecipients = byRecipient.size;
    let recipientsDelivered = 0;
    let recipientsBounced = 0;
    for (const rec of byRecipient.values()) {
      if (rec.delivered) recipientsDelivered += 1;
      else if (rec.hardFailed) recipientsBounced += 1;
    }
    const recipientsDeferred = uniqueRecipients - recipientsDelivered - recipientsBounced;

    const reasonCounts = new Map<string, { category: string; severity: string; count: number; sample: string }>();
    for (const e of list) {
      if (e.status === "sent" || !e.reason) continue;
      const { category, severity } = classifyReason(e.reason, e.dsn);
      const sample = normalizeReason(e.reason);
      const mapKey = `${category}::${sample}`;
      const existing = reasonCounts.get(mapKey);
      if (existing) existing.count += 1;
      else reasonCounts.set(mapKey, { category, severity, count: 1, sample });
    }

    buckets.push({
      key,
      total,
      sent,
      deferred,
      bounced,
      expired,
      deferral_rate: total ? Number(((deferred / total) * 100).toFixed(2)) : 0,
      bounce_rate: total ? Number((((bounced + expired) / total) * 100).toFixed(2)) : 0,
      unique_recipients: uniqueRecipients,
      recipients_delivered: recipientsDelivered,
      recipients_bounced: recipientsBounced,
      recipients_deferred: recipientsDeferred,
      delivery_rate: uniqueRecipients
        ? Number(((recipientsDelivered / uniqueRecipients) * 100).toFixed(2))
        : 0,
      attempts_per_recipient: uniqueRecipients
        ? Number((total / uniqueRecipients).toFixed(1))
        : 0,
      top_reasons: [...reasonCounts.values()].sort((a, b) => b.count - a.count).slice(0, topReasons),
    });
  }

  // Sort by people reached, not packets sent.
  return buckets.sort((a, b) => b.unique_recipients - a.unique_recipients);
}

/** Convert Mailcow's postfix log JSON array into flat log text. */
export function logEntriesToText(entries: unknown): string {
  if (!Array.isArray(entries)) return "";
  return entries
    .map((e) => {
      if (typeof e === "string") return e;
      const obj = e as Record<string, unknown>;
      const time = obj.time ? new Date(Number(obj.time) * 1000).toISOString() : "";
      return `${time} ${obj.program ?? ""} ${obj.message ?? ""}`.trim();
    })
    .join("\n");
}

/** Truncate a response body and append an explanatory note when over the limit. */
export function enforceLimit(text: string, hint: string): string {
  if (text.length <= CHARACTER_LIMIT) return text;
  return (
    text.slice(0, CHARACTER_LIMIT - 300) +
    `\n\n...[TRUNCATED at ${CHARACTER_LIMIT} characters. ${hint}]`
  );
}

/**
 * Render a markdown table from delivery buckets.
 *
 * Recipients lead, attempts follow. The retry column flags buckets where a few
 * stuck addresses are inflating the attempt counts.
 */
export function bucketsToMarkdown(buckets: DeliveryBucket[], label: string): string {
  const lines: string[] = [
    `| ${label} | Recipients | Delivered | Deferred | Failed | Delivery % | Attempts | Retries/rcpt |`,
    "|---|---:|---:|---:|---:|---:|---:|---:|",
  ];
  for (const b of buckets) {
    const retryFlag = b.attempts_per_recipient >= 5 ? ` ⚠` : "";
    lines.push(
      `| ${b.key} | ${b.unique_recipients} | ${b.recipients_delivered} | ${b.recipients_deferred} | ` +
        `${b.recipients_bounced} | ${b.delivery_rate}% | ${b.total} | ${b.attempts_per_recipient}${retryFlag} |`
    );
  }
  const detail: string[] = [];
  for (const b of buckets) {
    if (!b.top_reasons.length) continue;
    detail.push(
      `\n**${b.key}** — ${b.unique_recipients} recipient(s), ${b.total} attempts` +
        (b.attempts_per_recipient >= 5
          ? ` (retry storm: ${b.attempts_per_recipient}× per recipient)`
          : "") +
        `:`
    );
    for (const r of b.top_reasons) {
      detail.push(`- \`${r.category}\` (${r.severity}) ×${r.count}: ${r.sample}`);
    }
  }
  return lines.join("\n") + (detail.length ? "\n" + detail.join("\n") : "");
}
