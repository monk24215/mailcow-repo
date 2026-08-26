/** Shared type definitions. */

/** A single write-action response entry from the Mailcow API. */
export interface MailcowActionResult {
  type: "success" | "danger" | "warning" | "error" | string;
  msg?: unknown;
  log?: unknown;
}

/** A Postfix log entry as returned by GET /api/v1/get/logs/postfix/{n}. */
export interface PostfixLogEntry {
  time?: number | string;
  priority?: string;
  program?: string;
  message?: string;
}

/** One item from GET /api/v1/get/mailq/all. */
export interface MailqEntry {
  queue_id?: string;
  queue_name?: string;
  arrival_time?: number;
  message_size?: number;
  sender?: string;
  recipients?: Array<{ address?: string; delay_reason?: string }>;
  recipient_count?: number;
}

/** Result of executing one command over SSH. */
export interface SshResult {
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  duration_ms: number;
}

/** A parsed Postfix delivery attempt. */
export interface DeliveryEvent {
  queue_id: string;
  recipient: string;
  recipient_domain: string;
  provider: string;
  status: "sent" | "deferred" | "bounced" | "expired" | "other";
  dsn: string;
  reason: string;
  relay: string;
}

/**
 * Aggregated delivery outcome for one provider or recipient domain.
 *
 * Two denominators live here and they answer different questions. The
 * attempt-based fields (total/sent/deferred/...) describe MTA traffic. The
 * recipient-based fields describe people. At warmup volumes they diverge
 * wildly: Postfix will retry one refused address 169 times, which reads as a
 * provider-wide outage if you only count attempts. Judge reputation on the
 * recipient fields; use the attempt fields to spot retry storms.
 */
export interface DeliveryBucket {
  key: string;
  total: number;
  sent: number;
  deferred: number;
  bounced: number;
  expired: number;
  deferral_rate: number;
  bounce_rate: number;
  /** Distinct recipient addresses seen in this bucket. */
  unique_recipients: number;
  /** Recipients for whom at least one attempt succeeded. */
  recipients_delivered: number;
  /** Recipients with no success and at least one hard failure. */
  recipients_bounced: number;
  /** Recipients still only deferred — never delivered, never hard-failed. */
  recipients_deferred: number;
  /** recipients_delivered / unique_recipients, as a percentage. */
  delivery_rate: number;
  /** total / unique_recipients. Above ~5 indicates a retry storm. */
  attempts_per_recipient: number;
  top_reasons: Array<{ category: string; severity: string; count: number; sample: string }>;
}

export enum ResponseFormat {
  MARKDOWN = "markdown",
  JSON = "json",
}
