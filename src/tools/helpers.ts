/** Shared helpers for tool handlers. */

import { enforceLimit } from "../services/analysis.js";

export interface ToolResponse {
  [key: string]: unknown;
  content: Array<{ type: "text"; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

/** Successful tool response carrying both prose and structured data. */
export function ok(text: string, structured?: Record<string, unknown>, hint = "Narrow the query or lower the limit."): ToolResponse {
  return {
    content: [{ type: "text", text: enforceLimit(text, hint) }],
    ...(structured ? { structuredContent: structured } : {}),
  };
}

/** Error tool response. Errors are returned, not thrown, so the model can recover. */
export function fail(message: string): ToolResponse {
  return {
    content: [{ type: "text", text: message.startsWith("Error") ? message : `Error: ${message}` }],
    isError: true,
  };
}

/** Wrap a handler so unexpected exceptions become actionable tool errors. */
export function guard<T>(fn: (args: T) => Promise<ToolResponse>): (args: T) => Promise<ToolResponse> {
  return async (args: T) => {
    try {
      return await fn(args);
    } catch (err) {
      return fail(err instanceof Error ? err.message : String(err));
    }
  };
}

/** Pretty-print JSON for the text channel. */
export function j(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

/**
 * Destructive operations require an explicit confirm flag. This keeps a single
 * misread instruction — including one planted in a message body the server just
 * read — from deleting a mailbox or flushing the queue in one hop.
 */
export function requireConfirm(confirm: boolean, what: string): ToolResponse | null {
  if (confirm) return null;
  return fail(
    `Refused: "${what}" is irreversible and was called without confirm=true. ` +
      `Show the user exactly what will be affected, get their agreement, then call again with confirm=true.`
  );
}
