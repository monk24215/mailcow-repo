/**
 * Mailcow REST API client.
 *
 * Mailcow exposes a uniform route grammar:
 *   GET  /api/v1/get/{category}/{object}/{extra}
 *   POST /api/v1/{add|edit|delete}/{category}
 * Authentication is the X-API-Key header. Keys are scoped read-only or
 * read-write AND are restricted to an allow-list of source IPs.
 */

import axios, { AxiosInstance } from "axios";
import { API_TIMEOUT_MS } from "../constants.js";
import type { MailcowActionResult } from "../types.js";

let client: AxiosInstance | null = null;

function baseUrl(): string {
  const url = process.env.MAILCOW_BASE_URL;
  if (!url) {
    throw new Error(
      "MAILCOW_BASE_URL is not set. Set it to your Mailcow UI origin, e.g. https://mail.example.com"
    );
  }
  return url.replace(/\/+$/, "");
}

function getClient(): AxiosInstance {
  if (client) return client;
  const apiKey = process.env.MAILCOW_API_KEY;
  if (!apiKey) {
    throw new Error(
      "MAILCOW_API_KEY is not set. Create a read-write API key in Mailcow under " +
        "System > Configuration > Access > API, and allow-list the IP this server runs from."
    );
  }
  client = axios.create({
    baseURL: baseUrl(),
    timeout: API_TIMEOUT_MS,
    headers: {
      "X-API-Key": apiKey,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    // Mailcow rejects requests whose Sec-Fetch-Dest header is not "empty".
    // Node does not send that header, so nothing to strip here.
    validateStatus: () => true,
  });
  return client;
}

/** Convert an unknown thrown value or non-2xx response into an actionable message. */
export function describeApiError(error: unknown, path: string): string {
  if (axios.isAxiosError(error)) {
    const status = error.response?.status;
    if (status === 401 || status === 403) {
      return (
        `Error: Mailcow rejected the API key (HTTP ${status}) for ${path}. ` +
        "Two things cause this: the key is wrong, or the source IP of this server is not in the " +
        "key's allowed-IP list in Mailcow (System > Configuration > Access > API). " +
        "A read-only key also returns this on add/edit/delete calls."
      );
    }
    if (status === 404) {
      return `Error: Route not found: ${path}. Check the category/object segments against the Mailcow API grammar.`;
    }
    if (error.code === "ECONNABORTED") {
      return `Error: Request to ${path} timed out after ${API_TIMEOUT_MS}ms.`;
    }
    if (error.code === "ENOTFOUND" || error.code === "ECONNREFUSED") {
      return `Error: Cannot reach ${baseUrl()} (${error.code}). Verify MAILCOW_BASE_URL and that the host is reachable from this machine.`;
    }
    return `Error: Mailcow API request to ${path} failed: ${error.message}`;
  }
  return `Error: ${error instanceof Error ? error.message : String(error)}`;
}

/** Perform a GET against /api/v1/get/{path}. */
export async function apiGet<T = unknown>(path: string, params?: Record<string, string>): Promise<T> {
  const clean = path.replace(/^\/+/, "");
  const url = `/api/v1/get/${clean}`;
  const res = await getClient().get(url, { params });
  if (res.status === 401 || res.status === 403) {
    throw new Error(describeApiError({ isAxiosError: true, response: { status: res.status } } as never, url));
  }
  if (res.status === 404) {
    throw new Error(`Error: Route not found: ${url}. Check the category/object segments.`);
  }
  if (res.status >= 400) {
    throw new Error(`Error: Mailcow returned HTTP ${res.status} for ${url}: ${JSON.stringify(res.data).slice(0, 400)}`);
  }
  return res.data as T;
}

/** Perform a POST against /api/v1/{action}/{resource}. */
export async function apiPost(
  action: "add" | "edit" | "delete",
  resource: string,
  body: unknown
): Promise<MailcowActionResult[]> {
  const clean = resource.replace(/^\/+/, "");
  const url = `/api/v1/${action}/${clean}`;
  const res = await getClient().post(url, body);
  if (res.status === 401 || res.status === 403) {
    throw new Error(
      `Error: Mailcow rejected the API key (HTTP ${res.status}) for ${url}. ` +
        "Write calls need a read-write key whose allowed-IP list includes this machine."
    );
  }
  if (res.status === 404) {
    throw new Error(`Error: Route not found: ${url}.`);
  }
  if (res.status >= 400) {
    throw new Error(`Error: Mailcow returned HTTP ${res.status} for ${url}: ${JSON.stringify(res.data).slice(0, 400)}`);
  }
  const data = res.data;
  const results: MailcowActionResult[] = Array.isArray(data) ? data : [data as MailcowActionResult];
  return results;
}

/** True when every entry in a Mailcow write response reports success. */
export function allSucceeded(results: MailcowActionResult[]): boolean {
  return results.length > 0 && results.every((r) => r?.type === "success");
}

/** Flatten Mailcow's nested msg arrays into readable lines. */
export function formatActionResults(results: MailcowActionResult[]): string {
  return results
    .map((r) => {
      const msg = Array.isArray(r?.msg) ? r.msg.flat(Infinity).join(" ") : String(r?.msg ?? "");
      return `- [${r?.type ?? "unknown"}] ${msg}`;
    })
    .join("\n");
}
