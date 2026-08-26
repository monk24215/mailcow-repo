/** Shared constants and environment configuration. */

export const SERVER_NAME = "mailcow-mcp-server";
export const SERVER_VERSION = "1.0.0";

/** Maximum characters returned in a single tool response before truncation. */
export const CHARACTER_LIMIT = 25000;

/** Default timeout for Mailcow HTTP API requests, in milliseconds. */
export const API_TIMEOUT_MS = 30000;

/** Default timeout for a single remote SSH command, in milliseconds. */
export const SSH_TIMEOUT_MS = 60000;

/** Mailcow log sources exposed by GET /api/v1/get/logs/{source}/{count}. */
export const LOG_SOURCES = [
  "postfix",
  "dovecot",
  "rspamd-history",
  "rspamd-stats",
  "netfilter",
  "ratelimited",
  "sasl",
  "api",
  "acme",
  "watchdog",
  "ui",
  "sogo",
  "autodiscover",
  "cron",
] as const;

export type LogSource = (typeof LOG_SOURCES)[number];

/**
 * Recipient-domain to mailbox-provider mapping. Sending reputation is scored
 * per provider, not per domain, so delivery analysis is grouped this way.
 */
export const PROVIDER_MAP: Record<string, string> = {
  "gmail.com": "Google",
  "googlemail.com": "Google",
  "google.com": "Google",
  "hotmail.com": "Microsoft",
  "outlook.com": "Microsoft",
  "live.com": "Microsoft",
  "msn.com": "Microsoft",
  "hotmail.co.uk": "Microsoft",
  "outlook.co.uk": "Microsoft",
  "yahoo.com": "Yahoo/AOL",
  "yahoo.co.uk": "Yahoo/AOL",
  "ymail.com": "Yahoo/AOL",
  "rocketmail.com": "Yahoo/AOL",
  "aol.com": "Yahoo/AOL",
  "verizon.net": "Yahoo/AOL",
  "att.net": "Yahoo/AOL",
  "sbcglobal.net": "Yahoo/AOL",
  "bellsouth.net": "Yahoo/AOL",
  "icloud.com": "Apple",
  "me.com": "Apple",
  "mac.com": "Apple",
  "comcast.net": "Comcast",
  "xfinity.com": "Comcast",
  "proton.me": "Proton",
  "protonmail.com": "Proton",
  "zoho.com": "Zoho",
  "gmx.com": "GMX/Web.de",
  "gmx.de": "GMX/Web.de",
  "web.de": "GMX/Web.de",
  "mail.com": "GMX/Web.de",
  "mail.ru": "Mail.ru",
  "yandex.ru": "Yandex",
  "cox.net": "Cox",
  "charter.net": "Spectrum",
  "spectrum.net": "Spectrum",
  "roadrunner.com": "Spectrum",
  "rr.com": "Spectrum",
  "earthlink.net": "Earthlink",
  "juno.com": "United Online",
  "netzero.net": "United Online",
};

/**
 * Ordered classifiers for Postfix/remote-MTA rejection and deferral text.
 * First match wins, so the most reputation-specific patterns come first.
 */
export const REASON_PATTERNS: Array<{ category: string; pattern: RegExp; severity: "critical" | "warning" | "info" }> = [
  {
    category: "blocklisted",
    severity: "critical",
    // "blacklisted" must match as well as "blacklist" — KPN's rejection reads
    // "Your IP has been blacklisted", and a trailing \b after the stem misses it.
    pattern:
      /(\bspamhaus\b|\bbarracudacentral\b|\bblocked using\b|\blisted by\b|\blisted in\b|\bdnsbl\b|\brbl\b|\bsbl-xbl\b|\buceprotect\b|\bspamcop\b|\bsenderscore\b|\binvaluement\b|\bsorbs\b|\bpsbl\b|\bspamrats\b|\bblack-?list(ed|ing)?\b|\bdeny-?list(ed|ing)?\b|\bblock-?list(ed|ing)?\b)/i,
  },
  {
    category: "reputation_block",
    severity: "critical",
    // Includes the terse forms real providers actually send: MailChannels'
    // "550 [S10] Blocked" and Orange's "Service refused. OFR006_103" carry no
    // explanatory text at all, so they must be matched on their codes.
    pattern:
      /(\bunsolicited\b|\bbulk mail\b|\bspam-?like\b|\bspammy\b|\bpoor reputation\b|\bbad reputation\b|\bip reputation\b|\bsender reputation\b|\bnot accepted for policy reasons\b|\bs3150\b|\[s\d{1,3}\]\s*blocked\b|\bservice refus(e|ed|é)\b|\bofr\d{3}_\d+\b|\baccess to this mail system has been rejected\b|\bhas been blocked\b|\bwe do not accept mail\b|\b5\.7\.606\b|\b5\.7\.1 service unavailable\b|\bblocked\b)/i,
  },
  // NOTE: every alternative carries its own boundaries. Do NOT wrap the whole
  // alternation in \b(...)\b — a trailing \b after a stem like "throttl" or
  // "blacklist" makes it fail on the inflected forms servers actually send
  // ("Throttled", "has been blacklisted"), which is how a critical finding
  // silently degrades to "other".
  {
    category: "throttled",
    severity: "warning",
    pattern:
      /(\brate ?limit\w*|\btoo many\b|\bthrottl\w*|\btry again later\b|\btemporarily deferred\b|\btemporarily rate limited\b|\b4\.7\.28\b|\b4\.7\.0 \[ts0|\b421 4\.7|\bslow down\b|\bconnection limit\w*\b|\btoo much mail\b|\bdeferred due to (?:user|excessive) complaints\b|\btoo fast\b|\bnew or untrusted ip\b|\bsending rate\b)/i,
  },
  {
    category: "auth_failure",
    severity: "critical",
    pattern:
      /(\bspf\b|\bdkim\b|\bdmarc\b|\bdnssec\b|does not (?:pass|meet) .*(?:authentication|spf|dkim)|\bunauthenticated\b|\bauthentication check\w*|\b5\.7\.23\b|\b5\.7\.26\b|\b5\.7\.20\b|\b5\.7\.509\b)/i,
  },
  {
    category: "greylisted",
    severity: "info",
    pattern: /(\bgrey-?list\w*|\bgray-?list\w*|\b4\.7\.1 greylisting\b|\btry again in\b|\b450 4\.2\.0\b)/i,
  },
  {
    category: "user_unknown",
    severity: "info",
    pattern:
      /(\buser unknown\b|\bno such user\b|recipient (?:address )?rejected|\bunknown user\b|does not exist|\bmailbox unavailable\b|address (?:not found|rejected)|\b5\.1\.1\b|\b5\.1\.10\b|\b550 5\.1)/i,
  },
  {
    category: "mailbox_full",
    severity: "info",
    pattern:
      /(\bover ?quota\b|\bquota exceeded\b|\bmailbox full\b|insufficient (?:system )?storage|out of storage space|\b4\.2\.2\b|\b5\.2\.2\b|\b4\.1\.1 <)/i,
  },
  {
    category: "domain_error",
    severity: "info",
    pattern:
      /(host or domain name not found|name service error|\bno mx\b|unable to look up|domain not found|\bhost not found\b|\b4\.4\.3\b|\b5\.4\.4\b)/i,
  },
  {
    category: "connection_error",
    severity: "warning",
    pattern:
      /(connection timed out|connection refused|lost connection|network is unreachable|no route to host|\btimed? ?out\b|conversation with .* timed out)/i,
  },
  {
    category: "tls_error",
    severity: "warning",
    pattern: /(\btls\b|\bcertificate\b|\bssl\b|\bhandshake\b)/i,
  },
];

/**
 * Remote commands that are read-only and therefore need no confirmation token.
 * Anything not matching requires confirm=true on mailsrv_run.
 */
export const READONLY_COMMAND_PATTERNS: RegExp[] = [
  /^\s*docker\s+(ps|logs|stats|inspect|images|version|compose\s+(ps|logs|version|config))\b/i,
  /^\s*docker\s+exec\s+\S+\s+(postqueue\s+-p|postconf|rspamc\s+(stat|counters)|mailq|postcat|df|cat|ls|head|tail|grep)\b/i,
  /^\s*(uptime|df|free|w|who|id|hostname|uname|date|nproc|lsblk|ss|netstat|dig|host|nslookup|ping|traceroute|curl\s+-s?I)\b/i,
  /^\s*(cat|less|head|tail|grep|zgrep|awk|sed\s+-n|wc|sort|uniq|find|ls|stat|journalctl)\b/i,
  /^\s*(systemctl\s+(status|list-units|is-active)|fail2ban-client\s+status)\b/i,
];
