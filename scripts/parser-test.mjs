/**
 * Offline check of the Postfix log parser and delivery aggregation.
 * Run: node scripts/parser-test.mjs
 */

import { parseDeliveryEvents, aggregateDeliveries, classifyReason } from "../dist/services/analysis.js";

const SAMPLE = `
Aug 25 09:12:01 mail postfix/smtp[2211]: 4A1B2C3D4E: to=<alice@gmail.com>, relay=gmail-smtp-in.l.google.com[142.250.115.26]:25, delay=1.4, delays=0.1/0/0.6/0.7, dsn=2.0.0, status=sent (250 2.0.0 OK  1724577121 x12-20020a05 - gsmtp)
Aug 25 09:12:03 mail postfix/smtp[2212]: 4A1B2C3D4F: to=<bob@gmail.com>, relay=gmail-smtp-in.l.google.com[142.250.115.26]:25, delay=2.1, delays=0.1/0/1.2/0.8, dsn=4.7.0, status=deferred (host gmail-smtp-in.l.google.com[142.250.115.26] said: 421-4.7.28 Our system has detected an unusual rate of unsolicited mail originating from your IP address (in reply to end of DATA command))
Aug 25 09:12:05 mail postfix/smtp[2213]: 4A1B2C3D50: to=<carol@yahoo.com>, relay=mta5.am0.yahoodns.net[67.195.204.72]:25, delay=3.0, delays=0.1/0/1.0/1.9, dsn=5.7.1, status=bounced (host mta5.am0.yahoodns.net[67.195.204.72] said: 554 5.7.9 Message not accepted for policy reasons. See https://senders.yahooinc.com/ (in reply to end of DATA command))
Aug 25 09:12:07 mail postfix/smtp[2214]: 4A1B2C3D51: to=<dave@hotmail.com>, relay=hotmail-com.olc.protection.outlook.com[104.47.55.33]:25, delay=4.2, delays=0.1/0/2.0/2.1, dsn=5.1.1, status=bounced (host hotmail-com.olc.protection.outlook.com said: 550 5.1.1 Requested action not taken: mailbox unavailable)
Aug 25 09:12:09 mail postfix/smtp[2215]: 4A1B2C3D52: to=<erin@hotmail.com>, relay=hotmail-com.olc.protection.outlook.com[104.47.55.33]:25, delay=1.0, delays=0.1/0/0.4/0.5, dsn=2.0.0, status=sent (250 2.6.0 <id> Queued mail for delivery)
Aug 25 09:12:11 mail postfix/smtp[2216]: 4A1B2C3D53: to=<frank@comcast.net>, relay=mx1.comcast.net[96.114.157.80]:25, delay=6.0, delays=0.1/0/3.0/2.9, dsn=4.2.0, status=deferred (host mx1.comcast.net said: 421 4.2.0 Greylisted, please try again later)
Aug 25 09:12:13 mail postfix/smtp[2217]: 4A1B2C3D54: to=<gina@aol.com>, relay=mx-aol.mail.gm0.yahoodns.net[74.6.137.63]:25, delay=2.2, delays=0.1/0/1.0/1.1, dsn=5.7.1, status=bounced (host mx-aol.mail.gm0.yahoodns.net said: 553 5.7.1 [BL21] Connections will not be accepted from 1.2.3.4, because this IP is listed by Spamhaus)
Aug 25 09:12:15 mail postfix/smtp[2218]: 4A1B2C3D55: to=<hank@gmail.com>, relay=gmail-smtp-in.l.google.com[142.250.115.26]:25, delay=1.1, delays=0.1/0/0.5/0.5, dsn=2.0.0, status=sent (250 2.0.0 OK)
`.trim();

const events = parseDeliveryEvents(SAMPLE);
console.log(`parsed events: ${events.length} (expected 8)`);
if (events.length !== 8) {
  console.error("FAIL: parser missed lines");
  process.exit(1);
}

const providers = new Set(events.map((e) => e.provider));
console.log("providers:", [...providers].join(", "));

const buckets = aggregateDeliveries(events, "provider");
for (const b of buckets) {
  console.log(
    `${b.key.padEnd(12)} total=${b.total} sent=${b.sent} deferred=${b.deferred} bounced=${b.bounced} ` +
      `defer=${b.deferral_rate}% bounce=${b.bounce_rate}% reasons=${b.top_reasons.map((r) => r.category).join("/") || "-"}`
  );
}

const checks = [
  ["Google bucket correct", buckets.some((b) => b.key === "Google" && b.total === 3 && b.sent === 2 && b.deferred === 1)],
  ["Yahoo/AOL grouped together", buckets.some((b) => b.key === "Yahoo/AOL" && b.total === 2 && b.bounced === 2)],
  ["Microsoft grouped together", buckets.some((b) => b.key === "Microsoft" && b.total === 2 && b.sent === 1)],
  ["Comcast deferral counted", buckets.some((b) => b.key === "Comcast" && b.deferred === 1)],
  [
    "4.x throttle not mistaken for a hard block",
    classifyReason("421-4.7.28 Our system has detected an unusual rate of unsolicited mail", "4.7.0").category ===
      "throttled",
  ],
  ["blocklist outranks everything", classifyReason("this IP is listed by Spamhaus", "5.7.1").category === "blocklisted"],
  [
    "5.x policy refusal is a reputation block",
    classifyReason("554 5.7.9 Message not accepted for policy reasons", "5.7.1").category === "reputation_block",
  ],
  ["user_unknown classified", classifyReason("550 5.1.1 mailbox unavailable", "5.1.1").category === "user_unknown"],
  [
    "greylisting beats generic throttling",
    classifyReason("421 4.2.0 Greylisted, please try again later", "4.2.0").category === "greylisted",
  ],
  [
    "auth failure classified",
    classifyReason("550 5.7.26 This message does not pass authentication checks (SPF and DKIM)", "5.7.26").category ===
      "auth_failure",
  ],
  ["Google deferral tagged throttled", buckets.find((b) => b.key === "Google")?.top_reasons[0]?.category === "throttled"],
  [
    "AOL blocklist hit surfaced as critical",
    buckets
      .find((b) => b.key === "Yahoo/AOL")
      ?.top_reasons.some((r) => r.category === "blocklisted" && r.severity === "critical") === true,
  ],
];

// Verbatim rejection strings pulled from a live mail log. Each of these was
// misclassified at some point; they are here so that stays fixed.
const REAL_WORLD = [
  {
    name: "KPN names the blacklisting",
    reason:
      "host mx.kpnmail.nl[195.121.94.1] refused to talk to me: 521 5.5.0 Your IP [192.0.2.10] has been blacklisted. Please contact abuse@kpn.com for more information.",
    dsn: "4.0.0",
    expect: "blocklisted",
    severity: "critical",
  },
  {
    name: "MailChannels terse block",
    reason: "host mx1.mailchannels.net[23.83.209.1] refused to talk to me: 550 [S10] Blocked",
    dsn: "4.0.0",
    expect: "reputation_block",
    severity: "critical",
  },
  {
    name: "Cisco 554 beats the Postfix 4.x DSN",
    reason:
      "host mx2.hc2916-71.iphmx.com[68.232.1.1] refused to talk to me: 554-esa6.hc2916-71.iphmx.com 554 Your access to this mail system has been rejected due to the sending MTA's poor reputation.",
    dsn: "4.0.0",
    expect: "reputation_block",
    severity: "critical",
  },
  {
    name: "Orange OFR code",
    reason:
      "host smtp-in.orange.fr[193.252.22.1] refused to talk to me: 550 opmta1mti37nd1 smtp.orange.fr xZBIwcGuCj51b Service refuse. Service refused. OFR006_103 - please visit: https://postmaster.orange.fr/ [103]",
    dsn: "4.0.0",
    expect: "reputation_block",
    severity: "critical",
  },
  {
    name: "Rackspace new-IP throttle stays a throttle",
    reason:
      "host mx2.emailsrvr.com[146.20.1.1] said: 451 4.7.1 Received too many messages from a new or untrusted IP: 192.0.2.10 (Z27/80343E7) (G28) (in reply to RCPT TO command)",
    dsn: "4.7.1",
    expect: "throttled",
    severity: "warning",
  },
  {
    name: "Gmail over-quota is not reputation",
    reason:
      "host alt1.gmail-smtp-in.l.google.com[142.250.1.1] said: 452-4.2.2 The recipient's inbox is out of storage space.",
    dsn: "4.2.2",
    expect: "mailbox_full",
    severity: "info",
  },
  {
    name: "Comcast throttle stays a throttle",
    reason:
      "host mx2.mxge.comcast.net[96.114.1.1] said: 451 4.2.0 Throttled - https://postmaster.comcast.net/smtp-error-codes.php#RL000010",
    dsn: "4.2.0",
    expect: "throttled",
    severity: "warning",
  },
  {
    name: "Cloudflare unknown recipient stays list hygiene",
    reason: "host route3.mx.cloudflare.net[172.64.1.1] said: 550 5.1.1 Address does not exist. H471xiwLArEQ",
    dsn: "5.1.1",
    expect: "user_unknown",
    severity: "info",
  },
];

for (const c of REAL_WORLD) {
  const got = classifyReason(c.reason, c.dsn);
  checks.push([
    `${c.name} -> ${c.expect}/${c.severity}`,
    got.category === c.expect && got.severity === c.severity,
  ]);
}

// Retry-storm case: one refused address at a small domain, retried 40 times,
// alongside 30 real recipients who were all delivered. Counting attempts makes
// the small domain look like the dominant destination; counting people does not.
// Queue IDs must look like real Postfix ones (uppercase hex, 8-20 chars),
// otherwise the parser correctly ignores the line.
const qid = (prefix, i) => `${prefix}${i.toString(16).toUpperCase().padStart(2, "0")}`;
const stormLines = [];
for (let i = 0; i < 40; i++) {
  stormLines.push(
    `Aug 25 09:${String(i % 60).padStart(2, "0")}:00 mail postfix/smtp[9${i}]: ${qid("4A1B2C3D", i)}: to=<stuck@refuser.tld>, relay=mx.refuser.tld[10.0.0.1]:25, delay=1, delays=0/0/0/1, dsn=4.0.0, status=deferred (host mx.refuser.tld refused to talk to me: 550 [S10] Blocked)`
  );
}
for (let i = 0; i < 30; i++) {
  stormLines.push(
    `Aug 25 10:${String(i % 60).padStart(2, "0")}:00 mail postfix/smtp[8${i}]: ${qid("5B2C3D4E", i)}: to=<user${i}@yahoo.com>, relay=mta5.am0.yahoodns.net[67.195.204.72]:25, delay=1, delays=0/0/0/1, dsn=2.0.0, status=sent (250 ok)`
  );
}
const stormEvents = parseDeliveryEvents(stormLines.join("\n"));
const stormBuckets = aggregateDeliveries(stormEvents, "domain");
const refuser = stormBuckets.find((b) => b.key === "refuser.tld");
const yahooB = stormBuckets.find((b) => b.key === "yahoo.com");

console.log(
  `\nretry storm: refuser.tld ${refuser?.unique_recipients} recipient / ${refuser?.total} attempts ` +
    `(${refuser?.attempts_per_recipient}x), yahoo.com ${yahooB?.unique_recipients} recipients`
);

checks.push(
  ["retry storm collapses to 1 recipient", refuser?.unique_recipients === 1],
  ["retry storm still shows 40 attempts", refuser?.total === 40],
  ["attempts_per_recipient flags the storm", (refuser?.attempts_per_recipient ?? 0) >= 10],
  ["stuck recipient counted as undelivered", refuser?.recipients_deferred === 1 && refuser?.recipients_delivered === 0],
  ["yahoo recipients all delivered", yahooB?.unique_recipients === 30 && yahooB?.delivery_rate === 100],
  [
    "buckets sort by people, not attempts",
    stormBuckets[0]?.key === "yahoo.com",
  ]
);

let failed = 0;
for (const [name, pass] of checks) {
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}`);
  if (!pass) failed += 1;
}

process.exit(failed === 0 ? 0 : 1);
