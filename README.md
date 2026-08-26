# mailcow-mcp-server

An MCP server that gives Claude direct access to a [Mailcow](https://mailcow.email/) install and the mail host underneath it — built for the part of self-hosted email that actually hurts: **sending reputation**.

Wrapping the Mailcow API is the easy half. The useful half is the analysis layer, which reads Postfix delivery logs and answers the question you actually have: *is a provider unhappy with us, and if so, why, and what do we do about it?*

```
> Give me a reputation snapshot for the last 24 hours.

Verdict: HEALTHY
1,265 delivery attempts across 606 recipients at major providers
Yahoo/AOL 344 · Microsoft 87 · Apple 61 · Google 60 — all 100% delivered
Queue empty · 0 bans · 0 self-throttled · Rspamd 0 rejects
```

---

## ⚠️ Read this before installing

This server hands a language model administrative control of a mail server, and some of the text it reads is written by strangers.

**Untrusted input reaches tools that can delete things.** `mailcow_get_queued_message` returns third-party message bodies. `reputation_delivery_breakdown` parses rejection strings written by remote mail servers. Both are attacker-influenced. The same session also has tools that can delete a mailbox, drop the queue, or rotate a DKIM key.

Two guardrails exist and you should not remove them:

- **Irreversible operations refuse without `confirm: true`** — deleting a domain, mailbox, alias, DKIM key or quarantine item, and flushing or dropping the queue. The refusal tells the model to show you the scope first.
- **`mailsrv_run` allow-lists read-only commands** (`docker ps/logs/inspect`, `postqueue -p`, `rspamc stat`, `cat`/`grep`/`tail`, `df`/`free`/`uptime`, `dig`, `systemctl status`). Everything else — restarts, `postsuper`, package installs, config edits — requires `confirm: true`.

If you want a lower-risk setup, issue a **read-only** Mailcow API key. Every read tool keeps working; the management tools fail cleanly with a message explaining why.

---

## What's in it

**Reputation analysis** — the reason this exists.

| Tool | Answers |
|---|---|
| `reputation_snapshot` | "How are we doing right now?" Containers, queue, delivery outcomes, self-throttling, Rspamd, bans → a verdict of healthy / watch / degraded / critical. |
| `reputation_delivery_breakdown` | "Who's unhappy and what did they say?" Per-recipient delivery outcomes grouped by mailbox provider, with each remote MTA's rejection text classified. |
| `reputation_warmup_status` | "Can we send more yet?" Per-provider acceptance against configured rate limits, returning increase / hold / reduce / stop for each. |
| `reputation_auth_audit` | "Is our DKIM actually valid?" Compares the key Mailcow signs with against what DNS publishes, plus SPF/DMARC presence and auth failures in the log. |

**Mailcow administration** — 19 tools covering domains, mailboxes, aliases, DKIM, rate limits, allow/block policy, the queue, quarantine, and netfilter. Plus `mailcow_api_request`, a raw passthrough for any route without a dedicated tool, so you're never boxed in.

**Mail host access** — 6 SSH-backed tools for Postfix queue inspection, Rspamd stats, deep log search beyond Mailcow's Redis retention, host health, DNS/PTR checks, and arbitrary commands.

Full tool list in [Tools](#tools) below.

---

## Requirements

- Node.js 18+
- A Mailcow install (developed against **2026-07a**)
- A Mailcow API key — read-write for management, read-only if you'd rather not grant that
- *Optional:* SSH access to the mail host with Docker permissions, for the `mailsrv_*` tools and deeper log history

---

## Install

```bash
git clone https://github.com/YOUR-USER/mailcow-mcp-server.git
cd mailcow-mcp-server
npm install
npm run build
cp .env.example .env      # fill it in
node scripts/selftest.mjs
```

`selftest.mjs` verifies the API key, checks whether it's read-write or read-only, confirms the queue and Postfix logs are readable, and — if SSH is configured — proves Docker access and resolves the Mailcow container names. **Run it before registering.** Every failure mode below is easier to diagnose there than through a chat client.

### Getting a Mailcow API key

Mailcow UI → **System → Configuration** (`/admin/system`) → **Access → Admins** tab → scroll to **Read-Write Access**:

1. Tick **Activate API**, hit **Save** — the key field populates
2. Add the **public IP of the machine running this server** to *"Allow API access from these IPs/CIDR network notations"*

That second step causes most `401`s. The IP that needs allow-listing is wherever the MCP server runs — usually your desktop, **not** the mail server. If your ISP rotates your address, either use a CIDR range or tick *Skip IP check for API* (which makes the key alone sufficient — treat it accordingly).

### SSH setup

Generate a dedicated key rather than reusing your interactive one — it can be revoked independently and shows up distinctly in `authorized_keys`:

```bash
ssh-keygen -t ed25519 -N "" -C "mailcow-mcp" -f ~/.ssh/mailcow_mcp
ssh-copy-id -i ~/.ssh/mailcow_mcp.pub root@your-mail-host
```

`-N ""` sets an empty passphrase. An encrypted key fails with *"Encrypted private OpenSSH key detected"* — this server talks to the key file directly and never consults ssh-agent, so a key your normal `ssh` opens silently via the agent will still fail here.

The SSH user needs Docker access (`root`, or a member of the `docker` group). Note that docker-group membership is effectively root — what a dedicated user buys you is a separate audit trail and independent revocation, not reduced privilege.

Without SSH the server still works. You lose the `mailsrv_*` tools and log history is capped at what Mailcow keeps in Redis (a few thousand lines).

---

## Configuration

| Variable | Required | Notes |
|---|---|---|
| `MAILCOW_BASE_URL` | yes | Mailcow UI origin, no trailing slash |
| `MAILCOW_API_KEY` | yes | Read-write for management tools; read-only works for everything else |
| `MAIL_SSH_HOST` | no | Enables `mailsrv_*`. Prefer the IP over a hostname — a Cloudflare-proxied hostname won't reach SSH |
| `MAIL_SSH_USER` | no | Default `root` |
| `MAIL_SSH_PORT` | no | Default `22` |
| `MAIL_SSH_KEY_PATH` | no | **Absolute path.** OpenSSH format — a PuTTY `.ppk` won't load |
| `MAIL_SSH_KEY_PASSPHRASE` | no | Only if the key is encrypted |
| `MAIL_SSH_PASSWORD` | no | Alternative to key auth |

Note the server itself does **not** read `.env` — that file exists for `selftest.mjs`. At runtime, credentials come from your MCP client's config.

## Registering

**Claude Desktop** — Settings → Developer → Edit Config:

```json
{
  "mcpServers": {
    "mailcow": {
      "command": "node",
      "args": ["/absolute/path/to/mailcow-mcp-server/dist/index.js"],
      "env": {
        "MAILCOW_BASE_URL": "https://mail.example.com",
        "MAILCOW_API_KEY": "your-key",
        "MAIL_SSH_HOST": "203.0.113.10",
        "MAIL_SSH_USER": "root",
        "MAIL_SSH_KEY_PATH": "/home/you/.ssh/mailcow_mcp"
      }
    }
  }
}
```

On Windows, escape backslashes: `"C:\\Users\\you\\.ssh\\mailcow_mcp"`. Then **fully quit** the app from the system tray — closing the window leaves the server process running with the old build.

**Claude Code** — one command:

```bash
claude mcp add mailcow -s user \
  -e MAILCOW_BASE_URL=https://mail.example.com \
  -e MAILCOW_API_KEY=your-key \
  -e MAIL_SSH_HOST=203.0.113.10 \
  -e MAIL_SSH_USER=root \
  -e MAIL_SSH_KEY_PATH=/home/you/.ssh/mailcow_mcp \
  -- node /absolute/path/to/mailcow-mcp-server/dist/index.js
```

---

## Two ideas worth understanding

Everything useful in the analysis layer rests on these.

### Recipients, not attempts

Postfix retries a deferred address for days. One permanently refused subscriber can generate **150+ delivery attempts**. Count attempts and a dozen dead addresses look like a provider-wide outage:

| | Attempts | Unique recipients |
|---|---:|---:|
| `usa.net` | 169 | **1** |
| `orange.fr` + `wanadoo.fr` | 468 | **9** |
| `hetnet.nl` | 97 | **2** |

Read as attempts, that's a 56% deferral rate and an urgent French deliverability crisis. Read as recipients, it's about twenty dead addresses that need suppressing.

Every tool reports both. `unique_recipients` and `delivery_rate` are the real numbers; `attempts` and `attempts_per_recipient` exist to expose retry storms. No verdict is issued below 20 recipients — the tools return `insufficient_data` rather than a percentage computed from noise.

### Failure categories, not a bounce rate

An aggregate bounce rate tells you nothing actionable. These do:

| Category | Severity | Means | Do |
|---|---|---|---|
| `blocklisted` | critical | An RBL is named in the response | Delist first — sending more deepens it |
| `reputation_block` | critical | 5.x policy refusal; the provider has decided about you | Stop to that provider, fix the cause |
| `auth_failure` | critical | SPF/DKIM/DMARC failed at the receiver | Run `reputation_auth_audit` |
| `throttled` | warning | 4.x rate signal | Slow down — volume is ahead of your standing |
| `connection_error` | warning | Reachability, not reputation | Usually transient |
| `tls_error` | warning | Certificate or handshake | Check your TLS config |
| `greylisted` | info | Normal; retries succeed | Nothing |
| `user_unknown` | info | List hygiene | Suppress — a high rate *causes* reputation damage |
| `mailbox_full` | info | Recipient-side | Nothing |
| `domain_error` | info | Dead domain | Suppress |

Two rules the classifier enforces that are easy to get wrong:

**The remote's SMTP code beats Postfix's DSN.** Postfix records a connect-stage refusal as a *deferral* with a 4.x DSN even when the server plainly said `554`. Trusting the DSN downgrades a hard reputation rejection into a throttle and buries it.

**A 4.x response is never a permanent block.** Gmail's `421-4.7.28` throttle contains the words *"unusual rate of unsolicited mail"* — matched naively, that reads as a hard block and sends you chasing the wrong fix. Blocklist mentions outrank both rules, because a deferral citing an RBL is still an RBL problem.

---

## Tools

<details>
<summary><strong>Reputation</strong> (4)</summary>

`reputation_snapshot` · `reputation_delivery_breakdown` · `reputation_warmup_status` · `reputation_auth_audit`
</details>

<details>
<summary><strong>Mailcow — read</strong> (13)</summary>

`mailcow_status` · `mailcow_list_domains` · `mailcow_list_mailboxes` · `mailcow_list_aliases` · `mailcow_get_dkim` · `mailcow_get_logs` · `mailcow_get_queue` · `mailcow_get_queued_message` · `mailcow_get_quarantine` · `mailcow_get_ratelimits` · `mailcow_get_policy` · `mailcow_get_fail2ban` · `mailcow_get_rspamd_actions`
</details>

<details>
<summary><strong>Mailcow — write</strong> (10)</summary>

`mailcow_manage_domain` · `mailcow_manage_mailbox` · `mailcow_manage_alias` · `mailcow_manage_dkim` · `mailcow_manage_queue` · `mailcow_manage_quarantine` · `mailcow_set_ratelimit` · `mailcow_manage_policy` · `mailcow_edit_fail2ban` · `mailcow_api_request`
</details>

<details>
<summary><strong>Mail host — SSH</strong> (6)</summary>

`mailsrv_postfix_queue` · `mailsrv_rspamd_stats` · `mailsrv_mail_log` · `mailsrv_host_health` · `mailsrv_dns_check` · `mailsrv_run`
</details>

Every tool carries a full description with argument types, return schema, and worked examples — your client will show them.

---

## Things it's good at

```
"Gmail deferrals are up — what exactly are they saying?"
"Does the DKIM record in DNS still match what Mailcow is signing with?"
"Are we clear to raise warmup volume this week?"
"The queue is at 4,000 — what's stuck and why?"
"Which addresses are being retried into the ground? I want a suppression list."
"Set the daily send limit on this domain to 2,000."
```

---

## Troubleshooting

**`401` from the Mailcow API** — Either the key is wrong or the source IP isn't allow-listed. It's usually the IP, and it's the IP of *this machine*, not the mail server. A read-only key also returns 401 on write routes; `selftest.mjs` distinguishes these.

**`Cannot read SSH key at ~/.ssh/...`** — Use an absolute path. `~` expansion depends on `HOME`/`USERPROFILE` being set, which isn't guaranteed under a GUI-launched process.

**`Encrypted private OpenSSH key detected`** — The key has a passphrase. Either set `MAIL_SSH_KEY_PASSPHRASE` or generate a passphrase-free key for this purpose. ssh-agent doesn't help here.

**Tools show old behavior after an update** — `dist/` is what runs. Run `npm run build`, then fully restart the client. The tests import from `dist/`, so a passing test suite proves the build is current and points at the client process instead.

**`No running container matching "postfix-mailcow"`** — The SSH user can't reach Docker, or Mailcow isn't up. Check `docker ps` as that user.

**Quarantine tools return nothing** — Mailcow disables quarantine until you set *retentions per mailbox* and a *maximum size* under quarantine settings. Expected on a send-focused install.

---

## Testing

```bash
npm test                      # parser + classifier, then server boot and guard checks
node scripts/parser-test.mjs  # 26 cases, offline — includes verbatim rejection strings from live logs
node scripts/smoke-test.mjs   # boots over stdio, lists tools, verifies the confirm guards fire
node scripts/selftest.mjs     # live connectivity
```

The classifier tests carry real rejection strings from KPN, MailChannels, Cisco IronPort, Orange, Rackspace, Gmail, Comcast and Cloudflare. Each one was misclassified at some point; they're pinned so it stays fixed.

**Contributions welcome, and one kind especially:** if your MTA gets told something this classifier mishandles, open an issue with the raw rejection string. That's the highest-value contribution to this project and it costs you a copy-paste.

---

## Limitations

- Developed and tested against **one** Mailcow install (2026-07a). Container naming, log formats and API surface vary across versions.
- Log parsing assumes standard Postfix format from the `postfix-mailcow` container.
- **Complaint rate is invisible.** The recipient hitting "spam" never reaches your MTA. For volume sending, Google Postmaster Tools is mandatory alongside this — it measures the one threshold nothing here can see.
- The provider map covers major consumer mailbox providers; anything unmapped groups by domain.

## License

MIT
