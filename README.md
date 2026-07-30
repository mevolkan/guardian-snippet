# WordGuardHQ — functions.php Snippet

A single-file alternative to the full WordGuardHQ plugin. Drop it into your theme's `functions.php` when you cannot install plugins (managed hosts, theme-only deployments).

## Setup

1. Open `wpg-functions-snippet.php` and edit the two constants at the top:

```php
define( 'WPG_SERVER_URL', 'https://api.yourdomain.com' );
define( 'WPG_API_KEY',    'wpg_your_api_key_here' );
```

2. Paste the entire file contents into your child theme's `functions.php`, or use a code snippets plugin.

3. Your API key is shown on the site detail page in the WordGuardHQ dashboard.

## What it collects

| Feature | Schedule |
|---|---|
| Uptime heartbeat + performance metrics | Every 5 min (WP-Cron) |
| PHP errors, warnings, notices | Buffered, flush hourly or at 50 entries |
| Deprecated function / hook / `doing_it_wrong` | Buffered with logs |
| HTTP request log (outgoing `wp_remote_*` calls) | Buffered, flush hourly |
| WP Mail log (sent / failed) | Flush on shutdown |
| Login audit (success, failed, logout, password reset) | Flush on shutdown |
| Security events (option changes, user register/delete/role change) | Flush on shutdown |
| User enumeration blocking (`?author=N` probes) | On request, event logged + 301 redirect |
| Hook capture (top hooks fired per request) | Flush hourly + shutdown |
| Traffic analytics (pageviews, visitors, online now) | Buffered per request |
| Referrer stats (top 50 domains per day) | Flush hourly |
| SSL certificate expiry check | Daily |
| Security headers audit | Daily |
| Cron / transient / DB-table snapshots | Daily |

## Optional: `doing_it_wrong` logging

`doing_it_wrong` notices can be noisy on sites with older plugins. Opt in explicitly:

```php
define( 'WPG_CAPTURE_DOING_IT_WRONG', true );
```

## Differences from the full plugin

The snippet is intentionally lightweight. It sends **16 of the 23** telemetry types the full plugin
sends. Choosing it means giving up:

| Not collected | Plugin payload key |
|---|---|
| WordPress core file integrity (checksum comparison against wordpress.org) | `core_integrity` |
| Plugin CVE lookup via WPScan API | `plugin_cve_scan` |
| Dedicated fatal-error capture (with backtrace, dedup hash, repeat count) | `fatal_errors` |
| 12-point performance checklist (the snippet does basic memory/DB metrics only) | `performance_checks` |
| REST API endpoint inventory | `rest_api_snapshot` |
| REST API error buffer | `rest_api_errors` |
| URL visit tracking with page-type classification | `url_visits` |

It also has no settings admin page — configure via the constants above.

Everything else is byte-identical in intent: both post to the same `POST /api/v1/ingest/` and both
send only keys the server's `IngestPayload` schema declares.

For full coverage, install the plugin from the `wordpress-plugin/` directory.

## ⚠️ The snippet cannot be used with signed ingest

The full plugin signs every request with `X-Timestamp` / `X-Nonce` / `X-Signature`
(HMAC-SHA256 over `"{timestamp}\n{nonce}\n" + body`, keyed by the API key). **The snippet sends only
`X-API-Key`** and relies on the server's legacy unsigned path.

That path is gated by the backend's `INGEST_ENFORCE_SIGNATURE` setting (default `false`):

| `INGEST_ENFORCE_SIGNATURE` | Plugin | Snippet |
|---|---|---|
| `false` (default) | works | works |
| `true` | works | **401 — every request rejected** |

So turning signature enforcement on is a breaking change for every snippet install. If you plan to
enable it, migrate those sites to the plugin first. Both behaviours are covered by
`backend/tests/test_wp_plugin_contract.py`, so this cannot regress silently.
