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

The snippet is intentionally lightweight — it covers all the same data as the full plugin but does not include:

- WordPress core file integrity check (MD5 comparison against wordpress.org checksums)
- Plugin CVE lookup via WPScan API
- Settings admin page (configure via constants instead)
- 12-point performance checklist (snippet does basic memory/DB metrics only)
- REST API endpoint inventory
- URL visit tracking with page-type classification

For full coverage, install the plugin from the `wordpress-plugin/` directory.
