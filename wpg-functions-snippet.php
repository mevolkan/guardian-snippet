<?php
/**
 * ============================================================
 *  WordGuardHQ — functions.php snippet
 * ============================================================
 *  Drop this into your theme's functions.php if you cannot
 *  install the full plugin.  It covers:
 *    • PHP error log forwarding (buffered, hourly flush)
 *    • Uptime heartbeat (WP-Cron, every 5 min)
 *    • Basic security checks on each heartbeat
 *    • Performance metrics (memory, DB queries)
 *    • HTTP request logging (outgoing wp_remote_* calls)
 *    • WP Mail logging (sent / failed)
 *    • Login audit (success, failed, logout)
 *    • Cron / transient / DB-table snapshots (daily)
 *    • Traffic analytics (pageviews, unique visitors, online users)
 *    • Hook capture (top fired hooks, hourly flush)
 *    • Security events (critical option changes, user events, user enumeration blocking)
 *    • Server info (CPU load, disk usage)
 *    • SSL certificate expiry check
 *    • Security headers audit
 *    • Referrer stats (top referrer domains, daily)
 *    • Deprecated function / hook / doing_it_wrong logging
 *
 *  CONFIGURATION — edit the two lines below:
 */
define( 'WPG_SERVER_URL', 'https://your-server.example.com' ); // No trailing slash needed
define( 'WPG_API_KEY',    'wpg_your_api_key_here' );
/**
 * ============================================================
 */

// Guard: only run if both values are set
if (
    ! defined( 'WPG_SERVER_URL' ) ||
    ! defined( 'WPG_API_KEY' )   ||
    WPG_SERVER_URL === 'https://your-server.example.com'
) {
    return;
}

// ── Custom cron schedule ──────────────────────────────────────────────────────
add_filter( 'cron_schedules', function ( $schedules ) {
    if ( ! isset( $schedules['wpg_5min'] ) ) {
        $schedules['wpg_5min'] = [ 'interval' => 300, 'display' => 'Every 5 minutes (WordGuardHQ)' ];
    }
    return $schedules;
} );

// ── Schedule cron events on first load ────────────────────────────────────────
$wpg_crons = [
    'wpg_snippet_uptime'        => 'wpg_5min',
    'wpg_snippet_flush_logs'    => 'hourly',
    'wpg_snippet_flush_http'    => 'hourly',
    'wpg_snippet_flush_mail'    => 'hourly',
    'wpg_snippet_flush_logins'  => 'hourly',
    'wpg_snippet_flush_hooks'   => 'hourly',
    'wpg_snippet_flush_traffic' => 'hourly',
    'wpg_snippet_snapshot'      => 'daily',
    'wpg_snippet_security_checks' => 'daily',
];
foreach ( $wpg_crons as $hook => $schedule ) {
    if ( ! wp_next_scheduled( $hook ) ) {
        wp_schedule_event( time(), $schedule, $hook );
    }
}

// ── PHP error handler ─────────────────────────────────────────────────────────
set_error_handler( function ( $errno, $errstr, $errfile = '', $errline = 0 ) {
    static $map = [
        E_ERROR           => 'ERROR',   E_WARNING         => 'WARNING',
        E_NOTICE          => 'NOTICE',  E_USER_ERROR      => 'ERROR',
        E_USER_WARNING    => 'WARNING', E_USER_NOTICE     => 'NOTICE',
        E_DEPRECATED      => 'WARNING', E_USER_DEPRECATED => 'WARNING',
        E_PARSE           => 'ERROR',   E_RECOVERABLE_ERROR => 'ERROR',
    ];
    $level = $map[ $errno ] ?? 'INFO';

    $buffer   = get_transient( 'wpg_snippet_log_buffer' ) ?: [];
    $buffer[] = [
        'level'     => $level,
        'message'   => $errstr,
        'source'    => 'php',
        'context'   => [
            'file'  => str_replace( ABSPATH, '', $errfile ),
            'line'  => $errline,
        ],
        'timestamp' => gmdate( 'c' ),
    ];
    set_transient( 'wpg_snippet_log_buffer', $buffer, 2 * HOUR_IN_SECONDS );

    // Flush early if buffer is large
    if ( count( $buffer ) >= 50 ) {
        do_action( 'wpg_snippet_flush_logs' );
    }

    return false; // Let default handler run
}, E_ALL );

// ── Cron: flush logs ──────────────────────────────────────────────────────────
add_action( 'wpg_snippet_flush_logs', 'wpg_snippet_do_flush_logs' );
function wpg_snippet_do_flush_logs(): void {
    $buffer = get_transient( 'wpg_snippet_log_buffer' );
    if ( empty( $buffer ) ) return;

    delete_transient( 'wpg_snippet_log_buffer' );
    wpg_snippet_ingest( [
        'site_info' => [
            'wp_version'  => get_bloginfo( 'version' ),
            'php_version' => PHP_VERSION,
        ],
        'logs' => $buffer,
    ] );
}

// ── HTTP request logging ──────────────────────────────────────────────────────
// Record start time before each outgoing request.
add_filter( 'pre_http_request', function ( $preempt, array $args, string $url ) {
    $key = md5( $url . ( $args['method'] ?? 'GET' ) );
    set_transient( 'wpg_http_start_' . $key, microtime( true ), 60 );
    return $preempt;
}, 10, 3 );

// Capture result after each outgoing request.
add_action( 'http_api_debug', function ( $response, string $context, $class, array $args, string $url ) {
    if ( 'response' !== $context ) return;
    $server = trailingslashit( WPG_SERVER_URL );
    if ( strpos( $url, $server ) !== false ) return; // skip self

    $key   = md5( $url . ( $args['method'] ?? 'GET' ) );
    $start = get_transient( 'wpg_http_start_' . $key ) ?: microtime( true );
    delete_transient( 'wpg_http_start_' . $key );
    $ms = (int) round( ( microtime( true ) - $start ) * 1000 );

    $buffer   = get_transient( 'wpg_snippet_http_buffer' ) ?: [];
    if ( count( $buffer ) >= 500 ) return;
    $buffer[] = [
        'url'           => $url,
        'method'        => $args['method'] ?? 'GET',
        'type'          => ( strpos( $url, home_url() ) !== false ) ? 'internal' : 'external',
        'status_code'   => is_wp_error( $response ) ? null : (int) wp_remote_retrieve_response_code( $response ),
        'duration_ms'   => $ms,
        'is_error'      => is_wp_error( $response ),
        'error_message' => is_wp_error( $response ) ? $response->get_error_message() : null,
        'timestamp'     => gmdate( 'c' ),
    ];
    set_transient( 'wpg_snippet_http_buffer', $buffer, 2 * HOUR_IN_SECONDS );
    if ( count( $buffer ) >= 10 ) do_action( 'wpg_snippet_flush_http' );
}, 10, 5 );

add_action( 'wpg_snippet_flush_http', 'wpg_snippet_do_flush_http' );
function wpg_snippet_do_flush_http(): void {
    $buffer = get_transient( 'wpg_snippet_http_buffer' );
    if ( empty( $buffer ) ) return;
    delete_transient( 'wpg_snippet_http_buffer' );
    wpg_snippet_ingest( [ 'http_requests' => $buffer ] );
}

// ── WP Mail logging ───────────────────────────────────────────────────────────
add_filter( 'wp_mail', function ( array $args ) {
    $pending   = get_transient( 'wpg_snippet_mail_pending' ) ?: [];
    $pending[] = [
        'to'        => is_array( $args['to'] ) ? implode( ',', $args['to'] ) : $args['to'],
        'subject'   => $args['subject'] ?? '',
        'status'    => 'sent',
        'timestamp' => gmdate( 'c' ),
    ];
    set_transient( 'wpg_snippet_mail_pending', $pending, HOUR_IN_SECONDS );
    return $args;
}, PHP_INT_MAX );

add_action( 'wp_mail_failed', function ( $error ) {
    $pending = get_transient( 'wpg_snippet_mail_pending' ) ?: [];
    if ( ! empty( $pending ) ) {
        $last           = array_pop( $pending );
        $last['status'] = 'failed';
        $last['error']  = $error instanceof WP_Error ? $error->get_error_message() : (string) $error;
        $pending[]      = $last;
        set_transient( 'wpg_snippet_mail_pending', $pending, HOUR_IN_SECONDS );
    }
}, PHP_INT_MAX );

add_action( 'wpg_snippet_flush_mail', 'wpg_snippet_do_flush_mail' );
add_action( 'shutdown', function () {
    $buf = get_transient( 'wpg_snippet_mail_pending' );
    if ( ! empty( $buf ) ) wpg_snippet_do_flush_mail();
} );
function wpg_snippet_do_flush_mail(): void {
    $buffer = get_transient( 'wpg_snippet_mail_pending' );
    if ( empty( $buffer ) ) return;
    delete_transient( 'wpg_snippet_mail_pending' );
    wpg_snippet_ingest( [ 'mail_logs' => $buffer ] );
}

// ── Login audit ───────────────────────────────────────────────────────────────
function wpg_snippet_buffer_login_event( string $type, string $username, $user = null ): void {
    $buffer   = get_transient( 'wpg_snippet_login_buffer' ) ?: [];
    $buffer[] = [
        'event_type' => $type,
        'username'   => $username,
        'user_id'    => ( $user instanceof WP_User ) ? $user->ID : null,
        'ip'         => sanitize_text_field( $_SERVER['REMOTE_ADDR'] ?? '' ),
        'user_agent' => substr( sanitize_text_field( $_SERVER['HTTP_USER_AGENT'] ?? '' ), 0, 255 ),
        'timestamp'  => gmdate( 'c' ),
    ];
    set_transient( 'wpg_snippet_login_buffer', $buffer, 2 * HOUR_IN_SECONDS );
    if ( count( $buffer ) >= 5 ) do_action( 'wpg_snippet_flush_logins' );
}
add_action( 'wp_login',        function ( $login, $user ) { wpg_snippet_buffer_login_event( 'login_success', $login, $user ); }, 10, 2 );
add_action( 'wp_login_failed', function ( $login )        { wpg_snippet_buffer_login_event( 'login_failed',  $login ); } );
add_action( 'wp_logout',       function ()                { wpg_snippet_buffer_login_event( 'logout', wp_get_current_user()->user_login ?? '' ); } );
add_action( 'password_reset',  function ( $user )         { wpg_snippet_buffer_login_event( 'password_reset', $user->user_login, $user ); } );

add_action( 'wpg_snippet_flush_logins', 'wpg_snippet_do_flush_logins' );
add_action( 'shutdown', function () {
    $buf = get_transient( 'wpg_snippet_login_buffer' );
    if ( ! empty( $buf ) ) wpg_snippet_do_flush_logins();
} );
function wpg_snippet_do_flush_logins(): void {
    $buffer = get_transient( 'wpg_snippet_login_buffer' );
    if ( empty( $buffer ) ) return;
    delete_transient( 'wpg_snippet_login_buffer' );
    wpg_snippet_ingest( [ 'login_events' => $buffer ] );
}

// ── User enumeration blocking ─────────────────────────────────────────────────
add_action( 'template_redirect', function () {
    if ( is_admin() ) return;
    if ( isset( $_GET['author'] ) && is_numeric( $_GET['author'] ) ) {
        $user_id = (int) $_GET['author'];
        if ( get_userdata( $user_id ) ) {
            $buffer   = get_transient( 'wpg_snippet_sec_buffer' ) ?: [];
            $buffer[] = [
                'event_type'  => 'user_enumeration_attempt',
                'description' => "User enumeration attempt via ?author={$user_id}",
                'severity'    => 'warning',
                'details'     => [ 'probed_user_id' => $user_id, 'ip' => sanitize_text_field( $_SERVER['REMOTE_ADDR'] ?? '' ) ],
                'timestamp'   => gmdate( 'c' ),
            ];
            set_transient( 'wpg_snippet_sec_buffer', $buffer, 2 * HOUR_IN_SECONDS );
        }
        wp_redirect( home_url( '/' ), 301 );
        exit;
    }
}, 1 );

// ── Deprecated function / hook / doing_it_wrong logging ──────────────────────
add_action( 'doing_it_wrong_run', function ( $function, $message, $version ) {
    if ( ! ( defined( 'WPG_CAPTURE_DOING_IT_WRONG' ) && WPG_CAPTURE_DOING_IT_WRONG ) ) return;
    $buffer   = get_transient( 'wpg_snippet_log_buffer' ) ?: [];
    $buffer[] = [
        'level'     => 'WARNING',
        'message'   => "doing_it_wrong: {$function}() — {$message}",
        'source'    => 'wordpress',
        'context'   => [ 'function' => $function, 'version' => $version ],
        'timestamp' => gmdate( 'c' ),
    ];
    set_transient( 'wpg_snippet_log_buffer', $buffer, 2 * HOUR_IN_SECONDS );
}, 10, 3 );
add_action( 'deprecated_function_run', function ( $function, $replacement, $version ) {
    $buffer   = get_transient( 'wpg_snippet_log_buffer' ) ?: [];
    $buffer[] = [
        'level'     => 'DEPRECATED',
        'message'   => "Deprecated function: {$function}()" . ( $replacement ? " — use {$replacement}() instead" : '' ),
        'source'    => 'wordpress',
        'context'   => [ 'function' => $function, 'replacement' => $replacement, 'version' => $version ],
        'timestamp' => gmdate( 'c' ),
    ];
    set_transient( 'wpg_snippet_log_buffer', $buffer, 2 * HOUR_IN_SECONDS );
}, 10, 3 );
add_action( 'deprecated_hook_run', function ( $hook, $replacement, $version, $message ) {
    $buffer   = get_transient( 'wpg_snippet_log_buffer' ) ?: [];
    $buffer[] = [
        'level'     => 'DEPRECATED',
        'message'   => "Deprecated hook: {$hook}" . ( $replacement ? " — use {$replacement} instead" : '' ),
        'source'    => 'wordpress',
        'context'   => [ 'hook' => $hook, 'replacement' => $replacement, 'version' => $version ],
        'timestamp' => gmdate( 'c' ),
    ];
    set_transient( 'wpg_snippet_log_buffer', $buffer, 2 * HOUR_IN_SECONDS );
}, 10, 4 );

// ── Security events (critical option changes + user events) ───────────────────
$wpg_watched_options = [ 'active_plugins', 'blogname', 'admin_email', 'users_can_register', 'default_role', 'siteurl', 'home' ];
add_action( 'updated_option', function ( string $option ) use ( $wpg_watched_options ) {
    if ( ! in_array( $option, $wpg_watched_options, true ) ) return;
    $user    = wp_get_current_user();
    $login   = $user->user_login ?? 'unknown';
    $buffer  = get_transient( 'wpg_snippet_sec_buffer' ) ?: [];
    $buffer[] = [
        'event_type'  => 'option_change',
        'description' => "Option '{$option}' changed by {$login}",
        'severity'    => 'critical',
        'details'     => [ 'option' => $option, 'user' => $login ],
        'timestamp'   => gmdate( 'c' ),
    ];
    set_transient( 'wpg_snippet_sec_buffer', $buffer, 2 * HOUR_IN_SECONDS );
} );
add_action( 'user_register', function ( int $user_id ) {
    $user    = get_userdata( $user_id );
    $buffer  = get_transient( 'wpg_snippet_sec_buffer' ) ?: [];
    $buffer[] = [
        'event_type'  => 'user_register',
        'description' => 'New user registered: ' . ( $user->user_login ?? $user_id ),
        'severity'    => 'warning',
        'details'     => [ 'user_id' => $user_id ],
        'timestamp'   => gmdate( 'c' ),
    ];
    set_transient( 'wpg_snippet_sec_buffer', $buffer, 2 * HOUR_IN_SECONDS );
} );
add_action( 'delete_user', function ( int $user_id ) {
    $user    = get_userdata( $user_id );
    $buffer  = get_transient( 'wpg_snippet_sec_buffer' ) ?: [];
    $buffer[] = [
        'event_type'  => 'user_delete',
        'description' => 'User deleted: ' . ( $user ? $user->user_login : $user_id ),
        'severity'    => 'warning',
        'details'     => [ 'user_id' => $user_id ],
        'timestamp'   => gmdate( 'c' ),
    ];
    set_transient( 'wpg_snippet_sec_buffer', $buffer, 2 * HOUR_IN_SECONDS );
} );
add_action( 'set_user_role', function ( int $user_id, string $role ) {
    $user    = get_userdata( $user_id );
    $buffer  = get_transient( 'wpg_snippet_sec_buffer' ) ?: [];
    $buffer[] = [
        'event_type'  => 'role_change',
        'description' => 'Role changed to ' . $role . ' for ' . ( $user ? $user->user_login : $user_id ),
        'severity'    => 'critical',
        'details'     => [ 'user_id' => $user_id, 'new_role' => $role ],
        'timestamp'   => gmdate( 'c' ),
    ];
    set_transient( 'wpg_snippet_sec_buffer', $buffer, 2 * HOUR_IN_SECONDS );
}, 10, 2 );
add_action( 'shutdown', function () {
    $buf = get_transient( 'wpg_snippet_sec_buffer' );
    if ( ! empty( $buf ) ) {
        delete_transient( 'wpg_snippet_sec_buffer' );
        wpg_snippet_ingest( [ 'security_events' => $buf ] );
    }
} );

// ── Hook capture (tracks top hooks fired during a request) ────────────────────
$wpg_hook_counts = [];
add_action( 'all', function ( string $tag ) use ( &$wpg_hook_counts ) {
    if ( count( $wpg_hook_counts ) >= 200 ) return;
    $wpg_hook_counts[ $tag ] = ( $wpg_hook_counts[ $tag ] ?? 0 ) + 1;
} );
add_action( 'wpg_snippet_flush_hooks', 'wpg_snippet_do_flush_hooks' );
add_action( 'shutdown', 'wpg_snippet_do_flush_hooks' );
function wpg_snippet_do_flush_hooks(): void {
    global $wpg_hook_counts;
    if ( empty( $wpg_hook_counts ) ) return;
    $events = [];
    foreach ( $wpg_hook_counts as $hook => $count ) {
        $events[] = [ 'hook_name' => $hook, 'fire_count' => $count, 'timestamp' => gmdate( 'c' ) ];
    }
    $wpg_hook_counts = [];
    wpg_snippet_ingest( [ 'hook_events' => $events ] );
}

// ── Traffic analytics ─────────────────────────────────────────────────────────
function wpg_snippet_is_bot( string $ua ): bool {
    if ( empty( $ua ) ) return true;
    $bots = [ 'bot', 'crawl', 'slurp', 'spider', 'mediapartners', 'ia_archiver', 'semrush', 'ahrefs', 'mj12bot' ];
    $ua_lower = strtolower( $ua );
    foreach ( $bots as $fragment ) {
        if ( strpos( $ua_lower, $fragment ) !== false ) return true;
    }
    return false;
}

add_action( 'wp', function () {
    if ( is_admin() || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) return;
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if ( wpg_snippet_is_bot( $ua ) ) return;

    // Pageviews
    $pv = (int) get_transient( 'wpg_pv_today' );
    set_transient( 'wpg_pv_today', $pv + 1, DAY_IN_SECONDS );

    // Unique visitors (by IP, stored as a set)
    $ip      = sanitize_text_field( $_SERVER['REMOTE_ADDR'] ?? 'unknown' );
    $ip_key  = 'wpg_ip_' . md5( $ip );
    $visitors = (int) get_transient( 'wpg_visitors_today' );
    if ( ! get_transient( $ip_key . '_today' ) ) {
        set_transient( $ip_key . '_today', 1, DAY_IN_SECONDS );
        set_transient( 'wpg_visitors_today', $visitors + 1, DAY_IN_SECONDS );
    }

    // Online now (30 min window per IP)
    $online_key = 'wpg_online_' . md5( $ip );
    $was_online = get_transient( $online_key );
    set_transient( $online_key, 1, 30 * MINUTE_IN_SECONDS );
    if ( ! $was_online ) {
        $online = (int) get_transient( 'wpg_online_count' );
        set_transient( 'wpg_online_count', $online + 1, 30 * MINUTE_IN_SECONDS );
    }
} );

// Record referrer domain counts
add_action( 'template_redirect', function () {
    if ( is_admin() || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) return;
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if ( wpg_snippet_is_bot( $ua ) ) return;

    $referer = isset( $_SERVER['HTTP_REFERER'] ) ? esc_url_raw( $_SERVER['HTTP_REFERER'] ) : '';
    if ( empty( $referer ) ) return;

    $parsed = parse_url( $referer );
    $domain = ! empty( $parsed['host'] ) ? strtolower( $parsed['host'] ) : '';
    $domain = preg_replace( '/^www\./', '', $domain );
    $self   = preg_replace( '/^www\./', '', strtolower( parse_url( home_url(), PHP_URL_HOST ) ) );
    if ( empty( $domain ) || $domain === $self ) return;

    $data            = get_transient( 'wpg_referrer_today' ) ?: [];
    $data[ $domain ] = ( $data[ $domain ] ?? 0 ) + 1;
    arsort( $data );
    $data = array_slice( $data, 0, 50, true );
    set_transient( 'wpg_referrer_today', $data, DAY_IN_SECONDS );
} );

add_action( 'wpg_snippet_flush_traffic', 'wpg_snippet_do_flush_traffic' );
function wpg_snippet_do_flush_traffic(): void {
    $payload = [
        'traffic' => [
            'pageviews_today' => (int) get_transient( 'wpg_pv_today' ),
            'visitors_today'  => (int) get_transient( 'wpg_visitors_today' ),
            'online_now'      => (int) get_transient( 'wpg_online_count' ),
        ],
    ];
    $referrer_data = get_transient( 'wpg_referrer_today' );
    if ( is_array( $referrer_data ) && ! empty( $referrer_data ) ) {
        $payload['traffic']['referrer_stats'] = array_map(
            fn( $domain, $count ) => [ 'domain' => $domain, 'count' => $count ],
            array_keys( $referrer_data ),
            $referrer_data
        );
        delete_transient( 'wpg_referrer_today' );
    }
    wpg_snippet_ingest( $payload );
}

// ── Daily snapshot (crons, transients, DB tables) ─────────────────────────────
add_action( 'wpg_snippet_snapshot', 'wpg_snippet_do_snapshot' );
function wpg_snippet_do_snapshot(): void {
    global $wpdb;

    // ── Cron snapshot ─────────────────────────────────────────────────────────
    $cron_array   = _get_cron_array() ?: [];
    $cron_total   = 0; $cron_core = 0; $cron_custom = 0; $cron_no_cb = 0; $hook_names = [];
    foreach ( $cron_array as $hooks ) {
        foreach ( $hooks as $hook => $events ) {
            foreach ( $events as $event ) {
                $cron_total++;
                if ( str_starts_with( $hook, 'wp_' ) ) { $cron_core++; } else { $cron_custom++; }
                if ( ! has_action( $hook ) ) $cron_no_cb++;
                $hook_names[] = $hook;
            }
        }
    }

    // ── Transient snapshot ────────────────────────────────────────────────────
    $all_transients = (int) $wpdb->get_var(
        "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '_transient_%' AND option_name NOT LIKE '_transient_timeout_%'"
    );
    $expired = (int) $wpdb->get_var( $wpdb->prepare(
        "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_%' AND option_value < %d",
        time()
    ) );
    $core_transients = (int) $wpdb->get_var(
        "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name REGEXP '^_transient_(wp_|wc_|pll_)'"
    );

    // ── DB tables snapshot ────────────────────────────────────────────────────
    $tables      = $wpdb->get_results( 'SHOW TABLE STATUS', ARRAY_A ) ?: [];
    $total_bytes = 0;
    foreach ( $tables as $t ) {
        $total_bytes += (int) $t['Data_length'] + (int) $t['Index_length'];
    }

    wpg_snippet_ingest( [
        'cron_snapshot' => [
            'total'       => $cron_total,
            'wp_core'     => $cron_core,
            'custom'      => $cron_custom,
            'no_callback' => $cron_no_cb,
            'hooks'       => array_values( array_unique( $hook_names ) ),
        ],
        'transient_snapshot' => [
            'total'   => $all_transients,
            'wp_core' => $core_transients,
            'custom'  => max( 0, $all_transients - $core_transients ),
            'expired' => $expired,
        ],
        'db_tables_snapshot' => [
            'total_tables'  => count( $tables ),
            'total_size_mb' => round( $total_bytes / 1048576, 2 ),
        ],
    ] );
}

// ── Cron: uptime ping + metrics ───────────────────────────────────────────────
add_action( 'wpg_snippet_uptime', 'wpg_snippet_do_uptime' );
function wpg_snippet_do_uptime(): void {
    $start    = microtime( true );
    $response = wp_remote_get( home_url( '/' ), [
        'timeout'    => 10,
        'user-agent' => 'WordGuardHQ-Snippet/1.0',
    ] );
    $ms = (int) round( ( microtime( true ) - $start ) * 1000 );

    if ( is_wp_error( $response ) ) {
        $uptime = [ 'status' => 'down', 'error_message' => $response->get_error_message(), 'response_time_ms' => $ms ];
    } else {
        $code   = (int) wp_remote_retrieve_response_code( $response );
        $status = ( $code >= 500 ) ? 'down' : ( ( $code >= 400 || $ms > 5000 ) ? 'degraded' : 'up' );
        $uptime = [ 'status' => $status, 'http_status_code' => $code, 'response_time_ms' => $ms ];
    }

    // Quick security checks
    $vulns = wpg_snippet_quick_security_check();

    // Performance metrics
    $metrics = [
        [ 'metric_type' => 'memory_usage', 'value' => round( memory_get_usage(true) / 1048576, 2 ), 'unit' => 'MB' ],
        [ 'metric_type' => 'memory_peak',  'value' => round( memory_get_peak_usage(true) / 1048576, 2 ), 'unit' => 'MB' ],
    ];
    global $wpdb;
    if ( isset( $wpdb->num_queries ) ) {
        $metrics[] = [ 'metric_type' => 'db_query_count', 'value' => (float) $wpdb->num_queries, 'unit' => 'count' ];
    }

    // Server info (CPU + disk)
    $server_info = [];
    if ( is_readable( '/proc/loadavg' ) ) {
        $parts = explode( ' ', file_get_contents( '/proc/loadavg' ) );
        $server_info['cpu_load_1min'] = isset( $parts[0] ) ? (float) $parts[0] : null;
    }
    $disk_total = @disk_total_space( '/' );
    $disk_free  = @disk_free_space( '/' );
    if ( $disk_total && $disk_free ) {
        $server_info['disk_total_gb'] = round( $disk_total / 1073741824, 2 );
        $server_info['disk_free_gb']  = round( $disk_free  / 1073741824, 2 );
        $server_info['disk_used_pct'] = round( ( $disk_total - $disk_free ) / $disk_total * 100, 1 );
    }

    wpg_snippet_ingest( [
        'site_info'       => [ 'wp_version' => get_bloginfo('version'), 'php_version' => PHP_VERSION ],
        'uptime'          => $uptime,
        'vulnerabilities' => $vulns,
        'metrics'         => $metrics,
        'server_info'     => ! empty( $server_info ) ? $server_info : null,
    ] );
}

// ── Quick security check ──────────────────────────────────────────────────────
function wpg_snippet_quick_security_check(): array {
    $vulns = [];

    // WP_DEBUG in production
    if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
        $vulns[] = [
            'vuln_type' => 'weak_config', 'severity' => 'medium',
            'title'     => 'WP_DEBUG is enabled',
            'description' => 'Disable WP_DEBUG on production sites.',
            'affected_component' => 'wp-config.php',
        ];
    }

    // File editor enabled
    if ( ! defined( 'DISALLOW_FILE_EDIT' ) || ! DISALLOW_FILE_EDIT ) {
        $vulns[] = [
            'vuln_type' => 'weak_config', 'severity' => 'medium',
            'title'     => 'Theme/plugin file editor is enabled',
            'description' => 'Add define("DISALLOW_FILE_EDIT", true) to wp-config.php.',
            'affected_component' => 'wp-config.php',
        ];
    }

    // Default admin user
    if ( username_exists( 'admin' ) ) {
        $vulns[] = [
            'vuln_type' => 'weak_config', 'severity' => 'high',
            'title'     => 'Default "admin" username exists',
            'description' => 'Rename or delete the default admin account.',
            'affected_component' => 'users',
        ];
    }

    // PHP version
    if ( version_compare( PHP_VERSION, '8.1', '<' ) ) {
        $vulns[] = [
            'vuln_type'          => 'outdated_runtime',
            'severity'           => version_compare( PHP_VERSION, '7.4', '<' ) ? 'high' : 'medium',
            'title'              => 'PHP ' . PHP_VERSION . ' is outdated',
            'description'        => 'Upgrade to PHP 8.1+.',
            'affected_component' => 'php',
            'affected_version'   => PHP_VERSION,
        ];
    }

    // Outdated plugins
    $update = get_site_transient( 'update_plugins' );
    if ( $update && ! empty( $update->response ) ) {
        foreach ( $update->response as $slug => $data ) {
            if ( ! function_exists( 'get_plugin_data' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            $plugin_file = WP_PLUGIN_DIR . '/' . $slug;
            if ( file_exists( $plugin_file ) ) {
                $info = get_plugin_data( $plugin_file, false, false );
                $vulns[] = [
                    'vuln_type'          => 'outdated_plugin',
                    'severity'           => 'medium',
                    'title'              => 'Plugin outdated: ' . ( $info['Name'] ?? $slug ),
                    'description'        => "Update available: {$data->new_version}",
                    'affected_component' => $info['Name'] ?? $slug,
                    'affected_version'   => $info['Version'] ?? '',
                ];
            }
        }
    }

    return $vulns;
}

// ── Daily security checks (SSL expiry + security headers) ────────────────────
add_action( 'wpg_snippet_security_checks', 'wpg_snippet_do_security_checks' );
function wpg_snippet_do_security_checks(): void {
    $checks = [];

    // SSL certificate expiry
    $ssl_status = 'warning';
    $ssl_value  = 'Could not verify SSL certificate';
    if ( is_ssl() || strpos( home_url(), 'https' ) === 0 ) {
        $host    = parse_url( home_url(), PHP_URL_HOST );
        $context = stream_context_create( [ 'ssl' => [
            'capture_peer_cert' => true,
            'verify_peer'       => true,
            'verify_peer_name'  => true,
        ] ] );
        $stream = @stream_socket_client( "ssl://{$host}:443", $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $context );
        if ( $stream ) {
            $params = stream_context_get_params( $stream );
            $cert   = openssl_x509_parse( $params['options']['ssl']['peer_certificate'] );
            fclose( $stream );
            if ( ! empty( $cert['validTo_time_t'] ) ) {
                $days = (int) ( ( $cert['validTo_time_t'] - time() ) / DAY_IN_SECONDS );
                if ( $days > 30 ) {
                    $ssl_status = 'pass';
                    $ssl_value  = "Expires in {$days} days (" . date( 'Y-m-d', $cert['validTo_time_t'] ) . ')';
                } elseif ( $days > 7 ) {
                    $ssl_status = 'warning';
                    $ssl_value  = "Expires in {$days} days — renew soon";
                } else {
                    $ssl_status = 'fail';
                    $ssl_value  = $days > 0 ? "Expires in {$days} day(s) — URGENT" : 'Certificate has expired!';
                }
            }
        } elseif ( $errstr ) {
            $ssl_status = 'fail';
            $ssl_value  = "SSL error: {$errstr}";
        }
    } else {
        $ssl_status = 'warning';
        $ssl_value  = 'Site not using HTTPS — certificate check skipped';
    }
    $checks[] = [
        'id'             => 'ssl_expiry',
        'title'          => 'SSL Certificate Expiry',
        'status'         => $ssl_status,
        'value'          => $ssl_value,
        'recommendation' => 'Renew your SSL certificate before it expires.',
        'score'          => 9,
    ];

    // Security headers
    $head_resp = wp_remote_head( home_url( '/' ), [ 'timeout' => 8 ] );
    $head_status  = 'warning';
    $head_value   = 'Could not fetch response headers';
    $missing      = [];
    if ( ! is_wp_error( $head_resp ) ) {
        $resp_headers = wp_remote_retrieve_headers( $head_resp );
        foreach ( [
            'x-frame-options'        => 'X-Frame-Options',
            'x-content-type-options' => 'X-Content-Type-Options',
            'referrer-policy'        => 'Referrer-Policy',
            'permissions-policy'     => 'Permissions-Policy',
        ] as $key => $label ) {
            if ( empty( $resp_headers[ $key ] ) ) $missing[] = $label;
        }
        if ( empty( $resp_headers['content-security-policy'] ) ) $missing[] = 'Content-Security-Policy';
        if ( empty( $missing ) ) {
            $head_status = 'pass';
            $head_value  = 'All required security headers present';
        } elseif ( count( $missing ) <= 2 ) {
            $head_status = 'warning';
            $head_value  = 'Missing: ' . implode( ', ', $missing );
        } else {
            $head_status = 'fail';
            $head_value  = 'Missing ' . count( $missing ) . ' headers: ' . implode( ', ', $missing );
        }
    }
    $checks[] = [
        'id'             => 'security_headers',
        'title'          => 'Security Headers',
        'status'         => $head_status,
        'value'          => $head_value,
        'recommendation' => 'Add X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Content-Security-Policy, and Permissions-Policy headers.',
        'score'          => 7,
    ];

    wpg_snippet_ingest( [ 'security_checks' => $checks ] );
}

// ── HTTP helper ───────────────────────────────────────────────────────────────
function wpg_snippet_ingest( array $payload ): bool {
    $url      = trailingslashit( WPG_SERVER_URL ) . 'api/v1/ingest/';
    $response = wp_remote_post( $url, [
        'timeout'     => 15,
        'headers'     => [
            'Content-Type' => 'application/json',
            'X-API-Key'    => WPG_API_KEY,
        ],
        'body'        => wp_json_encode( $payload ),
        'data_format' => 'body',
    ] );

    if ( is_wp_error( $response ) ) {
        error_log( '[WordGuardHQ snippet] ' . $response->get_error_message() );
        return false;
    }
    return true;
}
