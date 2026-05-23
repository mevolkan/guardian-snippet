<?php
/**
 * ============================================================
 *  WP Guardian — functions.php snippet
 * ============================================================
 *  Drop this into your theme's functions.php if you cannot
 *  install the full plugin.  It covers:
 *    • PHP error log forwarding (buffered, hourly flush)
 *    • Uptime heartbeat (WP-Cron, every 5 min)
 *    • Basic security checks on each heartbeat
 *    • Performance metrics (memory, DB queries)
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
        $schedules['wpg_5min'] = [ 'interval' => 300, 'display' => 'Every 5 minutes (WP Guardian)' ];
    }
    return $schedules;
} );

// ── Schedule cron events on first load ────────────────────────────────────────
if ( ! wp_next_scheduled( 'wpg_snippet_uptime' ) ) {
    wp_schedule_event( time(), 'wpg_5min', 'wpg_snippet_uptime' );
}
if ( ! wp_next_scheduled( 'wpg_snippet_flush_logs' ) ) {
    wp_schedule_event( time(), 'hourly', 'wpg_snippet_flush_logs' );
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

// ── Cron: uptime ping + metrics ───────────────────────────────────────────────
add_action( 'wpg_snippet_uptime', 'wpg_snippet_do_uptime' );
function wpg_snippet_do_uptime(): void {
    $start    = microtime( true );
    $response = wp_remote_get( home_url( '/' ), [
        'timeout'    => 10,
        'user-agent' => 'WPGuardian-Snippet/1.0',
        'sslverify'  => false,
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

    wpg_snippet_ingest( [
        'site_info'       => [ 'wp_version' => get_bloginfo('version'), 'php_version' => PHP_VERSION ],
        'uptime'          => $uptime,
        'vulnerabilities' => $vulns,
        'metrics'         => $metrics,
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
        error_log( '[WP Guardian snippet] ' . $response->get_error_message() );
        return false;
    }
    return true;
}
