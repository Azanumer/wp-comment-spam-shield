<?php
/**
 * Plugin Name: Comment Spam Shield
 * Description: Dependency-free comment spam protection for WordPress — honeypot field, timing trap, JavaScript challenge, URL limits and disposable-email blocking. No API keys, no external services.
 * Version: 1.0.0
 * Author: Azan Umer
 * License: MIT
 * Text Domain: css
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'CSS_OPTION', 'css_settings' );

class CommentSpamShield {

    /**
     * Default settings. Everything is filterable at runtime via
     * the `css_setting` filter if you prefer code over the UI.
     */
    public static function defaults() {
        return array(
            'min_seconds'    => 5,    // form must take at least this long to submit
            'max_urls'       => 2,    // more URLs than this = spam
            'require_js'     => 1,    // require the JavaScript challenge token
            'block_disposable' => 1,  // block known disposable email domains
            'log_blocks'     => 1,    // keep a count of blocked attempts
        );
    }

    public static function setting( $key ) {
        $settings = get_option( CSS_OPTION, array() );
        $settings = wp_parse_args( $settings, self::defaults() );
        return apply_filters( 'css_setting', isset( $settings[ $key ] ) ? $settings[ $key ] : null, $key );
    }

    /** A per-site secret used to sign the JS challenge token. */
    public static function salt() {
        $salt = get_option( 'css_challenge_salt', '' );
        if ( $salt === '' ) {
            $salt = wp_generate_password( 32, false );
            add_option( 'css_challenge_salt', $salt, '', 'no' );
        }
        return $salt;
    }

    public static function init() {
        add_action( 'comment_form', array( __CLASS__, 'render_fields' ) );
        add_filter( 'preprocess_comment', array( __CLASS__, 'check_comment' ), 1 );
        add_action( 'admin_menu', array( __CLASS__, 'admin_menu' ) );
        add_action( 'admin_init', array( __CLASS__, 'register_settings' ) );
    }

    /**
     * Render the honeypot, timestamp and JS-challenge fields.
     * The honeypot is hidden with CSS (real browsers never fill it;
     * bots that auto-fill every input do).
     */
    public static function render_fields() {
        $ts    = time();
        $token = hash_hmac( 'sha256', (string) $ts, self::salt() );
        ?>
        <p class="css-hp-wrap" style="position:absolute;left:-9999px;top:auto;width:1px;height:1px;overflow:hidden;" aria-hidden="true" tabindex="-1">
            <label>Leave this empty <input type="text" name="css_hp" value="" autocomplete="off" /></label>
        </p>
        <input type="hidden" name="css_ts" value="<?php echo esc_attr( $ts ); ?>" />
        <input type="hidden" name="css_js" id="css_js" value="" data-token="<?php echo esc_attr( $token ); ?>" />
        <script>
        (function () {
            // Real browsers run JS and copy the signed token over; dumb bots never do.
            var el = document.getElementById('css_js');
            if (el && el.getAttribute('data-token')) {
                el.value = el.getAttribute('data-token');
            }
        })();
        </script>
        <?php
    }

    /** Reject spammy comments before WordPress saves them. */
    public static function check_comment( $commentdata ) {
        $reason = self::spam_reason();
        if ( $reason !== '' ) {
            self::log_block( $reason );
            wp_die(
                esc_html__( 'Your comment was flagged as spam.', 'css' ) .
                ' (' . esc_html( $reason ) . ')',
                esc_html__( 'Spam detected', 'css' ),
                array( 'response' => 403, 'back_link' => true )
            );
        }
        return $commentdata;
    }

    /** Return a spam reason string, or '' when the comment looks human. */
    public static function spam_reason() {
        // 1. Honeypot filled -> definitely a bot.
        if ( ! empty( $_POST['css_hp'] ) ) {
            return 'honeypot';
        }

        $ts = isset( $_POST['css_ts'] ) ? (int) $_POST['css_ts'] : 0;

        // 2. Timing trap: submitted too fast to be human.
        $min = (int) self::setting( 'min_seconds' );
        if ( $ts <= 0 || time() - $ts < $min ) {
            return 'too-fast';
        }
        // Render timestamp in the future -> clock games, treat as bot.
        if ( $ts > time() + 300 ) {
            return 'bad-timestamp';
        }

        // 3. JavaScript challenge: token must match the HMAC of the timestamp.
        if ( (int) self::setting( 'require_js' ) ) {
            $expected = hash_hmac( 'sha256', (string) $ts, self::salt() );
            if ( ! isset( $_POST['css_js'] ) || ! hash_equals( $expected, (string) $_POST['css_js'] ) ) {
                return 'js-challenge';
            }
        }

        // 4. Too many URLs in the comment body.
        $content = isset( $_POST['comment'] ) ? (string) $_POST['comment'] : '';
        $max     = (int) self::setting( 'max_urls' );
        if ( $max >= 0 && preg_match_all( '#https?://#i', $content, $m ) > $max ) {
            return 'too-many-urls';
        }

        // 5. Disposable email domains.
        if ( (int) self::setting( 'block_disposable' ) && ! empty( $_POST['email'] ) ) {
            $domain = strtolower( substr( strrchr( (string) $_POST['email'], '@' ), 1 ) );
            $blocked = apply_filters( 'css_disposable_domains', self::disposable_domains() );
            if ( in_array( $domain, $blocked, true ) ) {
                return 'disposable-email';
            }
        }

        return '';
    }

    public static function disposable_domains() {
        return array(
            'mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com',
            'throwawaymail.com', 'yopmail.com', 'trashmail.com', 'getnada.com',
            'maildrop.cc', 'temp-mail.org',
        );
    }

    public static function log_block( $reason ) {
        if ( ! (int) self::setting( 'log_blocks' ) ) {
            return;
        }
        $counts          = get_option( 'css_blocked', array() );
        $today           = gmdate( 'Y-m-d' );
        $counts[ $today ] = isset( $counts[ $today ] ) ? (int) $counts[ $today ] + 1 : 1;
        // Keep only the last 30 days of stats.
        $counts = array_slice( $counts, -30, null, true );
        update_option( 'css_blocked', $counts, 'no' );
    }

    /* ---- Admin UI ---- */

    public static function admin_menu() {
        add_options_page(
            __( 'Comment Spam Shield', 'css' ),
            __( 'Spam Shield', 'css' ),
            'manage_options',
            'comment-spam-shield',
            array( __CLASS__, 'settings_page' )
        );
    }

    public static function register_settings() {
        register_setting( 'css_settings_group', CSS_OPTION, array( __CLASS__, 'sanitize' ) );
    }

    public static function sanitize( $input ) {
        $out = array();
        $out['min_seconds']     = max( 0, (int) ( $input['min_seconds'] ?? 5 ) );
        $out['max_urls']        = max( 0, (int) ( $input['max_urls'] ?? 2 ) );
        $out['require_js']      = empty( $input['require_js'] ) ? 0 : 1;
        $out['block_disposable'] = empty( $input['block_disposable'] ) ? 0 : 1;
        $out['log_blocks']      = empty( $input['log_blocks'] ) ? 0 : 1;
        return $out;
    }

    public static function settings_page() {
        $settings = wp_parse_args( get_option( CSS_OPTION, array() ), self::defaults() );
        $counts   = get_option( 'css_blocked', array() );
        $total    = array_sum( array_map( 'intval', $counts ) );
        ?>
        <div class="wrap">
            <h1><?php esc_html_e( 'Comment Spam Shield', 'css' ); ?></h1>
            <p><?php
                printf(
                    /* translators: %d: number of blocked attempts */
                    esc_html__( 'Blocked %d spam comments in the last 30 days.', 'css' ),
                    (int) $total
                );
            ?></p>
            <form method="post" action="options.php">
                <?php settings_fields( 'css_settings_group' ); ?>
                <table class="form-table">
                    <tr>
                        <th scope="row"><label for="css_min_seconds"><?php esc_html_e( 'Minimum form time (seconds)', 'css' ); ?></label></th>
                        <td><input type="number" id="css_min_seconds" name="<?php echo esc_attr( CSS_OPTION ); ?>[min_seconds]" value="<?php echo esc_attr( $settings['min_seconds'] ); ?>" min="0" class="small-text" /></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="css_max_urls"><?php esc_html_e( 'Max URLs per comment', 'css' ); ?></label></th>
                        <td><input type="number" id="css_max_urls" name="<?php echo esc_attr( CSS_OPTION ); ?>[max_urls]" value="<?php echo esc_attr( $settings['max_urls'] ); ?>" min="0" class="small-text" /></td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Require JavaScript challenge', 'css' ); ?></th>
                        <td><input type="checkbox" name="<?php echo esc_attr( CSS_OPTION ); ?>[require_js]" value="1" <?php checked( $settings['require_js'], 1 ); ?> /></td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Block disposable emails', 'css' ); ?></th>
                        <td><input type="checkbox" name="<?php echo esc_attr( CSS_OPTION ); ?>[block_disposable]" value="1" <?php checked( $settings['block_disposable'], 1 ); ?> /></td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e( 'Log blocked attempts', 'css' ); ?></th>
                        <td><input type="checkbox" name="<?php echo esc_attr( CSS_OPTION ); ?>[log_blocks]" value="1" <?php checked( $settings['log_blocks'], 1 ); ?> /></td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }
}

CommentSpamShield::init();
