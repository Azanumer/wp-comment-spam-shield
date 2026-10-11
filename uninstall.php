<?php
// Removes plugin data on uninstall.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

delete_option( 'css_settings' );
delete_option( 'css_blocked' );
delete_option( 'css_challenge_salt' );
