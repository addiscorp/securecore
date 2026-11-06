<?php
/**
 * Plugin Name: SecureCore test mail catcher
 * Description: Test fixture for test/compat.sh (installed as a mu-plugin): wp_mail() writes each
 * message to wp-content/securecore-mail.log and reports success instead of sending it, so a
 * check can see that a plugin really sent its email. The stack has no mail server.
 */
add_filter('pre_wp_mail', function ($short, array $atts) {
    $to = is_array($atts['to']) ? implode(', ', $atts['to']) : (string) $atts['to'];
    $entry = "To: $to\nSubject: " . ($atts['subject'] ?? '') . "\n\n" . ($atts['message'] ?? '') . "\n----\n";
    file_put_contents(WP_CONTENT_DIR . '/securecore-mail.log', $entry, FILE_APPEND | LOCK_EX);
    return true;
}, 10, 2);
