#!/bin/sh
# Copy SecureCore's files from the image into the WordPress volume (run as root in the php
# container after WordPress is in place). Same layout a site owner would create by hand.
set -eu
content=/var/www/html/wp-content
mkdir -p "$content/mu-plugins" "$content/securecore/manifests" "$content/plugins/securecore-probe" "$content/plugins/securecore-bench"
cp /usr/src/securecore/mu-plugins/SecureCore.php "$content/mu-plugins/SecureCore.php"
cp /usr/src/securecore/manifests/*.json "$content/securecore/manifests/"
cp /usr/src/securecore/securecore-probe/*.php "$content/plugins/securecore-probe/"
cp /usr/src/securecore/securecore-bench/*.php "$content/plugins/securecore-bench/"
chown -R www-data:www-data "$content"
