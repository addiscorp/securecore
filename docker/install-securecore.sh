#!/bin/sh
# Put SecureCore into the WordPress volume the way install.sh does — the release zip unpacked
# to wp-content/plugins/securecore and the loader in mu-plugins — plus this repo's test
# plugins and their manifests. Run as root in the php container after WordPress is in place.
set -eu
content=/var/www/html/wp-content
data=$content/securecore
mkdir -p "$content/mu-plugins" "$data/manifests" "$data/bench" \
  "$content/plugins/securecore-probe" "$content/plugins/securecore-bench" "$content/plugins/securecore-state"
rm -rf "$content/plugins/securecore"
php -r '$z = new ZipArchive(); if ($z->open($argv[1]) !== true || !$z->extractTo($argv[2])) exit(1);' \
  /usr/src/securecore/securecore.zip "$content/plugins"
chmod 755 "$content/plugins/securecore/bin/securecore-worker"
cp "$content/plugins/securecore/mu-plugin/securecore-loader.php" "$content/mu-plugins/securecore-loader.php"
rm -f "$content/mu-plugins/SecureCore.php"
cp /usr/src/securecore/manifests/*.json "$data/manifests/"
cp /usr/src/securecore/worker-breakdown.php "$data/bench/worker-breakdown.php"
cp /usr/src/securecore/securecore-probe/*.php "$content/plugins/securecore-probe/"
cp /usr/src/securecore/securecore-bench/*.php "$content/plugins/securecore-bench/"
cp /usr/src/securecore/securecore-state/*.php "$content/plugins/securecore-state/"
chown -R www-data:www-data "$content"
