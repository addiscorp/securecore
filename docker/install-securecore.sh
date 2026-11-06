#!/bin/sh
# Copy SecureCore's files from the image into the WordPress volume, in the layout a site
# owner would create by hand (see INSTALL.md): the mu-plugin, and wp-content/securecore
# holding the sandbox code, the launcher and the manifests. Run as root in the php container
# after WordPress is in place.
set -eu
content=/var/www/html/wp-content
home=$content/securecore
mkdir -p "$content/mu-plugins" "$home/sandbox" "$home/bin" "$home/manifests" \
  "$content/plugins/securecore-probe" "$content/plugins/securecore-bench" "$content/plugins/securecore-state"
cp /usr/src/securecore/mu-plugins/SecureCore.php "$content/mu-plugins/SecureCore.php"
cp /usr/src/securecore/sandbox/*.php "$home/sandbox/"
cp /usr/src/securecore/bin/securecore-worker "$home/bin/securecore-worker"
chmod +x "$home/bin/securecore-worker"
cp /usr/src/securecore/manifests/*.json "$home/manifests/"
cp /usr/src/securecore/securecore-probe/*.php "$content/plugins/securecore-probe/"
cp /usr/src/securecore/securecore-bench/*.php "$content/plugins/securecore-bench/"
cp /usr/src/securecore/securecore-state/*.php "$content/plugins/securecore-state/"
chown -R www-data:www-data "$content"
