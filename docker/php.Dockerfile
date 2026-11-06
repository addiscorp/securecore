# Stock WordPress on stock PHP (php-fpm), plus SecureCore: the mu-plugin, the manifests,
# the probe plugin and the securecore binary. Files are copied in, not bind-mounted, so the
# stack also runs on Docker hosts that cannot see this folder (Colima, remote daemons).
FROM wordpress:php8.3-fpm
COPY plugin/SecureCore.php /usr/src/securecore/mu-plugins/SecureCore.php
COPY manifests/ /usr/src/securecore/manifests/
COPY probe/ /usr/src/securecore/securecore-probe/
COPY dist/securecore-linux-x64 /usr/local/bin/securecore
COPY docker/install-securecore.sh /usr/local/bin/install-securecore
