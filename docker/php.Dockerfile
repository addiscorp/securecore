# Stock WordPress on stock PHP (php-fpm): WordPress core runs here. SecureCore's files are
# copied in (not bind-mounted, so the stack also runs on Docker hosts that cannot see this
# folder, like Colima). install-securecore lays them out under wp-content. The sandbox
# itself is the worker container (docker/worker.Dockerfile); this container only connects to
# its socket and, on the admin screen, generates manifests (sandbox/scan.php).
FROM wordpress:php8.3-fpm
COPY plugin/SecureCore.php /usr/src/securecore/mu-plugins/SecureCore.php
COPY sandbox/ /usr/src/securecore/sandbox/
COPY bin/ /usr/src/securecore/bin/
COPY manifests/ /usr/src/securecore/manifests/
COPY probe/ /usr/src/securecore/securecore-probe/
COPY bench/plugin/ /usr/src/securecore/securecore-bench/
COPY bench/worker-breakdown.php /usr/src/securecore/sandbox/worker-breakdown.php
COPY test/plugin/ /usr/src/securecore/securecore-state/
COPY docker/install-securecore.sh /usr/local/bin/install-securecore
