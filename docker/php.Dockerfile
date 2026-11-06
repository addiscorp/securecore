# Stock WordPress on stock PHP (php-fpm): WordPress core runs here. SecureCore's mu-plugin,
# manifests and the test plugins are copied in (not bind-mounted, so the stack also runs on
# Docker hosts that cannot see this folder, like Colima). The sandbox itself is the worker
# container (docker/worker.Dockerfile); this container only connects to its socket.
FROM wordpress:php8.3-fpm
COPY plugin/SecureCore.php /usr/src/securecore/mu-plugins/SecureCore.php
COPY manifests/ /usr/src/securecore/manifests/
COPY probe/ /usr/src/securecore/securecore-probe/
COPY bench/plugin/ /usr/src/securecore/securecore-bench/
COPY test/plugin/ /usr/src/securecore/securecore-state/
COPY docker/install-securecore.sh /usr/local/bin/install-securecore
