# Stock WordPress on stock PHP (php-fpm): WordPress core runs here. SecureCore comes in as the
# release zip (scripts/package.sh → dist/securecore.zip), unpacked by install-securecore the
# same way install.sh does it, plus this repo's test plugins and manifests. Files are copied
# in, not bind-mounted, so the stack also runs on Docker hosts that cannot see this folder
# (Colima). The sandbox itself is the worker container (docker/worker.Dockerfile).
FROM wordpress:php8.3-fpm
COPY dist/securecore.zip /usr/src/securecore/securecore.zip
COPY manifests/ /usr/src/securecore/manifests/
COPY probe/ /usr/src/securecore/securecore-probe/
COPY bench/plugin/ /usr/src/securecore/securecore-bench/
COPY bench/worker-breakdown.php /usr/src/securecore/worker-breakdown.php
COPY test/plugin/ /usr/src/securecore/securecore-state/
COPY docker/install-securecore.sh /usr/local/bin/install-securecore
