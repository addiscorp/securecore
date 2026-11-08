# The release check's site (addiscorp/securecore#53, E8): WordPress on one cell's PHP, with
# SecureCore installed by the release's own installer from the release's own files, exactly as a
# server admin would. test/release-check.sh builds and drives it; docker/compose.release-check.yml
# runs it.
#
#   PHP_IMAGE  the cell's image from scripts/ext-cells.txt: the build image itself, so the
#              artifact is checked in the PHP it was built for (minus the Rust toolchain).
#   TS         nts | zts. NTS runs WordPress on php-fpm. The ZTS images have no php-fpm, so
#              ZTS runs it on php-cgi in FastCGI mode (php-cgi -b), behind the same nginx; its
#              request-time log lines go down FastCGI's stderr into nginx's error log.
#   release    (a build context) a release laid out by scripts/release-layout.sh holding this
#              cell's .so and launcher: the bytes the release ships, never a rebuild.
ARG PHP_IMAGE
# WordPress 7.1.4: only its files are used (/usr/src/wordpress), not its PHP.
ARG WORDPRESS_IMAGE=wordpress:php8.3-fpm@sha256:a6b5868cf272ee51b361c7ca31090080ee476d571416aa72832fdc640aa8527c
FROM ${WORDPRESS_IMAGE} AS wordpress

FROM ${PHP_IMAGE}
ARG TS
# WordPress's database driver, and opcache on as in the wordpress images (the vault checks
# opcache at startup).
RUN docker-php-ext-install -j"$(nproc)" mysqli >/dev/null && docker-php-ext-enable opcache
COPY --from=wordpress --chown=www-data:www-data /usr/src/wordpress /var/www/html
# The wordpress image's wp-config, which reads the database and the keys from the environment
# (the vault maps them); uploads and cache exist and belong to the site's user, as layer 1 wants.
RUN cp -p /var/www/html/wp-config-docker.php /var/www/html/wp-config.php \
 && install -d -o www-data -g www-data /var/www/html/wp-content/uploads /var/www/html/wp-content/cache
# How this cell serves FastCGI on :9000, plain (sapi) and under layer 1 (sapi-layer1).
RUN set -eu; \
    if [ "$TS" = zts ]; then \
      run='php-cgi -b 0.0.0.0:9000'; l1='securecore-fpm --config /var/www/html/securecore.json --php-fpm php-cgi -- -b 0.0.0.0:9000'; \
    else \
      run='php-fpm'; l1='securecore-fpm --config /var/www/html/securecore.json'; \
    fi; \
    printf '#!/bin/sh\nexec %s\n' "$run" > /usr/local/bin/sapi; \
    printf '#!/bin/sh\nexec %s\n' "$l1" > /usr/local/bin/sapi-layer1; \
    chmod 755 /usr/local/bin/sapi /usr/local/bin/sapi-layer1
# The installer, from the release, against the release (file:// is what curl fetches from the
# bucket, byte for byte). Its output is kept for the check to read.
COPY --from=release / /release
RUN mkdir -p /release-check \
 && sh /release/install-ext.sh --from file:///release --canary --wordpress /var/www/html > /release-check/install.log 2>&1 \
 || { cat /release-check/install.log; exit 1; }
CMD ["sapi"]
