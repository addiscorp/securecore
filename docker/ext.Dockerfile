# The SecureCore PHP extension (ext/, addiscorp/securecore#53), built against PHP 8.3 NTS on
# Debian bookworm. From the repo root (the repo is the build context; nothing is bind-mounted,
# so this works on Docker hosts that can't see this folder, e.g. Colima):
#
#   docker build -f docker/ext.Dockerfile --target check .            clippy (-D warnings) + tests
#   docker build -f docker/ext.Dockerfile --target so -o .tmp/ext .   writes .tmp/ext/securecore.so
#   docker build -f docker/ext.Dockerfile --target php .              WordPress php-fpm + the extension
#   docker build -f docker/ext.Dockerfile --target php-layer1 .       the same, started by securecore-fpm
#
# docker/compose.ext.yml runs the WordPress stack with the `php` target;
# docker/compose.ext-layer1.yml on top of it runs the `php-layer1` target (layer 1, E6).

# php-config and the headers ext-php-rs's bindgen reads; clang/libclang for bindgen.
FROM php:8.3-fpm-bookworm@sha256:d7677e2a3c1579fbe52848cc446bc24860187c876c383a43b7d4b8e06dce537e AS toolchain
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang libclang-dev \
 && rm -rf /var/lib/apt/lists/*
COPY --from=rust:1.99-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c /usr/local/cargo /usr/local/cargo
COPY --from=rust:1.99-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c /usr/local/rustup /usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo RUSTUP_HOME=/usr/local/rustup PATH=/usr/local/cargo/bin:$PATH \
    CARGO_TARGET_DIR=/build/target
RUN rustup component add clippy
WORKDIR /build/ext
COPY ext/ /build/ext/

FROM toolchain AS build
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --locked --release -p securecore-php -p securecore-fpm \
 && mkdir -p /out && cp /build/target/release/libsecurecore.so /out/securecore.so \
 && cp /build/target/release/securecore-fpm /out/securecore-fpm

# Every Rust gate for ext/: the whole workspace, the PHP crate included.
FROM toolchain AS check
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo clippy --locked --workspace --all-targets -- -D warnings \
 && cargo test --locked --workspace

FROM scratch AS so
COPY --from=build /out/securecore.so /securecore.so

# Stock WordPress php-fpm (Debian trixie, PHP 8.3 NTS: same extension API as the build) with
# the extension. One ini line points it at the config, /var/www/html/securecore.json: the site
# root is the folder containing it. The image's entrypoint copies /usr/src/wordpress into a new
# site volume, so a fresh stack starts with off.json there; test/ext-config.sh replaces it.
FROM wordpress:php8.3-fpm AS php
# PDO's MySQL driver (the image ships mysqli only): plugins that use PDO, and the database policy's
# probe (test/ext-db.sh, E4), which drives the PDO routes against the real server.
RUN docker-php-ext-install pdo_mysql
COPY --from=build /out/securecore.so /usr/local/lib/php/extensions/securecore.so
COPY docker/securecore.ini /usr/local/etc/php/conf.d/securecore.ini
COPY ext/examples/off.json /usr/src/wordpress/securecore.json

# Layer 1 (E6): the same image, with php-fpm started by securecore-fpm, which reads layer1 from
# the site's securecore.json, sandboxes itself with gelada and execs php-fpm (master and
# workers inherit the sandbox). docker-ensure-installed.sh is the image's entrypoint under the
# name that copies WordPress into a new site volume whatever the command is (the plain
# entrypoint does that only for a command named php-fpm). A new volume starts with off.json:
# layer 1 off, and the launcher says so in the log. The pool listens on TCP 9000, which layer1
# must allow (network.bind); a unix-socket listen can't work under TCP port rules.
FROM php AS php-layer1
COPY --from=build /out/securecore-fpm /usr/local/bin/securecore-fpm
ENTRYPOINT ["docker-ensure-installed.sh"]
CMD ["securecore-fpm", "--config", "/var/www/html/securecore.json"]
