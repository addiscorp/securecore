# The SecureCore PHP extension (ext/, addiscorp/securecore#53), built against the PHP in
# PHP_IMAGE: an official php image on Debian bookworm (PHP 8.3 NTS unless told otherwise). From
# the repo root (the repo is the build context; nothing is bind-mounted, so this works on Docker
# hosts that can't see this folder, e.g. Colima):
#
#   docker build -f docker/ext.Dockerfile --target check .            clippy (-D warnings) + tests
#   docker build -f docker/ext.Dockerfile --target so -o .tmp/ext .   writes .tmp/ext/securecore.so
#   docker build -f docker/ext.Dockerfile --target dist -o <dir> .    securecore.so + securecore-fpm
#   docker build -f docker/ext.Dockerfile --target php .              WordPress php-fpm + the extension
#   docker build -f docker/ext.Dockerfile --target php-layer1 .       the same, started by securecore-fpm
#   docker build -f docker/ext.Dockerfile --target guest .            the microVM guest's root (#71;
#                                                                      scripts/guest-image.sh makes the disk)
#
# The release matrix (E8) builds `dist` once per cell of scripts/ext-cells.txt, with
# --build-arg PHP_IMAGE=<that cell's image> (scripts/ext-build.sh). The NTS cells build in the
# php:<v>-fpm-bookworm image and the ZTS cells in php:<v>-zts-bookworm: each image's php-config
# and headers are that version and thread-safety build exactly, so bindgen sees the ABI the
# extension will be loaded into. bookworm (glibc 2.36) is also the oldest glibc the binaries
# need, so they run on bookworm, trixie and Ubuntu 24.04 alike.
#
# docker/compose.ext.yml runs the WordPress stack with the `php` target;
# docker/compose.ext-layer1.yml on top of it runs the `php-layer1` target (layer 1, E6).
ARG PHP_IMAGE=php:8.3-fpm-bookworm@sha256:d7677e2a3c1579fbe52848cc446bc24860187c876c383a43b7d4b8e06dce537e

# php-config and the headers ext-php-rs's bindgen reads; clang/libclang for bindgen.
FROM ${PHP_IMAGE} AS toolchain
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang libclang-dev \
 && rm -rf /var/lib/apt/lists/*
COPY --from=rust:1.99-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c /usr/local/cargo /usr/local/cargo
COPY --from=rust:1.99-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c /usr/local/rustup /usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo RUSTUP_HOME=/usr/local/rustup PATH=/usr/local/cargo/bin:$PATH
RUN rustup component add clippy
# One target folder per PHP flavour (e.g. 8.3-nts) inside the shared cache: ext-php-rs's build
# script watches php-config's path, not which PHP it is, so a target folder shared between
# flavours would keep the first flavour's bindings.
RUN php -r 'echo PHP_MAJOR_VERSION, ".", PHP_MINOR_VERSION, PHP_ZTS ? "-zts" : "-nts";' > /flavour
WORKDIR /build/ext
COPY ext/ /build/ext/

# The target cache is shared by every build of this file on the Docker host (every checkout and
# branch), and cargo decides by mtime whether a workspace crate is stale. A COPY keeps the files'
# edit times, so a crate built later from another branch looks newer than this branch's sources and
# gets linked in its place. Stamping the workspace's own sources first makes cargo rebuild the five
# local crates (seconds) while the registry dependencies stay cached.
FROM toolchain AS build
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    find /build/ext -name '*.rs' -exec touch {} + \
 && export CARGO_TARGET_DIR="/build/target/$(cat /flavour)" \
 && cargo build --locked --release -p securecore-php -p securecore-fpm \
 && mkdir -p /out && cp "$CARGO_TARGET_DIR/release/libsecurecore.so" /out/securecore.so \
 && cp "$CARGO_TARGET_DIR/release/securecore-fpm" /out/securecore-fpm

# Every Rust gate for ext/: the whole workspace, the PHP crate included.
FROM toolchain AS check
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    find /build/ext -name '*.rs' -exec touch {} + \
 && export CARGO_TARGET_DIR="/build/target/$(cat /flavour)" \
 && cargo clippy --locked --workspace --all-targets -- -D warnings \
 && cargo test --locked --workspace

FROM scratch AS so
COPY --from=build /out/securecore.so /securecore.so

# What a release cell ships: the extension for this PHP, and the launcher (plain Rust; the same
# bytes in every cell of one architecture, which the release checks).
FROM scratch AS dist
COPY --from=build /out/securecore.so /securecore.so
COPY --from=build /out/securecore-fpm /securecore-fpm

# Stock WordPress php-fpm (Debian trixie, PHP 8.3 NTS: same extension API as the build) with
# the extension. One ini line points it at the config, /var/www/html/securecore.json: the site
# root is the folder containing it. The image's entrypoint copies /usr/src/wordpress into a new
# site volume, so a fresh stack starts with off.json there; test/ext-config.sh replaces it.
FROM wordpress:php8.3-fpm AS php
# PDO's MySQL driver (the image ships mysqli only): plugins that use PDO, and the database policy's
# probe (test/ext-db.sh, E4). ext/sockets (E5): so the host tests exercise socket_connect. Both
# are core extensions with no external libs.
RUN docker-php-ext-install -j"$(nproc)" pdo_mysql sockets
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

# libsc-vsock-connect.so (#70): preloaded into the guest's php-fpm, it turns a connect to
# 127.0.0.1:<forwarded port> into a vsock connect to the host, so mysqlnd's own socket reaches
# MySQL with no process in between.
FROM toolchain AS preload
COPY ext/fpm/guest/vsock-connect.c /src/vsock-connect.c
RUN mkdir -p /out && clang -O2 -Wall -Werror -shared -fPIC -o /out/libsc-vsock-connect.so /src/vsock-connect.c -ldl

# Layer 1 as a microVM (#71): the guest's root filesystem. The same php-fpm and extension as the
# `php` target, with securecore-fpm as PID 1 (/sbin/securecore-init), the preload and the pool
# overrides. scripts/guest-image.sh exports it to the read-only rootfs.ext4 the host boots; the
# site and its writable folders come in on their own disks, never from here. The image carries
# no site secrets (delivering them per site is #72).
FROM php AS guest
COPY --from=build /out/securecore-fpm /usr/local/bin/securecore-fpm
COPY --from=preload /out/libsc-vsock-connect.so /usr/local/lib/libsc-vsock-connect.so
COPY ext/fpm/guest/zz-microvm.conf /usr/local/etc/php-fpm.d/zz-microvm.conf
COPY ext/fpm/guest/warm.php /usr/local/lib/securecore/warm.php
# The same ini files without the extension, for the extension-off latency runs (sc.ext=0).
RUN ln -sf /usr/local/bin/securecore-fpm /sbin/securecore-init \
 && mkdir -p /usr/local/etc/php/conf.d-noext /etc/securecore \
 && cp /usr/local/etc/php/conf.d/*.ini /usr/local/etc/php/conf.d-noext/ \
 && rm /usr/local/etc/php/conf.d-noext/securecore.ini
