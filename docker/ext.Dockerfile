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
# The `php` targets' (and so the microVM guest's) base, by digest: WordPress 7.1.4's php8.3-fpm
# image, the same one docker/release-check.Dockerfile takes WordPress's files from. A release's
# guest image is built from these bytes and no others (#80).
ARG WORDPRESS_IMAGE=wordpress:php8.3-fpm@sha256:a6b5868cf272ee51b361c7ca31090080ee476d571416aa72832fdc640aa8527c
# Every apt package these stages install comes from snapshot.debian.org at this moment, so a
# rebuild installs the same versions (clang, which compiles the guest's preload; e2fsprogs, which
# makes the guest's disk): the guest image is reproducible (#80).
ARG DEBIAN_SNAPSHOT=20261101T000000Z
# The guest disk's tools (mke2fs, tar, gzip): this image plus e2fsprogs from the snapshot.
ARG GUEST_TOOLS_IMAGE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# php-config and the headers ext-php-rs's bindgen reads; clang/libclang for bindgen, from the
# snapshot (the image's own Debian release, its main, updates and security suites).
FROM ${PHP_IMAGE} AS toolchain
ARG DEBIAN_SNAPSHOT
RUN . /etc/os-release \
 && rm -f /etc/apt/sources.list.d/debian.sources \
 && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s %s main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s %s-updates main\ndeb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/%s %s-security main\n' \
      "$DEBIAN_SNAPSHOT" "$VERSION_CODENAME" "$DEBIAN_SNAPSHOT" "$VERSION_CODENAME" "$DEBIAN_SNAPSHOT" "$VERSION_CODENAME" > /etc/apt/sources.list \
 && apt-get update \
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
FROM ${WORDPRESS_IMAGE} AS php
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

# The guest's init, static (#101): the guest's /usr and /lib are the host's (its own glibc,
# whatever version), so the init depends on no library at all. The same sources as securecore-fpm.
FROM toolchain AS build-init
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    find /build/ext -name '*.rs' -exec touch {} + \
 && export CARGO_TARGET_DIR="/build/target/init-static" \
 && RUSTFLAGS="-C target-feature=+crt-static" cargo build --locked --release -p securecore-fpm --target x86_64-unknown-linux-gnu \
 && mkdir -p /out && cp "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/securecore-fpm" /out/securecore-init \
 && ! ldd /out/securecore-init > /dev/null 2>&1

# Layer 1 as a microVM: the SecureCore base (#101). The guest is the host's own PHP: the launcher
# captures the host's php-fpm, its extensions and their libraries into a disk of their own, its
# php.ini, scan folder and pool into another, and mounts both over this base, which holds only
# what is SecureCore's: the init (PID 1, /sc/securecore-init), the preload, the warm-up script,
# the mount points (/sc/php, /sc/conf, and an empty folder for each top-level folder the host's
# PHP lives in) and nothing else. No shell, no libraries, no PHP: nothing here runs but the init.
# scripts/guest-image.sh exports it to the read-only rootfs.ext4 the installer records.
FROM toolchain AS guest-root
COPY --from=build-init /out/securecore-init /g/sc/securecore-init
COPY --from=preload /out/libsc-vsock-connect.so /g/sc/libsc-vsock-connect.so
COPY ext/fpm/guest/warm.php /g/sc/warm.php
RUN cd /g && mkdir -p proc sys dev tmp run sc/php sc/conf bin etc home lib lib32 lib64 libx32 nix opt root sbin srv usr var \
 && chmod 755 sc sc/php sc/conf && chmod 1777 tmp && chmod 755 sc/securecore-init && chmod 644 sc/libsc-vsock-connect.so sc/warm.php
FROM scratch AS guest
COPY --from=guest-root /g/ /
CMD ["/sc/securecore-init"]

# The guest disk's tools (#80): scripts/guest-image.sh runs scripts/guest-disk.sh in this image, so
# the export's tar, mke2fs and gzip are these pinned bytes and never the host's. mke2fs's version
# decides the disk's bytes (1.47.0 copies each file's ctime from the unpacked tree, 1.47.1 and
# later take SOURCE_DATE_EPOCH), so it comes from the snapshot, never from whatever the host has.
FROM ${GUEST_TOOLS_IMAGE} AS guest-tools
ARG DEBIAN_SNAPSHOT
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/%s trixie main\n' "$DEBIAN_SNAPSHOT" > /etc/apt/sources.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends e2fsprogs \
 && find /var/lib/apt/lists -mindepth 1 -delete
COPY --chmod=755 scripts/guest-disk.sh /usr/local/bin/guest-disk
