# The SecureCore PHP extension (ext/, addiscorp/securecore#53), built against PHP 8.3 NTS on
# Debian bookworm. From the repo root (the repo is the build context; nothing is bind-mounted,
# so this works on Docker hosts that can't see this folder, e.g. Colima):
#
#   docker build -f docker/ext.Dockerfile --target check .            clippy (-D warnings) + tests
#   docker build -f docker/ext.Dockerfile --target so -o .tmp/ext .   writes .tmp/ext/securecore.so
#   docker build -f docker/ext.Dockerfile --target php .              WordPress php-fpm + the extension
#
# docker/compose.ext.yml runs the WordPress stack with the `php` target.

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
    cargo build --locked --release -p securecore-php \
 && mkdir -p /out && cp /build/target/release/libsecurecore.so /out/securecore.so

# Every Rust gate for ext/: the whole workspace, the PHP crate included.
FROM toolchain AS check
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo clippy --locked --workspace --all-targets -- -D warnings \
 && cargo test --locked --workspace

FROM scratch AS so
COPY --from=build /out/securecore.so /securecore.so

# Stock WordPress php-fpm (Debian trixie, PHP 8.3 NTS: same extension API as the build) with
# the extension. One ini line points it at the config; docker/compose.ext.yml supplies the file.
FROM wordpress:php8.3-fpm AS php
COPY --from=build /out/securecore.so /usr/local/lib/php/extensions/securecore.so
COPY docker/securecore.ini /usr/local/etc/php/conf.d/securecore.ini
COPY ext/examples/off.json /etc/securecore/securecore.json
