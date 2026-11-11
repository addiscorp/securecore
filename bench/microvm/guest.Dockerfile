# The microVM guest's root filesystem (addiscorp/securecore#68, #70): the php-layer1 image
# (docker/ext.Dockerfile: WordPress php-fpm 8.3, the extension, securecore-fpm) plus the guest's
# PID 1, its forwarders and the pool overrides. build-images.sh exports it to a read-only ext4
# image; the site and its uploads come in on their own disks, not from here.
#   docker build -f bench/microvm/guest.Dockerfile --build-arg BASE=<project>-php -t <tag> .
# The database path (#70, init.sh's sc.db): libsc-vsock-connect.so (mysqlnd straight onto vsock),
# or securecore-microvm guest-forward (one process, no fork per connection); socat stays for the
# spike's comparison runs only.
ARG BASE=sc-mvm-php
FROM rust:1.99-bookworm@sha256:e6f2cff35d0f309acf8433b4f05878ed77092602c5065cc81801177da0bb3a9c AS build
COPY bench/microvm/Cargo.toml bench/microvm/Cargo.lock /src/
COPY bench/microvm/src /src/src
COPY bench/microvm/vsock-connect.c /src/
RUN cd /src && cargo build --locked --release \
 && cc -O2 -Wall -Werror -shared -fPIC -o /src/libsc-vsock-connect.so /src/vsock-connect.c -ldl

FROM ${BASE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends socat iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/securecore-microvm /usr/local/bin/securecore-microvm
COPY --from=build /src/libsc-vsock-connect.so /usr/local/lib/libsc-vsock-connect.so
COPY bench/microvm/zz-microvm.conf /usr/local/etc/php-fpm.d/zz-microvm.conf
COPY bench/microvm/init.sh /sbin/securecore-init
# The same ini files without the extension, for the extension-off latency runs (sc.ext=0).
RUN mkdir -p /usr/local/etc/php/conf.d-noext \
 && cp /usr/local/etc/php/conf.d/*.ini /usr/local/etc/php/conf.d-noext/ \
 && rm /usr/local/etc/php/conf.d-noext/securecore.ini \
 && chmod 755 /sbin/securecore-init
