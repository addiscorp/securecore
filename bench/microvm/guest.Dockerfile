# The microVM guest's root filesystem (addiscorp/securecore#68): the php-layer1 image
# (docker/ext.Dockerfile: WordPress php-fpm 8.3, the extension, securecore-fpm) plus socat for
# the vsock ends and the guest's PID 1. build-images.sh exports it to a read-only ext4 image;
# the site and its uploads come in on their own disks, not from here.
#   docker build -f bench/microvm/guest.Dockerfile --build-arg BASE=<project>-php -t <tag> .
ARG BASE=sc-mvm-php
FROM ${BASE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends socat iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY bench/microvm/zz-microvm.conf /usr/local/etc/php-fpm.d/zz-microvm.conf
COPY bench/microvm/init.sh /sbin/securecore-init
# The same ini files without the extension, for the extension-off latency runs (sc.ext=0).
RUN mkdir -p /usr/local/etc/php/conf.d-noext \
 && cp /usr/local/etc/php/conf.d/*.ini /usr/local/etc/php/conf.d-noext/ \
 && rm /usr/local/etc/php/conf.d-noext/securecore.ini \
 && chmod 755 /sbin/securecore-init
