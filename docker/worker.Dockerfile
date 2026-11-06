# The SecureCore worker is just PHP CLI with pcntl + opcache. It runs the launcher and code
# installed under wp-content/securecore on the mounted WordPress volume, so there is one copy
# of the code (the same one core's admin screen reads). It runs in its own container with no
# network (see compose.yml); the sandbox's isolation is the launcher's PHP settings, and the
# container is an extra layer.
FROM php:8.3-cli
RUN docker-php-ext-install pcntl > /dev/null && docker-php-ext-enable opcache
