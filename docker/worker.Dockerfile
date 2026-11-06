# The SecureCore worker is just PHP CLI with pcntl + opcache. It runs the launcher and code
# installed under wp-content/securecore on the mounted WordPress volume, so there is one copy
# of the code (the same one core's admin screen reads). It runs in its own container with no
# network (see compose.yml); the sandbox's isolation is the launcher's PHP settings, and the
# container is an extra layer.
FROM php:8.3-cli
# pcntl: fork per request. opcache: share the compiled WordPress across forks. mysqli: the
# "real WordPress" model (addiscorp/securecore#42) boots WordPress core, whose requirement
# check insists the extension is present — the sandbox never connects (no network, no
# password); every query goes back to core over the socket (sandbox/bootstrap.php).
RUN docker-php-ext-install pcntl mysqli > /dev/null && docker-php-ext-enable opcache
