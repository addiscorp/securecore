# The SecureCore worker: stock PHP CLI with pcntl + opcache, running sandbox/worker.php.
# It runs in its own container with no network (see compose.yml): the sandbox's isolation
# is where it runs, not PHP flags.
FROM php:8.3-cli
RUN docker-php-ext-install pcntl > /dev/null
# opcache ships with the image; enable it for the CLI.
RUN docker-php-ext-enable opcache
COPY sandbox/worker.php sandbox/setup.php /opt/securecore/
COPY bench/worker-breakdown.php /opt/securecore/
