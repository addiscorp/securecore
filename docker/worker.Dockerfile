# The SecureCore worker is PHP CLI with pcntl + opcache, run inside gelada (addiscorp/securecore#42,
# part 3) — an OS sandbox applied at exec with no container of its own. gelada gives the worker
# filesystem and network confinement (Landlock + seccomp on Linux): it cannot read wp-config.php,
# cannot connect out (to MySQL, php-fpm or any host), and can write only the folders it is given.
# The launcher's open_basedir / disable_functions stay as an inner layer.
#
# gelada comes from crates.io by exact version (APS 10: registries by version, never a git pin),
# built in a builder stage and copied in — the worker image has no Rust toolchain.
FROM rust:1-bookworm AS gelada
RUN cargo install gelada --version 0.2.0 --locked --root /opt/gelada

FROM php:8.3-cli
# pcntl: fork per request. opcache: share the compiled WordPress across forks. mysqli: the
# "real WordPress" model (addiscorp/securecore#42) boots WordPress core, whose requirement
# check insists the extension is present — the sandbox never connects (gelada blocks it); every
# query goes back to core over the socket (sandbox/bootstrap.php).
RUN docker-php-ext-install pcntl mysqli > /dev/null && docker-php-ext-enable opcache
# php:8.3-cli and rust:1-bookworm are both Debian bookworm, so the gelada binary's glibc matches.
COPY --from=gelada /opt/gelada/bin/gelada /usr/local/bin/gelada
