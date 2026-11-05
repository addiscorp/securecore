#!/bin/sh
# Start the WordPress stack and the SecureCore worker, and install the site. From repo root:
#   docker/setup.sh
set -eu
cd "$(dirname "$0")"

docker compose up -d --build db php web

wp() { docker compose run --rm -T cli wp "$@"; }

echo "waiting for the database"
i=0
until docker compose exec -T db mariadb -uwordpress -pwordpress-db-password -e 'select 1' wordpress >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { echo "database did not start" >&2; exit 1; }
  sleep 1
done
# The php container writes wp-config.php on its first request.
until docker compose exec -T php test -f /var/www/html/wp-config.php; do
  curl -s -o /dev/null http://127.0.0.1:8088/ || true
  sleep 1
done
docker compose exec -T php sh /usr/local/bin/install-securecore

if ! wp core is-installed >/dev/null 2>&1; then
  wp core install --url=http://127.0.0.1:8088 --title=SecureCore --admin_user=admin \
    --admin_password=securecore-demo --admin_email=admin@example.com --skip-email
fi
wp plugin activate hello securecore-probe

# The worker reads the plugins and manifests that install-securecore just wrote, so start it
# now (and rebuild it so code changes take effect).
docker compose up -d --build worker

wp core version
echo "site: http://127.0.0.1:8088/wp-admin/  (admin / securecore-demo)"
