#!/bin/sh
# Prove request isolation on the running docker/ stack: two requests to the same plugin must
# not see each other's state. With the fork per request they don't; without it (the worker's
# SECURECORE_NOFORK mode) the static leaks, which is the point of forking.
#   DOCKER_CONTEXT=colima test/isolation.sh
set -eu
cd "$(dirname "$0")/.."
compose() { docker compose -f docker/compose.yml "$@"; }
fails=0

compose cp test/isolation.php php:/tmp/securecore-isolation.php >/dev/null

echo "fork worker (normal):"
if compose exec -T php php /tmp/securecore-isolation.php /run/securecore/worker.sock; then
  echo "ok   isolated with the fork"
else
  echo "FAIL not isolated with the fork"; fails=$((fails + 1))
fi

echo "no-fork worker (SECURECORE_NOFORK=1, one process reused):"
compose stop worker >/dev/null 2>&1
cid=$(compose run --rm -d -e SECURECORE_NOFORK=1 worker)
sleep 3
if compose exec -T php php /tmp/securecore-isolation.php /run/securecore/worker.sock leak; then
  echo "ok   state leaks without the fork, as expected (so the fork is what isolates)"
else
  echo "FAIL expected a leak without the fork"; fails=$((fails + 1))
fi
docker stop "$cid" >/dev/null 2>&1 || true
compose up -d worker >/dev/null 2>&1
sleep 2

[ "$fails" -eq 0 ] && echo "isolation proven" || echo "$fails check(s) failed"
[ "$fails" -eq 0 ]
