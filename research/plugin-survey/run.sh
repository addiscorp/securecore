#!/usr/bin/env bash
# Reproduce the plugin survey (issue #40) from scratch: fetch the corpus, index WordPress
# core + WooCommerce, analyze each plugin, aggregate.
#
#   research/plugin-survey/run.sh                 # everything (re-uses downloads already in the work dir)
#   research/plugin-survey/run.sh --fresh         # delete the work dir first
#   research/plugin-survey/run.sh --only a,b      # analyze only these slugs (results for others are kept)
#
# Needs docker (on this iMac: DOCKER_CONTEXT=colima), curl, unzip, jq. The PHP work runs in
# a php:8.3-cli container; files go in and out with `docker cp` / tar, no bind mounts.
# Downloads and sources live in <repo>/.tmp/survey (git-ignored).
set -euo pipefail
export COPYFILE_DISABLE=1   # no macOS metadata in the tar streams
if [ "$(uname)" = Darwin ]; then tar() { command tar --no-xattrs --no-mac-metadata "$@"; }; fi

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
work="$repo/.tmp/survey"
only=""
jobs=3
while [ $# -gt 0 ]; do
  case "$1" in
    --fresh) [ -d "$work" ] && find "$work" -mindepth 1 -delete; shift ;;
    --only) only="$2"; shift 2 ;;
    --jobs) jobs="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done
mkdir -p "$work" "$here/results/plugins"

# 1. corpus
"$here/fetch.sh" "$work"

# 2. PHP-Parser, pinned by composer.lock
if [ ! -f "$work/tools/vendor/autoload.php" ]; then
  mkdir -p "$work/tools"
  tar -C "$here" -cf - composer.json composer.lock |
    docker run --rm -i composer:2 sh -c 'mkdir -p /s && cd /s && tar -xf - && composer install -q --no-interaction 1>&2 && tar -cf - vendor' |
    tar -xf - -C "$work/tools"
fi

# 3. one work container for the PHP steps
name="securecore-survey-$$"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run -d --name "$name" php:8.3-cli sleep 86400 >/dev/null
docker exec "$name" mkdir -p /s/bin /s/src /s/out/plugins
tar -C "$here" -cf - lib.php index.php analyze.php aggregate.php | docker exec -i "$name" tar -xf - -C /s/bin
tar -C "$work/tools" -cf - vendor | docker exec -i "$name" tar -xf - -C /s/bin

if [ -n "$only" ]; then
  slugs=$(tr ',' ' ' <<<"$only")
else
  slugs=$(jq -r '.[].slug' "$here/results/corpus.json")
fi
# Sources: WordPress, WooCommerce (needed for the index) and the plugins to analyze.
copy=".wordpress woocommerce"
for s in $slugs; do [ "$s" = woocommerce ] || copy="$copy $s"; done
# shellcheck disable=SC2086
tar -C "$work/src" -cf - $copy | docker exec -i "$name" tar -mxf - -C /s/src

# 4. index of WordPress core, WooCommerce and PHP
docker exec "$name" php -d memory_limit=4G /s/bin/index.php /s/src/.wordpress /s/src/woocommerce /s/out/index.json
docker exec "$name" php -r '$i=json_decode(file_get_contents("/s/out/index.json"),true);
  echo json_encode(["wordpress_version"=>$i["wordpress_version"],"woocommerce_version"=>$i["woocommerce_version"],"php_version"=>$i["php_version"],
  "wp"=>["files"=>$i["wp"]["files"],"functions"=>count($i["wp"]["functions"]),"classes"=>count($i["wp"]["classes"]),"constants"=>count($i["wp"]["constants"]),
  "globals"=>count($i["wp"]["globals"]),"hooks_literal"=>count($i["wp"]["hooks"]),"hooks_dynamic"=>count($i["wp"]["hook_patterns"])],
  "woo"=>["files"=>$i["woo"]["files"],"functions"=>count($i["woo"]["functions"]),"classes"=>count($i["woo"]["classes"]),"constants"=>count($i["woo"]["constants"]),"hooks_literal"=>count($i["woo"]["hooks"])]],
  JSON_PRETTY_PRINT),"\n";' > "$here/results/index-summary.json"

# 5. analyze, $jobs plugins at a time
# shellcheck disable=SC2086
printf '%s\n' $slugs | docker exec -i "$name" sh -c \
  "xargs -P $jobs -I{} php -d memory_limit=3G /s/bin/analyze.php /s/src/{} {} /s/out/index.json /s/out/plugins/{}.json"
docker exec "$name" tar -C /s/out/plugins -cf - . | tar -xf - -C "$here/results/plugins"

# 6. aggregate over every plugin result present
tar -C "$here/results" -cf - corpus.json plugins | docker exec -i "$name" sh -c 'mkdir -p /s/agg && tar -xf - -C /s/agg'
docker exec "$name" php -d memory_limit=2G /s/bin/aggregate.php /s/agg/corpus.json /s/agg/plugins /s/out/index.json /s/out/aggregate.json /s/out/tables.md
docker exec "$name" tar -C /s/out -cf - aggregate.json tables.md | tar -xf - -C "$here/results"
echo "results in $here/results (aggregate.json, tables.md, plugins/*.json)"
