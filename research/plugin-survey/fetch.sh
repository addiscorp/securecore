#!/usr/bin/env bash
# Fetch the survey corpus: the top 51 popular wordpress.org plugins (the 50 most
# installed besides WooCommerce, plus WooCommerce, which is in the top 50 itself),
# the 5 most-installed plugins that declare "Requires Plugins: woocommerce", and the
# current WordPress release. One download at a time, with a pause between requests.
#
# Usage: fetch.sh <work-dir>      (downloads land in <work-dir>/zips, sources in <work-dir>/src)
set -euo pipefail

work=${1:?usage: fetch.sh <work-dir>}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$work/zips" "$work/src" "$here/results"
api='https://api.wordpress.org/plugins/info/1.2/?action=query_plugins'
fields='&request[fields][sections]=0&request[fields][description]=0&request[fields][short_description]=0&request[fields][ratings]=0&request[fields][icons]=0&request[fields][banners]=0&request[fields][screenshots]=0&request[fields][versions]=0&request[fields][contributors]=0&request[fields][tags]=0'
pause() { sleep 2; }

curl -fsS -g "${api}&request[browse]=popular&request[per_page]=250${fields}" -o "$work/popular250.json"

# corpus.json: rank, group, slug, version, active installs, zip size (filled below), requires_php.
jq '
  [.plugins | to_entries[] | .value + {rank: (.key + 1)}] as $all
  | ($all | map(select(.slug != "woocommerce")) | .[0:50] | map(. + {group: "top50"}))
  + ($all | map(select(.slug == "woocommerce")) | map(. + {group: "woocommerce"}))
  + ($all | map(select((.requires_plugins // []) | index("woocommerce"))) | .[0:5] | map(. + {group: "woo-extension"}))
  | map({rank, group, slug, name, version, active_installs, requires_php, requires, tested,
         requires_plugins, download_link, last_updated})
' "$work/popular250.json" > "$work/corpus.partial.json"

n=$(jq length "$work/corpus.partial.json")
echo "corpus: $n plugins"

i=0
while read -r slug link; do
  i=$((i + 1))
  zip="$work/zips/$slug.zip"
  if [ ! -s "$zip" ]; then
    echo "[$i/$n] $slug"
    curl -fsS -L "$link" -o "$zip.part" && mv "$zip.part" "$zip"
    pause
  fi
  if [ ! -d "$work/src/$slug" ]; then
    mkdir -p "$work/src/.unpack-$slug"
    unzip -q -o "$zip" -d "$work/src/.unpack-$slug"
    # wordpress.org zips hold one top-level folder named after the slug.
    if [ -d "$work/src/.unpack-$slug/$slug" ]; then
      mv "$work/src/.unpack-$slug/$slug" "$work/src/$slug"
      find "$work/src/.unpack-$slug" -depth -mindepth 0 -delete
    else
      mv "$work/src/.unpack-$slug" "$work/src/$slug"
    fi
  fi
done < <(jq -r '.[] | "\(.slug) \(.download_link)"' "$work/corpus.partial.json")

# Zip and unpacked sizes.
jq -c '.[]' "$work/corpus.partial.json" | while read -r row; do
  slug=$(jq -r .slug <<<"$row")
  zbytes=$(stat -f %z "$work/zips/$slug.zip" 2>/dev/null || stat -c %s "$work/zips/$slug.zip")
  ubytes=$(du -sk "$work/src/$slug" | cut -f1)
  php_files=$(find "$work/src/$slug" -type f -name '*.php' | wc -l | tr -d ' ')
  jq -c --argjson z "$zbytes" --argjson u "$((ubytes * 1024))" --argjson p "$php_files" \
    '. + {zip_bytes: $z, unpacked_bytes: $u, php_files: $p} | del(.download_link)' <<<"$row"
done | jq -s . > "$here/results/corpus.json"

# WordPress core (the reference for what counts as "WordPress").
if [ ! -d "$work/src/.wordpress" ]; then
  curl -fsS -L https://wordpress.org/latest.zip -o "$work/zips/wordpress.zip"
  mkdir -p "$work/src/.unpack-wp"
  unzip -q -o "$work/zips/wordpress.zip" -d "$work/src/.unpack-wp"
  mv "$work/src/.unpack-wp/wordpress" "$work/src/.wordpress"
  find "$work/src/.unpack-wp" -depth -delete
fi
grep -E "^\\\$wp_version" "$work/src/.wordpress/wp-includes/version.php"
rm -f "$work/corpus.partial.json"
echo "fetched $n plugins + WordPress into $work/src"
