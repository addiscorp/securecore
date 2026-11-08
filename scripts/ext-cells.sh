#!/bin/sh
# The extension's release matrix, from scripts/ext-cells.txt (addiscorp/securecore#53, E8).
#
#   scripts/ext-cells.sh json              the cells as a JSON array, for a workflow matrix:
#                                          [{"php":"8.1","ts":"nts","image":"php:8.1-fpm-…"}, …]
#   scripts/ext-cells.sh list              "<php> <ts>" per line
#   scripts/ext-cells.sh image <php> <ts>  that cell's build image
#   scripts/ext-cells.sh arches            the architectures every cell is built for
#   scripts/ext-cells.sh arch              this Docker host's architecture, as a release name
#
# Release file names (the installer, ext/install.sh, asks for the same names):
#   ext/securecore-php<php>-<ts>-linux-<arch>.so   the extension, one per cell
#   ext/securecore-fpm-linux-<arch>                the layer-1 launcher, one per architecture
set -eu
cells=$(dirname "$0")/ext-cells.txt
rows() { grep -v '^[[:space:]]*\(#\|$\)' "$cells"; }

case ${1:-} in
  json)
    rows | awk 'BEGIN { printf "[" } { printf "%s{\"php\":\"%s\",\"ts\":\"%s\",\"image\":\"%s\"}", (NR > 1 ? "," : ""), $1, $2, $3 } END { print "]" }' ;;
  list)
    rows | awk '{ print $1, $2 }' ;;
  image)
    [ $# -eq 3 ] || { echo "usage: $0 image <php> <ts>" >&2; exit 2; }
    image=$(rows | awk -v p="$2" -v t="$3" '$1 == p && $2 == t { print $3 }')
    [ -n "$image" ] || { echo "$0: no cell $2 $3 in $cells" >&2; exit 1; }
    echo "$image" ;;
  arches)
    echo "x86_64 arm64" ;;
  arch)
    # The Docker server's, not this shell's: builds run there.
    case $(docker info --format '{{.Architecture}}') in
      x86_64|amd64) echo x86_64 ;;
      aarch64|arm64) echo arm64 ;;
      *) echo "$0: unsupported Docker architecture $(docker info --format '{{.Architecture}}')" >&2; exit 1 ;;
    esac ;;
  *)
    sed -n '2,13p' "$0" >&2; exit 2 ;;
esac
