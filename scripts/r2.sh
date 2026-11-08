#!/bin/sh
# One object in the releases bucket over R2's S3 API, with curl's SigV4 signing: no AWS CLI, so
# it works the same on every runner image (the release cells run on x86_64 and arm64).
#   scripts/r2.sh put <key> <file>
#   scripts/r2.sh get <key> <file>
#   scripts/r2.sh delete <key>
# Needs R2_ENDPOINT, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and R2_BUCKET_RELEASES in the
# environment. The keys reach curl on stdin (--config -), never on its command line.
set -eu
: "${R2_ENDPOINT:?}" "${AWS_ACCESS_KEY_ID:?}" "${AWS_SECRET_ACCESS_KEY:?}" "${R2_BUCKET_RELEASES:?}"
op=${1:-} key=${2:-}
[ -n "$key" ] || { echo "usage: $0 put|get <key> <file> | delete <key>" >&2; exit 2; }
url="${R2_ENDPOINT%/}/$R2_BUCKET_RELEASES/$key"
r2() { printf 'user = "%s:%s"\n' "$AWS_ACCESS_KEY_ID" "$AWS_SECRET_ACCESS_KEY" | curl --config - --aws-sigv4 "aws:amz:auto:s3" -fsS --retry 3 "$@"; }
case $op in
  put) [ $# -eq 3 ] || exit 2; r2 -T "$3" "$url" -o /dev/null ;;
  get) [ $# -eq 3 ] || exit 2; r2 -o "$3" "$url" ;;
  delete) r2 -X DELETE "$url" -o /dev/null ;;
  *) echo "usage: $0 put|get <key> <file> | delete <key>" >&2; exit 2 ;;
esac
