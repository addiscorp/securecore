#!/bin/sh
# The compatibility sweep (docs/compatibility.md): set up what the checks need on the running
# docker/ stack, check WooCommerce running TRUSTED (test/woo.sh with SecureCore on), then
# run test/compat.sh for each plugin, one at a time. Results: .tmp/compat/results.tsv,
# details per plugin in .tmp/compat/<slug>/. Exits non-zero if any plugin does not work.
#   DOCKER_CONTEXT=colima test/compat-all.sh [slug ...]
set -u
cd "$(dirname "$0")/.." || exit 1
compose() { docker compose -f docker/compose.yml "$@"; }
# wp-cli, keeping its exit status (a pipe into tr would hide it).
wp() {
  compose run --rm -T cli wp "$@" > .tmp/compat/wp.out 2>>.tmp/compat/wp-cli.err; wp_rc=$?
  tr -d '\r' < .tmp/compat/wp.out; return "$wp_rc"
}
PLUGINS="wordpress-seo elementor contact-form-7 classic-editor akismet wpforms-lite jetpack google-site-kit
updraftplus all-in-one-seo-pack litespeed-cache wp-mail-smtp really-simple-ssl wordfence redirection
woo-store-vacation woo-checkout-field-editor-pro"
[ $# -gt 0 ] && PLUGINS=$*
mkdir -p .tmp/compat
: > .tmp/compat/results.tsv

# The mail catcher (a test fixture): wp_mail() writes to wp-content/securecore-mail.log.
compose cp test/compat-mailcatch.php php:/var/www/html/wp-content/mu-plugins/securecore-mailcatch.php >/dev/null
compose exec -T php chown www-data /var/www/html/wp-content/mu-plugins/securecore-mailcatch.php
wp rewrite structure '/%postname%/' >/dev/null
# Core-side PHP messages go to wp-content/debug.log (test/compat.sh reads it); Jetpack next
# to WooCommerce needs more than 128 MB to activate under wp-cli.
wp config set WP_DEBUG true --raw >/dev/null
wp config set WP_DEBUG_LOG true --raw >/dev/null
wp config set WP_DEBUG_DISPLAY false --raw >/dev/null
wp config set WP_MEMORY_LIMIT 512M >/dev/null

# WooCommerce, trusted (no manifest), with a product and Cash on delivery, as docs/woocommerce-survey.md.
wp plugin is-installed woocommerce || wp plugin install woocommerce >/dev/null || { echo "FAIL install WooCommerce"; exit 1; }
wp plugin activate woocommerce >/dev/null || { echo "FAIL activate WooCommerce"; exit 1; }
[ -n "$(wp post list --post_type=product --field=ID)" ] || wp wc product create --user=admin --name='Compat product' --type=simple --regular_price=10 >/dev/null
wp option update woocommerce_cod_settings '{"enabled":"yes","title":"Cash on delivery"}' --format=json >/dev/null
wp option update woocommerce_coming_soon no >/dev/null
woo_version=$(wp plugin list --name=woocommerce --field=version)
if test/woo.sh > .tmp/compat/woocommerce.log 2>&1; then woo=yes; failed=; else woo=no; failed=$(grep FAIL .tmp/compat/woocommerce.log | head -n 1); fi
icon=$(curl -fsS "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D=woocommerce&request%5Bfields%5D%5Bicons%5D=1" | sed -n 's/.*"icons":{\([^}]*\)}.*/\1/p' | tr ',' '\n' | sed -nE 's/"(svg|2x|1x)":"([^"]*)"/\1 \2/p' | sed 's#\\/#/#g' | sort -k1,1r | awk '{print $2}' | head -n 1)
printf '%s\t%s\t%s\t%s\t%s\n' "woocommerce (trusted)" "$woo_version" "$woo" "${failed:-}" "$icon" >> .tmp/compat/results.tsv
echo "== woocommerce $woo_version trusted: $woo"

bad=0
for slug in $PLUGINS; do
  test/compat.sh "$slug" > ".tmp/compat/$slug.log" 2>&1; rc=$?
  tail -n 1 ".tmp/compat/$slug.log"
  [ "$rc" = 0 ] || bad=$((bad + 1))
done
echo
cat .tmp/compat/results.tsv
[ "$woo" = yes ] && [ "$bad" = 0 ]
