#!/bin/sh
# Walk a WooCommerce store over HTTP: shop page, product page, then the Store API cart and
# checkout with Cash on delivery, and read the order back through the REST API. Exits
# non-zero on the first failure. Run against the docker/ stack with SecureCore off and on
# (test/woo.sh and SECURECORE on by default); WooCommerce runs in core either way.
#   test/woo.sh
set -u
cd "$(dirname "$0")/.."
base=http://127.0.0.1:8088
dir=.tmp/woo
mkdir -p "$dir"
compose() { docker compose -f docker/compose.yml "$@"; }
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+ — $2}"; fails=$((fails + 1)); }

product_id=$(compose run --rm -T cli wp post list --post_type=product --field=ID 2>/dev/null | tr -d '\r' | head -1)
[ -n "$product_id" ] && pass "a product exists (id $product_id)" || { fail "no product"; exit 1; }
slug=$(compose run --rm -T cli wp post list --post_type=product --field=post_name 2>/dev/null | tr -d '\r' | head -1)

code=$(curl -s -o "$dir/shop.html" -w '%{http_code}' "$base/shop/")
{ [ "$code" = 200 ] && grep -qi 'add' "$dir/shop.html"; } && pass "shop page (200)" || fail "shop page" "$code"
code=$(curl -s -o "$dir/product.html" -w '%{http_code}' "$base/product/$slug/")
{ [ "$code" = 200 ] && grep -qiE 'add[ -]?to[ -]?cart|wc-block' "$dir/product.html"; } && pass "product page (200)" || fail "product page" "$code"

# Store API: a cart token + nonce from the first call, echoed back on the next calls.
curl -s -D "$dir/h.txt" -o "$dir/cart.json" "$base/wp-json/wc/store/v1/cart" >/dev/null
nonce=$(tr -d '\r' < "$dir/h.txt" | awk -F': ' 'tolower($1)=="nonce"{print $2}')
token=$(tr -d '\r' < "$dir/h.txt" | awk -F': ' 'tolower($1)=="cart-token"{print $2}')
[ -n "$nonce" ] && [ -n "$token" ] && pass "Store API cart (got nonce + token)" || { fail "Store API cart"; exit 1; }
H="-H Nonce:$nonce -H Cart-Token:$token -H Content-Type:application/json"

curl -s $H -o "$dir/add.json" -w '' -X POST "$base/wp-json/wc/store/v1/cart/add-item" \
  -d "{\"id\":$product_id,\"quantity\":1}"
items=$(grep -o '"key"' "$dir/add.json" | wc -l | tr -d ' ')
[ "$items" -ge 1 ] && pass "add to cart" || fail "add to cart" "$(head -c 160 "$dir/add.json")"

# Checkout with Cash on delivery.
curl -s -D "$dir/co-h.txt" $H -o "$dir/checkout.json" -X POST "$base/wp-json/wc/store/v1/checkout" -d '{
  "billing_address":{"first_name":"Test","last_name":"Buyer","address_1":"1 Test St","city":"Testville","state":"CA","postcode":"90001","country":"US","email":"buyer@test.example","phone":"5550000"},
  "shipping_address":{"first_name":"Test","last_name":"Buyer","address_1":"1 Test St","city":"Testville","state":"CA","postcode":"90001","country":"US"},
  "payment_method":"cod"
}'
order_id=$(grep -oE '"order_id":[0-9]+' "$dir/checkout.json" | head -1 | grep -oE '[0-9]+')
status=$(grep -oE '"status":"[a-z-]+"' "$dir/checkout.json" | head -1 | sed -E 's/.*:"([a-z-]+)"/\1/')
[ -n "$order_id" ] && pass "checkout created order $order_id (status ${status:-?})" || { fail "checkout" "$(head -c 200 "$dir/checkout.json")"; exit 1; }

# The order is visible in wp-admin (via the admin-authenticated REST store).
got=$(compose run --rm -T cli wp wc shop_order get "$order_id" --user=admin --field=status 2>/dev/null | tr -d '\r')
[ -n "$got" ] && pass "order $order_id in wp-admin (status $got)" || fail "order not in wp-admin"

# A plain REST read of the catalogue (Store API products).
code=$(curl -s -o "$dir/products.json" -w '%{http_code}' "$base/wp-json/wc/store/v1/products")
{ [ "$code" = 200 ] && grep -q "\"id\":$product_id" "$dir/products.json"; } && pass "REST products read" || fail "REST products read" "$code"

[ "$fails" -eq 0 ] && echo "woocommerce store works ($fails failures)" || echo "$fails check(s) failed"
[ "$fails" -eq 0 ]
