# WooCommerce and SecureCore

Two questions, in order: does a store work with SecureCore installed (WooCommerce trusted),
and what would it take to sandbox WooCommerce or its extensions.

## Level 1 — a store works, WooCommerce trusted

WooCommerce runs in core (no manifest = trusted); other plugins are sandboxed. This is what
a store owner needs first: most plugin vulnerabilities are in the long tail of small
plugins, not WooCommerce itself.

`test/woo.sh` walks a real store over HTTP and exits non-zero on failure: the shop page, a
product page, the Store API cart, checkout with **Cash on delivery**, the order read back in
wp-admin, and a REST catalogue read. It passes with SecureCore **on** (WooCommerce trusted,
Hello Dolly + the probe sandboxed) and **off**:

```
ok   a product exists (id 11)
ok   shop page (200)
ok   product page (200)
ok   Store API cart (got nonce + token)
ok   add to cart
ok   checkout created order 13 (status processing)
ok   order 13 in wp-admin (status processing)
ok   REST products read
woocommerce store works (0 failures)        # on AND off
```

So SecureCore can protect the long tail today without touching WooCommerce.

## Level 2 — survey: sandboxing WooCommerce and its extensions

This is a survey to decide the next issues, not a fix. I sandboxed one small free extension
(woo-store-vacation 1.9.9, with WooCommerce trusted) and then WooCommerce itself
(9.x: its generated manifest is **675 functions, 863 hooks, dynamic hooks present**), and
recorded what broke.

### What broke, grouped by cause

| # | cause | what I saw | rough fix |
|---|---|---|---|
| 1 | **Namespaced calls to core functions/constants don't hit the global stand-ins** | Extension threw `Undefined constant Woo_Store_Vacation\WP_LANG_DIR`; WooCommerce failed to load with `Call to undefined function Automattic\Jetpack\Autoloader\…\get_option()`. The sandbox defines stand-ins and a few constants in the global namespace; code calling them *fully qualified* inside its own namespace doesn't resolve to them. | **Medium.** Define the common WordPress constants in the sandbox (`WP_LANG_DIR`, `WP_CONTENT_DIR`, `WPINC`, …) by forwarding them at boot, and resolve qualified function calls (the stand-in generator already has the names; also register them in the namespaces that call them, or ship a small global shim the autoloader expects). ~50–150 lines. |
| 2 | **A plugin class `extends` a WooCommerce/core class that isn't in its sandbox** | woo-store-vacation has `class … extends WC_Settings_Page`; WooCommerce extensions routinely extend `WC_Payment_Gateway`, `WC_Widget`, `WC_REST_Controller`, `WP_Widget`. With WooCommerce trusted (in core), the base class isn't defined in the sandbox, so the subclass fatals at definition. | **Large.** The paired-object mechanism from the design doc #4: generate, from the base class's method list, a sandbox-side stub base class whose inherited methods forward to core and whose abstract methods the plugin fills. Per base class, ~100–200 lines + a generator; the set of base classes is bounded and known. |
| 3 | **Templates, the main query and shortcodes render in core, where a sandboxed plugin's functions aren't defined** | With WooCommerce sandboxed, the shop page returned 200 but rendered no products: WooCommerce's hooks fired inside the sandbox, but WordPress built the page and ran `the_content`/`WP_Query` in core, which has no `wc_*` functions. The theme and blocks calling `wc_get_product()` etc. in core would fatal. | **Large / architectural.** This is why WooCommerce should stay trusted. Sandboxing it would need core-side stand-ins for every WooCommerce function the theme/blocks call (the inverse direction: core → sandbox), i.e. WooCommerce's whole public API as forwarding stubs in core. Hundreds of functions; only worth it with the paired-class work (#2). |
| 4 | **REST controllers and the Store API live in core** | The Store API (`/wp-json/wc/store/*`) and `wc/v3` register their routes and controllers at `rest_api_init` in core. Sandboxed, the controllers (which `extend WC_REST_Controller`) don't exist in core, so cart/checkout/catalogue endpoints 404 or error. | **Large**, and a subcase of #2 + #3: the controller classes need the paired-class treatment, and their registration must happen in core with the handlers forwarding into the sandbox. |
| 5 | **Action Scheduler and cron** | Not reached (WooCommerce didn't load sandboxed), but Action Scheduler stores and runs jobs via WP-Cron in core and its tables; a sandboxed WooCommerce would register its runner inside the sandbox where cron in core can't see it. | **Medium**, once #1–#3 are done: forward the scheduler's register/claim/run calls, or keep Action Scheduler trusted as a shared library. ~100 lines. |
| 6 | **Custom tables** | WooCommerce's HPOS and Action Scheduler use custom tables through `$wpdb` with the site DB user. The data gateway (SQL parsed, tables checked) from design doc #2 isn't built yet; today `$wpdb` calls are forwarded whole and core runs them. | **Medium–large**, tracked separately: the `$wpdb` proxy with table-level grants. Not WooCommerce-specific. |
| 7 | **Dynamic hooks** | Both the extension and WooCommerce register hooks with non-literal tags (`"woocommerce_{$x}"`), which the `token_get_all` scan can't see (`dynamic_hooks: true` in both manifests). | **Small for detection** (already flagged in the manifest), **medium to handle**: let a plugin declare hook *prefixes*, or register a catch-all forwarder for a plugin's dynamic hooks. ~50 lines. |

### Reading

- **Keep WooCommerce trusted.** Causes 3 and 4 make sandboxing WooCommerce itself a large, architectural job (core-side stubs for its whole API). Level 1 already protects the plugins that matter most.
- **The first unlock for sandboxing *extensions* is causes 1 and 2**: define the core constants in the sandbox and resolve namespaced core calls (medium), then paired base classes for `WC_Payment_Gateway` / `WC_Widget` / `WC_REST_Controller` (large but bounded). With those, a large class of small WooCommerce extensions becomes sandboxable with WooCommerce trusted.
- **Order for the next issues:** (1) constants + namespaced resolution → (2) paired classes → (7) dynamic hooks → (5) Action Scheduler → (6) the `$wpdb` gateway. Cause 3/4 (sandboxing WooCommerce itself) only after all of those.

### Reproduce

Level 1: `DOCKER_CONTEXT=colima test/woo.sh` against the running stack (install WooCommerce,
add a product, enable Cash on delivery first — see the PR for the exact wp-cli commands).
Level 2: generate a plugin's manifest with `sandbox/gen-manifest.php <plugin> <plugins-dir>`,
drop it in `wp-content/securecore/manifests`, restart the worker, load the shop page, and
read `wp-content/securecore-audit.log` and the worker log.
