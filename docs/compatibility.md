# Plugin compatibility (sandboxed)

What we have actually run in the sandbox, and what happened. The product page's "Works with"
section may only list rows marked **yes** here. Swept on 6 Nov 2026 (#29): WordPress 7.1.4
on php-fpm 8.3 (the docker/ stack), worker on PHP 8.3 CLI, SecureCore at 7d5ff2f (main,
after #28), each plugin at its current wordpress.org version.

## The result

**No plugin in the sweep works sandboxed yet.** Every one of the 17 fails when it loads in
the sandbox, for one of eight causes (below, each with an issue). None of them gets as far
as a failure in its main feature.

The containment does hold. With each failing plugin sandboxed, the rest of the site kept
working:

- the front page and wp-admin load (200, no critical error);
- the other sandboxed plugins (Hello Dolly, the probe) still run sandboxed;
- the probe's attacks still fail;
- `test/site.sh` passes, for all 17.

So a plugin that can't run in the sandbox fails alone; it doesn't take the site down.

**WooCommerce works with SecureCore on, running trusted**, as docs/woocommerce-survey.md
said: WooCommerce 11.2.2, `test/woo.sh` passes with SecureCore on (shop, product page,
Store API cart, Cash on delivery checkout, order in wp-admin, REST products). That, and
WordPress itself, is what the page can say today.

The first three causes are the broadest:

| issue | cause | plugins it hits |
|---|---|---|
| #30 | the scanner counts methods as functions | 5 |
| #31 | WordPress's files are out of the sandbox's reach | 5 |
| #32 | WordPress's globals | 7 |

Between them they touch 14 of the 17 plugins. Most plugins hit more than one cause, though,
so a plugin moves to yes only when all of its causes are fixed. A re-run of
`test/compat-all.sh` after each fix shows what moves.

## Plugins

`yes` = loads sandboxed, its screens work, its main feature passes the same check it passes
trusted, no denials or PHP messages, `test/site.sh` passes. `partly` = all of that except
the main feature, which needs something this stack doesn't have (noted). `no` = fails a
check; the cause is linked.

| plugin | version | works sandboxed | what was checked | why not |
|---|---|---|---|---|
| WooCommerce (trusted, not sandboxed) | 11.2.2 | **yes, trusted** | `test/woo.sh`: shop, product, Store API cart, COD checkout, order in wp-admin, REST | — (sandboxing WooCommerce itself: docs/woocommerce-survey.md) |
| Yoast SEO | 28.8 | no | SEO meta on a post: canonical, og:title, schema graph (baseline ok); admin screen | `get_option()` / `get_current_user_id()` / `is_multisite()` undefined, since Yoast has methods with those names #30; `$wp_rewrite` #32; `option_wpseo` hooks denied #35 |
| Elementor | 4.3.6 | no | a page built with a heading widget renders Elementor markup (baseline ok); admin screen | fails to load: its bundled Jetpack autoloader's `get_option()` has no stand-in #30 |
| Contact Form 7 | 6.2.4.1 | no | a visitor submits the form and the email is sent with the message (baseline ok, via the test mail catcher); admin screen | fails to load: `require wp-admin/includes/class-wp-list-table.php` #31; `get_option()` / `register_post_type()` shadowed by its methods #30; `extends WP_List_Table` #34; uploads folder #31 |
| Classic Editor | 1.7.0 | no | Posts → Add New opens the classic editor (baseline ok) | loads, but `add_filter(…, '__return_false')` is not registered #36; `$wp_version` / `$pagenow` / `$post` #32 |
| Akismet | 5.7.2 | no | settings screen (spam checking needs an Akismet API key) | fails to load: `class … extends WP_Widget` #34 |
| WPForms Lite | 2.0.4 | no | its form renders from the `[wpforms]` shortcode (baseline ok); admin screen | fails to load: `$wp_version` is null #32 |
| Jetpack | 16.4 | no | dashboard screen (its features need a WordPress.com account) | `$wp_version` undefined #32 |
| Site Kit by Google | 1.191.0 | no | setup screen (its data needs a Google account) | `$wpdb` is null (`get_blog_prefix() on null`) #32; dynamic hooks denied #35 |
| UpdraftPlus | 1.26.14 | no | backup screen (a backup run is a long WP-Cron job; not exercised) | fails to load: `Class "wpdb" not found` #34; `include wp-includes/version.php` #31; `$wp_version` #32 |
| All in One SEO | 5.0.5 | no | SEO meta on a post: canonical, og:title, schema graph (baseline ok); admin screen | fails to load: `require wp-admin/includes/plugin.php` #31 |
| LiteSpeed Cache | 7.9.3 | no | dashboard (its page cache needs a LiteSpeed web server; this stack is nginx) | fails to load: `Undefined constant "WP_CONTENT_DIR"` #33 |
| WP Mail SMTP | 4.10.3 | no | Email Test tool (check unverified: its baseline didn't see the email, fix pending); admin screen | `WPMailSMTP\get_option()` undefined, since it has a `get_option` method #30; its own objects come back as `__PHP_Incomplete_Class` #37 |
| Really Simple Security | 9.8.4 | no | settings screen (it moves a site to HTTPS; this stack is plain http) | `include wp-admin/includes/plugin.php` #31; `is_plugin_active` missing from its manifest (open question in #30) |
| Wordfence | 9.0.2 | no | an IP blocked in Wordfence gets its block page (baseline ok); admin screen | fails to load: `require wp-includes/version.php` #31 |
| Redirection | 5.10.1 | no | a redirect it holds sends the visitor on with a 301 (check unverified: its baseline failed, fix pending); admin screen loads sandboxed | `load-tools_page_redirection` and `plugin_action_links_*` denied #35 |
| Store Vacation Lite for WooCommerce (extension) | 1.9.9 | no | vacation notice on the shop (check unverified: its baseline failed, fix pending) | `plugin_basename()` / `add_submenu_page()` shadowed by its methods #30; `WP_LANG_DIR`, `WEEK_IN_SECONDS` #33 |
| Checkout Field Editor for WooCommerce (extension) | 2.2.1 | no | screens and logs only (no functional check written) | `$wp_version` null #32; `MONTH_IN_SECONDS` #33; dynamic hooks #35 |

Re-reading docs/woocommerce-survey.md with these results: its cause 1, "namespaced calls to
core functions don't hit the global stand-ins", is #30. PHP falls back from a namespaced
call to the global function; the stand-in was missing because the plugin has a method with
that name. Its constants half is #33.

## The causes

| issue | cause | plugins |
|---|---|---|
| #30 | The scanner counts class methods as functions, so a WordPress function with a method's name gets no stand-in or grant | Yoast, Elementor, Contact Form 7, WP Mail SMTP, Store Vacation |
| #31 | The sandbox can't read WordPress's own files (ABSPATH is `/wordpress/`, outside open_basedir) or wp-content/uploads | All in One SEO, Contact Form 7, Really Simple Security, UpdraftPlus, Wordfence |
| #32 | WordPress globals (`$wp_version`, `$wpdb`, `$wp_rewrite`, `$pagenow`, `$post`) are null in the sandbox | WPForms Lite, Jetpack, Classic Editor, Checkout Field Editor, Site Kit, Yoast, UpdraftPlus |
| #33 | WordPress constants (`WP_CONTENT_DIR`, `MONTH_IN_SECONDS`, `WP_LANG_DIR`, …) are undefined | LiteSpeed Cache, Checkout Field Editor, Store Vacation |
| #34 | Core classes (`WP_Widget`, `wpdb`, `WP_List_Table`) to extend or create | Akismet, UpdraftPlus, Contact Form 7 |
| #35 | Dynamic hook tags (`plugin_action_links_<file>`, `option_<name>`, `load-<page>`, `activate_<file>`) are denied | Redirection, Yoast, Site Kit, Checkout Field Editor, Contact Form 7 |
| #36 | String callbacks naming core functions (`'__return_false'`) aren't registered | Classic Editor |
| #37 | A plugin's own objects come back into the sandbox as `__PHP_Incomplete_Class` | WP Mail SMTP |

Also found while setting up: #38, `scripts/package.sh` on macOS with the default TMPDIR built a zip
without the main class — `securecore.php` (the loader) and `SecureCore.php` (the class) differ only
in case, so on the case-insensitive staging volume one overwrote the other. Fixed in #51: the class
file is now `securecore-core.php`, and `package.sh` fails if any two packaged paths are equal
case-insensitively.

## Icons (wordpress.org plugins API, `icons`)

For the page. Only WooCommerce may be shown under "Works with" today, as running trusted.
The others are listed so the page can add each one as it passes.

| plugin | icon |
|---|---|
| WooCommerce | https://ps.w.org/woocommerce/assets/icon.svg?rev=3640790 |
| Yoast SEO | https://ps.w.org/wordpress-seo/assets/icon-256x256.gif?rev=3419908 |
| Elementor | https://ps.w.org/elementor/assets/icon-256x256.gif?rev=3444228 |
| Contact Form 7 | https://ps.w.org/contact-form-7/assets/icon.svg?rev=2339255 |
| Classic Editor | https://ps.w.org/classic-editor/assets/icon-256x256.png?rev=1998671 |
| Akismet | https://ps.w.org/akismet/assets/icon-256x256.png?rev=2818463 |
| WPForms Lite | https://ps.w.org/wpforms-lite/assets/icon.svg?rev=3254748 |
| Jetpack | https://ps.w.org/jetpack/assets/icon.svg?rev=2819237 |
| Site Kit by Google | https://ps.w.org/google-site-kit/assets/icon-256x256.png?rev=3606666 |
| UpdraftPlus | https://ps.w.org/updraftplus/assets/icon-256x256.png?rev=3729681 |
| All in One SEO | https://ps.w.org/all-in-one-seo-pack/assets/icon.svg?rev=2443290 |
| LiteSpeed Cache | https://ps.w.org/litespeed-cache/assets/icon-256x256.png?rev=2554181 |
| WP Mail SMTP | https://ps.w.org/wp-mail-smtp/assets/icon-256x256.png?rev=1755440 |
| Really Simple Security | https://ps.w.org/really-simple-ssl/assets/icon-256x256.png?rev=2839720 |
| Wordfence | https://ps.w.org/wordfence/assets/icon.svg?rev=2070865 |
| Redirection | https://ps.w.org/redirection/assets/icon-256x256.jpg?rev=983639 |
| Store Vacation Lite for WooCommerce | https://ps.w.org/woo-store-vacation/assets/icon-256x256.gif?rev=2923942 |
| Checkout Field Editor for WooCommerce | https://ps.w.org/woo-checkout-field-editor-pro/assets/icon-256x256.gif?rev=3479964 |

## How it's checked

`test/compat.sh <slug>` checks one plugin on the running docker/ stack; `test/compat-all.sh`
sets up what the checks need and runs the list. Each plugin:

1. Install the current wordpress.org version and activate it.
2. Run its functional check with the plugin **trusted**. This baseline proves the check sees
   the feature. If it fails, the check is broken, and the plugin is never reported as
   working.
3. Switch it into the sandbox the way a person does: Settings → SecureCore → Save, which
   generates the manifest from its code.
4. Load the front page, the dashboard, the Plugins screen and its own screen. Each must
   return 200 with no critical error, and the footer must say it ran sandboxed with core
   including none.
5. Run the same functional check sandboxed.
6. Check the logs: no denials, sandbox failures or sandbox PHP messages in the audit log;
   nothing in debug.log; nothing new in the worker log.
7. Run `test/site.sh`.
8. Switch it back out and deactivate it.

Evidence lands in `.tmp/compat/<slug>/`: every page, the manifests, the audit/debug/worker
logs and `problems.log`.

```
DOCKER_CONTEXT=colima docker/setup.sh          # the stack (macOS: TMPDIR=$PWD/.tmp, see #38)
DOCKER_CONTEXT=colima test/compat-all.sh       # or: test/compat.sh <slug>
```

The checks run over HTTP, like a visitor or an admin. Under wp-cli, SecureCore steps aside
and plugins load in core, so wp-cli is used only for setup. Email checks use a test-only
mu-plugin (`test/compat-mailcatch.php`) that records `wp_mail()` instead of sending it.
compat-all.sh also sets up the stack for the sweep:

- `/%postname%/` permalinks;
- `WP_DEBUG_LOG` on (debug.log, display off);
- `WP_MEMORY_LIMIT` 512M, because activating Jetpack next to WooCommerce exhausts 128 MB
  under wp-cli.

Not finished: the WP Mail SMTP, Redirection and Store Vacation checks didn't see their
feature even with the plugin trusted, so their sandboxed result rests on the load failures
only. They need fixing before those plugins can move to yes.
