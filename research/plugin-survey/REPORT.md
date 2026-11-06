# What 56 popular plugins need from WordPress (static analysis, #40)

The question behind this survey: SecureCore runs plugins in a sandboxed PHP worker. Today the
sandbox has no WordPress in it and forwards each WordPress call to core. The sweep (#29, PR #39)
found 0 of 17 popular plugins load that way, for eight causes (#30–#37). The alternative on the
table is a dummy or read-only WordPress inside the sandbox. This report maps, from the source of
the 50 most-installed wordpress.org plugins plus WooCommerce and 5 WooCommerce extensions, what
has to exist inside the sandbox and what has to stay out.

Everything here is reproducible with one command (`research/plugin-survey/run.sh`). The generated
tables are in `results/tables.md` and the numbers in `results/aggregate.json` (one JSON per plugin
is in `results/plugins/`). Numbers below are from the run on 6 Nov 2026: WordPress 7.1.4,
WooCommerce 11.2.2, and each plugin's version on wordpress.org that day (`results/corpus.json`).
Re-runs pick up new releases. A `--fresh` re-run 40 minutes after the first picked up Limit Login
Attempts Reloaded 3.4.1 → 3.4.2, which moved a few call-site counts but no number in the
summary tables.

## The answer in numbers

| to load 90% (51/56) of these plugins, a sandbox must provide | count (greedy minimum) | for all 56 |
| --- | --- | --- |
| WordPress functions, as real code or as stand-ins | **1,076** | 1,412 |
| WordPress core files they `require` themselves | **60** | 86 |
| WordPress globals | **90** (34 of them objects) | 122 (43 objects) |
| WordPress / wp-config constants | **70** | 95 |
| core classes they extend or implement (a base class must exist) | **19** | 47 |
| core classes they use at all (`new`, static calls, `instanceof`, `catch`, extend) | **86** | 164 |

Median plugin: 161 distinct WordPress functions (smallest: Classic Widgets, 1; largest: Jetpack, 880).
548 functions are called by at least 10% of plugins. 50 of 56 run their own SQL through `$wpdb`.
55 of 56 call nonce or hash functions that need wp-config's keys and salts.

**Reading:** the "forward calls" design has to rebuild, as stand-ins, proxies and paired classes,
most of WordPress's API surface: about 1,100–1,400 functions, 34–43 object globals and 19–47 base
classes. Every one of those is a round trip, plus the objects that cross it (#37). The causes
from the sweep are not edge cases. Each of the eight is present in 59–98% of the 56 plugins, and
**no plugin is free of all eight** (table below). A read-only WordPress inside the sandbox provides
all of the above natively. That moves the work to a much smaller and better-defined boundary: the
database, the secrets, file writes, processes, network and a short list of sensitive core calls.

## The sweep's causes, across all 56

Static predictions: a plugin is marked when its code (own or bundled) contains the pattern behind
the cause. Full matrix per plugin: `results/tables.md`, "The sweep's causes".

| cause | what it is | plugins (of 56) |
| --- | --- | --- |
| #30 | calls a WordPress function that has the same name as one of its own methods (the scanner bug) | **46** (82%) |
| #31 | `require`s a core file (48), touches uploads (34), or touches wp-content outside its folder (10) | **50** (89%) |
| #32 | reads or writes WordPress globals | **55** (98%) |
| #33 | reads WordPress constants other than `ABSPATH`/`WPINC` | **53** (95%) |
| #34 | uses a core class: extends/implements one (34 plugins) or only `new`/static/`instanceof` (19 more) | **53** (95%) |
| #35 | hook tags not literal in the source, or activation/deactivation hooks | **53** (95%) |
| #36 | core functions as string callbacks: as hook callbacks (`'__return_false'`) **38**; in any callback position (`array_map('absint', …)`, menu callbacks) | **51** (91%) |
| #37 | passes an object it built (`$this`, `new`) into an option/transient/meta/cache or a hook it fires (lower bound) | **33** (59%) |

**Checked against the sweep:** for all 15 swept plugins that are in this corpus (the 2 Woo
extensions it swept are not), every cause the sweep saw at run time is predicted statically. No
misses. Static analysis predicts more causes than the sweep saw, as expected: the sweep stops at
the first fatal. One example of a predicted, unobserved cause is Classic Editor and #30. It calls
the global `add_meta_box()` and `get_edit_post_link()` from inside its own static methods of the
same names (`classic-editor.php:685, 689, 840`), so even with #32/#36 fixed it would fail on the
post edit screen.

## 1. What a sandbox must provide (files, globals, constants, classes)

**Core files required explicitly** (86 distinct; ≥10% of plugins):

| file | plugins |
| --- | --- |
| `wp-admin/includes/plugin.php` | 38 (68%) |
| `wp-admin/includes/file.php` | 34 (61%) |
| `wp-admin/includes/class-wp-upgrader.php` | 28 (50%) |
| `wp-admin/includes/upgrade.php` | 20 (36%) |
| `wp-admin/includes/plugin-install.php` | 18 (32%) |
| `wp-admin/includes/image.php` | 14 (25%) |
| `wp-admin/includes/misc.php` | 12 (21%) |
| `wp-admin/includes/update.php`, `class-wp-list-table.php` | 11 each |
| `wp-admin/includes/theme.php`, `wp-includes/pluggable.php` | 10 each |
| `wp-admin/includes/media.php`, `template.php` | 9 each |
| `translation-install.php`, `screen.php` | 8 each |
| `user.php`, `class-wp-filesystem-base.php`, `class-wp-filesystem-direct.php` | 7 each |
| `wp-admin/includes/admin.php`, `class-plugin-upgrader.php`, `post.php` | 6 each |

The 90% set is 60 files and the 100% set is 86. In practice that is "all of `wp-admin/includes/`
plus a few `wp-includes` classes" (PHPMailer, IXR, phpass, version.php). Stand-in copies of three
files, as #31 suggested, would not get far. Counting the files that *define* the functions they
call, rather than the files they include, the 90% set is 88 of core's files.

**Globals** (122 distinct, 90 for 90%). The top ones: `$wpdb` 52, `$wp_version` 41, `$pagenow` 35,
`$post` 32, `$wp` 27, `$wp_filesystem` 27, `$submenu` 23, `$wp_filter` 18, `$wp_query` 18,
`$wp_admin_bar` 15, `$current_screen` 14, `$wp_rewrite` 14, `$wp_roles` 13. 34 object globals are
needed for 90%:
`current_screen, current_user, l10n, menu, post, shortcode_tags, submenu, wp, wp_admin_bar,
wp_current_filter, wp_customize, wp_embed, wp_filesystem, wp_filter, wp_locale, wp_meta_boxes,
wp_object_cache, wp_plugin_paths, wp_post_types, wp_query, wp_registered_sidebars,
wp_registered_widget_controls, wp_registered_widgets, wp_rewrite, wp_roles, wp_scripts, wp_styles,
wp_taxonomies, wp_textdomain_registry, wp_the_query, wp_theme_directories, wp_widget_factory,
wp_xmlrpc_server, wpdb`. 18 plugins touch `$wp_filter`, core's hook table, directly. A proxy for that
is effectively a second hook system. Copying scalars (#32's first step) covers `$wp_version` and
`$pagenow` but none of these.

**Constants** (95 distinct, 70 for 90%). The common ones are harmless: `ABSPATH` 48, `DAY_IN_SECONDS` 39,
`ARRAY_A` 37, `HOUR_IN_SECONDS` 36, `WP_PLUGIN_DIR` 36, `WP_DEBUG` 35, `MINUTE_IN_SECONDS` 34,
`WP_CONTENT_DIR` 33, `DOING_AJAX` 27, … But the 90% set **includes the secrets**: `AUTH_KEY` 10,
`DB_NAME` 10, and `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `AUTH_SALT`… (section 2). "All of wp-config's
constants" is never acceptable; it has to be an allowlist plus substitutes.

**Core classes extended or implemented** (47 distinct; 22 plugins extend none): `WP_List_Table`
14, `WP_REST_Controller` 11, `WP_Widget` 7, `WP_Upgrader_Skin` 6, `WP_Importer` 4, `Plugin_Upgrader`
4, `IXR_Client` 4, then a long tail (`Walker`, `WP_Customize_Control`, `WP_Query`, `WP_Error`,
`WP_HTML_Tag_Processor`, REST controllers…). The 90% set is 19 classes. Classes used at all: `WP_Error` 47,
`WP_REST_Response` 32, `WP_Query` 29, `Plugin_Upgrader` 28, `WP_Post` 26, `WP_User` 25.

**WooCommerce extensions** (5, WooCommerce trusted): they extend **56** distinct WooCommerce classes
between them: `WC_Payment_Gateway`(`_CC`), `WC_REST_Controller`, `WC_Payment_Token`,
`AbstractPaymentMethodType`, onboarding `Task`, `WC_Email`, `WC_Session(_Handler)`… They call
35–158 WooCommerce functions each. A sandbox for extensions needs WooCommerce's classes in it as
well, which is the same argument as for core, one level up.

## 2. What must never be inside it: secrets, and who reads them

**22 of 56 plugins read a secret directly** (`DB_*`, the keys and salts, `$wpdb->dbpassword/dbuser/
dbhost/dbname/dbh`, or wp-config.php itself). Every site with file:line and enclosing function is in
`results/tables.md` (214 sites). Grouped by why:

| why | plugins | what they read |
| --- | --- | --- |
| **Own database connection** (mysqldump, restore, a firewall that runs before WordPress) | UpdraftPlus, Duplicator, WP File Manager, Jetpack (WAF blocklog: `require_once` wp-config.php then `new mysqli(DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)`), Wordfence (WAF `mysqli_real_connect`) | `DB_HOST/USER/PASSWORD/NAME` |
| **The raw connection handle** `$wpdb->dbh` | All-in-One WP Migration (its whole export engine), Wordfence, Duplicator, AIOSEO, WP File Manager | the live mysqli |
| **Database name only**, for `information_schema` size/engine queries | LiteSpeed, Rank Math, AIOSEO, Yoast, Complianz, SG Optimizer, SG Security, WooCommerce | `DB_NAME` / `$wpdb->dbname` |
| **Keys and salts as encryption key material** for data they store | Site Kit (`LOGGED_IN_KEY`/`SALT` → openssl key for stored credentials, `Data_Encryption.php:122–143`), Rank Math (same), Yoast (`AUTH_KEY` → `derive_key`), Hostinger Reach, Limit Login Attempts (MFA backup codes, OTP pepper), Jetpack (PayPal OAuth), Duplicator, LiteSpeed (debug log name) | `AUTH_*`, `LOGGED_IN_*`, `NONCE_*` |
| **Keys hashed into a stable site ID** | WP Mail SMTP, AIOSEO, MonsterInsights, WPForms (bundled ProductApi), UpdraftPlus (autologin key) | `AUTH_KEY`, `SECURE_AUTH_KEY`, `LOGGED_IN_KEY` |
| **Reads and rewrites wp-config.php** | WP Fastest Cache (`file_get_contents` + `file_put_contents(ABSPATH."wp-config.php")` to add `WP_CACHE`, `inc/admin.php:362–365`) | the whole file |

**And indirectly, nearly everyone:** **55 of 56** call core functions whose result depends on the salts:
`wp_create_nonce` 52, `wp_verify_nonce` 51, `wp_nonce_field` 40, `check_ajax_referer` 38,
`check_admin_referer` 33, `wp_nonce_url` 32, `wp_hash` 24, `wp_salt` 17, `wp_set_auth_cookie` 13.
A read-only WordPress without the real salts would generate nonces that core rejects, and the
other way round. So these ~15 functions (all in `pluggable.php`) have to run in core even in the
read-only design. They are pluggable, so the sandbox can define them as forwarders before core's
copies load.

**Consequences for a read-only WordPress:** its wp-config must be a different file. It keeps the
non-secret constants (paths, `WP_DEBUG`, `WP_CACHE`…), has no `DB_*` values, and sets the key and
salt constants to per-plugin substitutes (for example HMAC(real key, plugin slug)). Then plugins
that use the keys as an ID or as key material keep working on new data. Data they already
encrypted with the real keys (Site Kit, Rank Math, Yoast, LLAR, Hostinger Reach) won't decrypt
until it is re-encrypted once, at the switch to sandboxed. That is a migration step to design, not
a reason to share the keys. `$wpdb` inside the sandbox has to be a gateway subclass with no
connection of its own (`dbh` null), which breaks All-in-One WP Migration's engine and the
`dbh`-reading paths listed above.

## 3. Plugins that can't be sandboxed in any design, unless the feature is off or granted in core

These need something no sandbox should give a plugin: writing wp-config.php, the site's
`.htaccess`, drop-ins or mu-plugins; running processes; or their own database connection. Each
entry was found by the analyzer, and those marked ✓ were confirmed by reading the source.

| plugin | what | evidence |
| --- | --- | --- |
| WP Fastest Cache | rewrites **wp-config.php** (`WP_CACHE`) and the site `.htaccess` | ✓ `inc/admin.php:362–365, 482` |
| SG Optimizer (sg-cachepress) | rewrites **wp-config.php** (`toggle_cache_constant`), installs the **advanced-cache.php** drop-in, runs `exec()` (image optimizers, `find`) | ✓ `File_Cacher.php:57, 1038–1042, 1077–1100`; `Images_Optimizer.php:317` |
| WP Super Cache | site `.htaccess` (`insert_with_markers`), `advanced-cache.php`, `WP_CACHE` in wp-config | `inc/htaccess.php:59, 356–405`; `inc/lifecycle.php:486` (likely: same function names the file and writes) |
| LiteSpeed Cache | `object-cache.php` drop-in, `guest.vary.php` URL entry point | `src/object-cache.cls.php:388` (likely); ✓ `guest.vary.php` |
| Really Simple Security | firewall writes `.htaccess`, `wp-config.php`, `.user.ini` (auto_prepend_file); deletes an mu-plugin; `lets-encrypt/download.php` loads wp-load.php itself | ✓ `security/firewall-manager.php:332–363, 486–542`; ✓ `lets-encrypt/download.php:6–11` |
| Wordfence | WAF writes `.htaccess`/`.user.ini`, own `mysqli` connection, raw `$wpdb->dbh` | `waf/bootstrap.php:584–715`, `vendor/wordfence/wf-waf/src/lib/storage/mysql.php:739` |
| Jetpack | WAF: `require_once` wp-config.php + own `mysqli`; writes an **mu-plugin** (Woo analytics proxy) | ✓ `jetpack-waf/src/class-waf-blocklog-manager.php:48–50`; `woocommerce-analytics/src/class-woocommerce-analytics.php:365` |
| Elementor | Safe Mode copies its own **mu-plugin** into `wp-content/mu-plugins` | ✓ `modules/safe-mode/module.php:97–105` |
| Duplicator | rewrites wp-config.php (`WPConfigTransformer`), mu-plugin, `.htaccess`/`web.config`/`.user.ini`, `popen`, own `mysqli`, DB credentials | `src/Libs/WpConfig/WPConfigTransformer.php:489`, `src/MuPlugin/MuGenerator.php:20`, `src/Libs/Shell/Shell.php:25` |
| UpdraftPlus | `popen`/`proc_open` (mysqldump, zip), DB credentials, `wp-content/maintenance.php`, restores the whole site | `class-updraftplus.php:1813, 1941`, `includes/updraftclone/temporary-clone-restore.php:49` |
| WP File Manager | `exec`/`proc_open` (elFinder), own `mysqli_connect` with DB credentials; by purpose, a full file manager | `lib/php/elFinder.class.php:5331`, `classes/db-backup.php:167` |
| All-in-One WP Migration | export/import runs on `$wpdb->dbh` directly | `lib/vendor/servmask/database/class-ai1wm-database*.php` |

Plus two whose purpose is running PHP the admin writes: **Code Snippets** and **WPCode**
(insert-headers-and-footers) call `eval()` (✓ `php/snippet-ops.php:947`,
`includes/class-wpcode-snippet-execute.php:426`). These *can* run sandboxed, since the eval runs
inside the sandbox, but then every snippet is sandboxed too, which may not be what the admin
wants.

That is **12–14 of 56**, nearly all of them cache, security/firewall, backup/migration or
file-manager plugins. Infrastructure plugins of this kind are best run trusted, or given
narrow capabilities that core performs on their behalf (write `WP_CACHE`, install one known
drop-in), never write access to those files.

**What else the sandbox has to keep out or gate** (plugin counts):

- **Writes.** 2,052 write call sites; **1,844 (90%) have a path the analyzer can't resolve**. Of
  those it can, the targets are uploads (14 plugins), their own folder (6), temp (5), wp-content
  cache/languages (5), and php:// streams (16). 16 plugins trigger core's `.htaccess` write through a
  hard `flush_rewrite_rules()`; read-only core makes that a no-op, which is fine. A sandbox needs
  writable uploads, temp and a cache folder. Everything else, including the plugin's own folder,
  can stay read-only.
- **Processes.** `exec`/`popen`/`proc_open` in own code: UpdraftPlus, Duplicator, SG Optimizer,
  WP File Manager. In bundled code: monolog, google/auth, mixpanel and an LE-ACME test file (Really
  Simple SSL ships `vendor/…/LE_ACME2Tests/AccountTest.php` with `system('rm -R …')`). Bundled
  `eval` is phpseclib, Twig and HTMLPurifier (6 plugins). `disable_functions` in the sandbox costs
  only those four plugins' features.
- **Network.** 48 plugins use `wp_remote_*`, 17 curl, 21 sockets/DNS/FTP, 24 `wp_mail` (26 counting PHP's `mail()`). **85% of
  remote calls in own code (94% in bundled) have a host that isn't a literal**, so an egress
  allowlist can't be generated statically. It has to be learned or approved at run time.
- **Sensitive core calls** (whatever the design, a policy has to gate these): activate/deactivate
  plugins 34 (61%), install/update code through the upgraders 30 (54%), log a user in/out 19
  (34%), create/change users 17 (30%), cron 37 (66%), mail 24 (43%), uploads 12 (21%), switch
  theme 7.
- **Database.** 50 plugins run their own SQL through `$wpdb`, naming core tables (`options` 33,
  `posts` 29, `postmeta` 27, `usermeta` 20, `comments` 16, `users` 11) and creating their own
  (WooCommerce 38 tables, Redirection 8, Jetpack 8, Duplicator 8, …). A read-only WordPress still
  needs the data gateway (parse SQL, check tables) from docs/woocommerce-survey.md cause 6. That
  part doesn't get smaller with either design.
- **URL entry points.** Files that load WordPress themselves bypass any sandbox entered through
  the plugin loader: Really Simple SSL `lets-encrypt/download.php`, `system-status.php`; Complianz
  `system-status.php`; Duplicator's installer. Plus LiteSpeed `guest.vary.php`, which runs with no
  WordPress at all. The web server must refuse direct PHP requests under `wp-content/plugins` except
  for an allowlist. This is independent of the sandbox design.

## 4. How far static analysis can be trusted

| what | own code | bundled code |
| --- | --- | --- |
| function calls with a computed name (`$f()`) | 0.2% (708 / 435,282) | 0.8% |
| method calls with a computed name (`$o->$m()`) | 0.1% | 0.2% |
| static calls with a computed class or name | 0.5% | 1.2% |
| `new $class` | 1.2% | 1.6% |
| `call_user_func*` with a non-literal callable | **79.5%** (455 / 572) | 60.1% |
| includes with a fully dynamic path | **23.1%** (1,210 / 5,248) | 34.0% |
| `add_action`/`add_filter` with a dynamic tag | 4.3% | 5.1% |
| … whose tag resolves only by folding constants / `__FILE__` | 2.4% | 2.4% |
| `do_action`/`apply_filters` with a dynamic tag | 6.5% | 7.9% |
| file writes with an unresolved path | **90%** (1,844 / 2,052, both scopes) | |
| remote calls whose host isn't literal | **84.8%** | 94.0% |

**What these mean.** *Which* functions, classes and constants a plugin names is about 99% static.
So sections 1 and the cause counts are solid lower bounds: dynamic calls can only add to them. *Where*
a plugin writes, *which host* it calls and *which file* an autoloader includes are mostly dynamic.
For those, the static numbers show the shape of the problem but can't serve as a manifest. The
decision between the two designs depends on the first kind of number, so it rests on solid ground.
The second kind argues for run-time policy (grants, egress allowlists) in either design.

**Validation done:**

- **Hand-checked plugins.** Classic Editor (1 file, 1,064 lines) and WPS Hide Login (5 own files)
  were read by hand and compared with their JSON. Globals, core includes and `$wpdb` use matched
  exactly. Two deltas went to the analyzer: a commented-out `add_action` I counted by grep (the
  analyzer was right, 32 not 33), and a `global $current_user` I missed. One delta went to my hand
  reading: `OPTIMIZE TABLE` wasn't in the SQL patterns (fixed).
- **Run-time evidence.** All causes the sweep observed in 15 plugins are predicted (table above).
  Contact Form 7 matches line for line: `class-wp-list-table.php` (`admin/includes/list-table.php:6`),
  `get_option`/`register_post_type` shadowed by its methods (`includes/form-tag.php:64`,
  `includes/contact-form.php:50`), `extends WP_List_Table`, the `load-*` tags, and
  `activate_contact-form-7/wp-contact-form-7.php`, which the analyzer builds from
  `'activate_' . WPCF7_PLUGIN_BASENAME` by folding the constant.
- **Spot checks of surprising findings** (source read, all confirmed unless noted):
  1. WP Fastest Cache rewrites wp-config.php (above).
  2. Jetpack's WAF `require_once`s wp-config.php and connects with the DB password (above).
  3. Elementor's Safe Mode installs an mu-plugin (above).
  4. Really Simple SSL's `download.php` is a URL entry point that loads `wp-load.php` itself (above).
  5. SG Optimizer replaces `advanced-cache.php` and rewrites wp-config.php. The wp-config write is
     a **miss** by the resolver: the path is a class property default (`public $config_file =
     ABSPATH . 'wp-config.php'`), which the resolver doesn't follow. Found through the
     "names the file and writes" heuristic.
  6. Wordfence's `require_once(ABSPATH . WPINC . 'http.php')` (`lib/wfAPI.php:103, 238`) is a real
     missing-slash bug. It sits in a branch that runs only when `wp_remote_post()` doesn't exist,
     which is exactly the situation in today's sandbox.
  7. Site Kit uses `LOGGED_IN_KEY`/`LOGGED_IN_SALT` as its openssl key and salt (above).
  8. LiteSpeed's `guest.vary.php` runs with no WordPress (`require 'lib/guest.cls.php'`, then work).
  9. Wordfence's "names wp-config.php and writes" hits are **false positives**. Those functions
     refuse to delete wp-config.php. UpdraftPlus's are restore code. The heuristic is a pointer, not
     evidence.
  10. Classic Editor #30 (above).
- **Analyzer bugs found and fixed during validation:** the WordPress zip's bundled Akismet and
  themes were indexed as core (excluded `wp-content/`); `noop.php`'s stub functions were mapped as
  the defining file; PHP builtins that core polyfills (`mb_strlen`) and PHP constants core defines
  for old PHP (`ENT_SUBSTITUTE`) were classed as WordPress; a plugin's own copy of a library core
  also ships (sodium_compat, PHPMailer) was classed as core; `php://` streams were mangled by path
  normalization; macOS `._*` files were parsed as PHP.

**Blind spots (what this survey can't see):**

- **Reachability.** A call counts even if it sits in dead code or behind a feature flag. Counts
  are "the code contains", not "a request runs".
- **Calls on core objects** (`$wpdb->get_results`, `$wp_query->is_main_query()`, `WP_Query`
  methods) count as the global/class, not as functions. The function totals undercount the API
  surface a forwarder needs.
- **Class property defaults and return values aren't followed** by the path resolver (the SG
  Optimizer miss). Constants (`define`, `const`, class constants) and `__FILE__`/`__DIR__`,
  `dirname`, `plugin_dir_path`, `trailingslashit`, `sprintf` and `wp_upload_dir()['basedir']` are.
- **Global reads vs writes** are approximate: a write is an assignment to the variable in the
  function that declared it `global`, or to `$GLOBALS['x']`. Writes through references or arrays
  aren't seen.
- **#37 is a lower bound**: only `$this`, `new …` or a variable assigned from `new` in the same
  function, passed to options/transients/meta/cache or a fired hook.
- **"Vendor"** means folder names (`vendor/`, `vendor_prefixed/`, `jetpack_vendor/`,
  `third-party/`, `node_modules/`). WooCommerce's `packages/` (Action Scheduler, blueprint) counts as
  its own code.
- **Entry points:** "runs without WordPress" is an upper bound. It flags unguarded files whose
  top-level code calls anything besides a short list of side-effect-free functions; most such
  files are class files or polyfill bootstraps that do nothing harmful when opened.
- **Only PHP**: JavaScript, REST clients and the admin UI aren't analyzed. **One version** of each
  plugin, and the top-50 list as of 6 Nov 2026.
- **730 function names are unclassified** (not core, Woo, PHP or the plugin's own). They are
  integrations with other plugins, WordPress.com or WP-CLI (`amp_is_available`,
  `WP_CLI\Utils\…`), normally behind `function_exists`.

## 5. Bundled code and PHP versions

37 of 56 plugins bundle third-party code: 16,349 of the 34,155 PHP files analyzed (48%) are bundled.
Common packages: `automattic/jetpack-autoloader` (7 plugins), `woocommerce/action-scheduler` (5,
plus WooCommerce itself), `psr/log` 5, `composer/installers` 5, `symfony/polyfill-mbstring` 4. Several
plugins scope their vendors with php-scoper (`vendor_prefixed/`). Seven bundle their own copy
of the Jetpack autoloader (Elementor, Really Simple SSL, Hostinger, Hostinger Reach, WooCommerce,
WooPayments, WooCommerce Shipping & Tax); its namespaced `get_option()` call is Elementor's
`…\Autoloader\…\get_option()` failure in the sweep (#30). The `Requires PHP` headers: 7.4 for 21 plugins, 7.2 for 4, 7.0 for 3, 8.1 for 3,
8.3 for 1 (Contact Form 7), 5.x for 3, none for 21. Every file parsed on PHP 8.3 with zero parse errors.

## Recommendation

The data favours **a read-only WordPress inside the sandbox** over forwarding calls. The forward
design must reproduce 1,076–1,412 functions, 34–43 object globals and 19–47 base classes, and fix
eight causes, each of which hits most plugins. The read-only design reduces the boundary to:

1. a **sandbox wp-config** with path/debug constants, no `DB_*`, and per-plugin substitute
   keys/salts (with a one-time re-encrypt for plugins that already encrypted data with the real
   keys);
2. **`$wpdb` as a gateway** subclass with no connection (SQL parsed, tables checked);
3. the **~15 salted pluggables** (`wp_create_nonce`, `wp_verify_nonce`, `wp_hash`, `wp_salt`, auth
   cookie functions) defined in the sandbox as forwarders to core;
4. **writable** uploads, temp and cache folders only, everything else read-only; `disable_functions`
   for `exec`-family calls; egress through a run-time allowlist;
5. **policy on the sensitive core calls** (plugins, upgraders, users, auth cookies, cron, mail),
   which in a read-only WordPress run locally and must be intercepted (a `pre_*` filter where core
   has one, a forwarder for pluggables, a grant check for the rest);
6. outside the sandbox: the web server **refuses direct PHP requests** under wp-content/plugins,
   and the 12–14 infrastructure plugins in section 3 stay trusted.

How the sandbox's read-only WordPress gets its state (options, the current user, the request)
without a database connection is the next design question. It is the gateway in point 2 with a
cache in front, and it is the same work the forward design needs for `$wpdb` anyway.

## Reproduce

```
DOCKER_CONTEXT=colima research/plugin-survey/run.sh          # ~2 minutes after the first download
DOCKER_CONTEXT=colima research/plugin-survey/run.sh --fresh  # delete downloads and start over
DOCKER_CONTEXT=colima research/plugin-survey/run.sh --only classic-editor,wps-hide-login
```

`fetch.sh` reads the plugins API (`browse=popular`, 250 per page), takes the top 51 (WooCommerce
is in the top 50, so 50 others plus WooCommerce), adds the five most-installed plugins that declare
`Requires Plugins: woocommerce` (Google for WooCommerce, WooPayments, PayPal Payments, Stripe,
WooCommerce Shipping & Tax), and downloads each zip and WordPress `latest.zip`, one at a time with a
2-second pause. `index.php` extracts WordPress's and WooCommerce's functions, classes, constants,
globals and fired hooks. `analyze.php` analyzes one plugin, `aggregate.php` writes
`results/aggregate.json` and `results/tables.md`. PHP-Parser 5.9.0 is pinned by `composer.lock`. Downloads
live in `.tmp/survey` (git-ignored); the work runs in a throwaway `php:8.3-cli` container fed by
`docker cp`/tar, because the Colima VM on this iMac doesn't share `/Volumes`.
