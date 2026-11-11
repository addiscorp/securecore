<?php
// The WordPress front page, timed inside PHP (addiscorp/securecore#70, bench.sh breakdown): the
// X-SC-PHP-MS header is the wall time from here to the end of WordPress's output, so the rest of
// a request's time is FastCGI and the bridge. ?big=N instead answers N bytes of plain text with
// no WordPress at all: the transport alone. Copied into the bench site only.
$t = hrtime(true);
if (isset($_GET['big'])) {
    header('Content-Type: text/plain');
    echo str_repeat('x', (int) $_GET['big']);
    exit;
}
// WordPress routes on these: make it the request for /.
$_SERVER['REQUEST_URI'] = '/';
$_SERVER['SCRIPT_NAME'] = $_SERVER['PHP_SELF'] = '/index.php';
$_SERVER['SCRIPT_FILENAME'] = __DIR__ . '/index.php';
ob_start();
define('WP_USE_THEMES', true);
require __DIR__ . '/wp-blog-header.php';
$out = ob_get_clean();
header(sprintf('X-SC-PHP-MS: %.2f', (hrtime(true) - $t) / 1e6));
echo $out;
