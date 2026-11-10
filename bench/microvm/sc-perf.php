<?php
// Splits a page's cost for the microVM comparison (addiscorp/securecore#68, bench.sh perf): MySQL
// round trips (200 x SELECT 1 on one connection) and pure PHP CPU (a 2M-step loop), timed inside
// PHP, so nginx, FastCGI and the vsock bridge are not in either number. Needs the extension off
// (the vault hides the DB password from PHP otherwise). Copied into the bench site only.
header('Content-Type: text/plain');
$host = getenv('WORDPRESS_DB_HOST') ?: 'db';
$port = 3306;
if (str_contains($host, ':')) {
    [$host, $port] = explode(':', $host, 2);
}
$t = hrtime(true);
$m = new mysqli($host, getenv('WORDPRESS_DB_USER'), getenv('WORDPRESS_DB_PASSWORD'), getenv('WORDPRESS_DB_NAME'), (int) $port);
$connect = (hrtime(true) - $t) / 1e6;
$t = hrtime(true);
for ($i = 0; $i < 200; $i++) {
    $m->query('SELECT 1')->free();
}
$q = (hrtime(true) - $t) / 1e6 / 200;
$t = hrtime(true);
$x = 0;
for ($i = 0; $i < 2000000; $i++) {
    $x += $i % 7;
}
$cpu = (hrtime(true) - $t) / 1e6;
printf("connect_ms=%.3f query_ms=%.4f cpu_ms=%.2f\n", $connect, $q, $cpu);
