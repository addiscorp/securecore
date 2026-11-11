<?php
// The microVM's snapshot warm-up (addiscorp/securecore#71): compiles every .php file under the
// site root (SC_WARM_ROOT, from the host's FastCGI request) into opcache, and runs none of them.
// No WordPress request is made, so nothing touches the database; the VM being warmed has no
// way to it anyway. Lives in the guest root image, outside the site, never reachable by URL.
header('Content-Type: text/plain');
$root = (string) ($_SERVER['SC_WARM_ROOT'] ?? '');
if ($root === '' || !is_dir($root) || !function_exists('opcache_compile_file')) {
    echo "compiled=0 (no root or no opcache)\n";
    return;
}
$n = 0;
// CATCH_GET_CHILD: folders php-fpm can't read (the site disk's lost+found) are skipped.
$it = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::LEAVES_ONLY,
    RecursiveIteratorIterator::CATCH_GET_CHILD
);
foreach ($it as $file) {
    if ($file->isFile() && substr($file->getFilename(), -4) === '.php' && @opcache_compile_file($file->getPathname())) {
        $n++;
    }
}
echo "compiled=$n\n";
