<?php
// The microVM's snapshot warm-up (addiscorp/securecore#71): reads every .php file under the
// site root (SC_WARM_ROOT, from the host's FastCGI request) into the guest's page cache, so the
// snapshot holds them. It compiles and runs none of them: no WordPress request is made, so
// nothing touches the database (the VM being warmed has no way to it anyway), and opcache is not
// filled with files compiled out of context (opcache_compile_file over a whole WordPress tree
// declares functions as it goes and caches classes whose traits aren't bound yet: Contact Form
// 7 then fails with "Trait not found"). Lives in the guest root image, never reachable by URL.
header('Content-Type: text/plain');
$root = (string) ($_SERVER['SC_WARM_ROOT'] ?? '');
if ($root === '' || !is_dir($root)) {
    echo "read=0 (no root)\n";
    return;
}
$n = 0;
$bytes = 0;
// CATCH_GET_CHILD: folders php-fpm can't read (the site disk's lost+found) are skipped.
$it = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::LEAVES_ONLY,
    RecursiveIteratorIterator::CATCH_GET_CHILD
);
foreach ($it as $file) {
    if ($file->isFile() && substr($file->getFilename(), -4) === '.php') {
        $s = @file_get_contents($file->getPathname());
        if ($s !== false) {
            $n++;
            $bytes += strlen($s);
        }
    }
}
echo "read=$n bytes=$bytes\n";
