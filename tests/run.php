<?php

require __DIR__ . '/bootstrap.php';

foreach (glob(__DIR__ . '/test_*.php') as $file) {
    echo "== " . basename($file) . " ==\n";
    require $file;
}

global $failures;
if ($failures > 0) {
    fwrite(STDERR, "{$failures} failure(s)\n");
    exit(1);
}
echo "all pass\n";
exit(0);
