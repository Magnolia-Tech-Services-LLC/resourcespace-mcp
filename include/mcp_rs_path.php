<?php

function mcp_rs_include_dir(string $start): string
{
    $dir = $start;
    for ($i = 0; $i < 8; $i++) {
        $parent = dirname($dir);
        if ($parent === $dir) {
            break;
        }
        $dir = $parent;
        if (is_file($dir . '/include/boot.php')) {
            return $dir . '/include';
        }
    }
    return dirname($start, 3) . '/include';
}
