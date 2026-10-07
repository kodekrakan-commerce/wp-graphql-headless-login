<?php
declare(strict_types=1);
$mode = $argv[1] ?? 'roundtrip';
if ($mode === 'roundtrip') {
    fwrite(STDOUT, json_encode(['args' => array_slice($argv, 2), 'cwd' => getcwd(), 'env' => getenv('HEADLESS_CHILD_VALUE')], JSON_THROW_ON_ERROR | JSON_UNESCAPED_UNICODE));
    fwrite(STDERR, 'controlled stderr');
} elseif ($mode === 'exit') {
    fwrite(STDERR, 'controlled failure');
    exit(7);
} elseif ($mode === 'wait') {
    usleep(2000000);
} else {
    throw new RuntimeException('Unknown controlled child mode.');
}
