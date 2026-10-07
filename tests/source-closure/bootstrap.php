<?php
declare(strict_types=1);
require __DIR__ . '/admission.php';
headless_source_closure_admission();
require dirname(__DIR__, 2) . '/vendor/autoload.php';

foreach (['str_contains', 'str_starts_with', 'str_ends_with'] as $function) {
    if (!(new ReflectionFunction($function))->isInternal()) {
        throw new RuntimeException('Native PHP string function replaced: ' . $function);
    }
}
foreach (['str_icontains', 'str_istarts_with', 'str_iends_with'] as $removed) {
    if (function_exists($removed)) {
        throw new RuntimeException('Removed non-native helper remains loaded: ' . $removed);
    }
}
