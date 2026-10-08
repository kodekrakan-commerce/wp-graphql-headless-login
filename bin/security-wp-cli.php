#!/usr/bin/env php
<?php
declare(strict_types=1);
// Pass this exact reviewed PHP launcher as CliProcess constructor argument six.
require dirname(__DIR__) . '/tests/source-closure/wp-cli-boundary.php';
headless_cli_boundary(getcwd(), array_slice($argv, 1), [
    'WP_CLI_REQUIRE' => getenv('WP_CLI_REQUIRE'),
    'WP_CLI_EARLY_REQUIRE' => getenv('WP_CLI_EARLY_REQUIRE'),
    'WP_CLI_CONFIG_PATH' => getenv('WP_CLI_CONFIG_PATH'),
]);
require dirname(__DIR__) . '/tests/source-closure/admission.php';
headless_source_closure_admission();
putenv('WP_CLI_CONFIG_PATH=' . dirname(__DIR__) . '/tests/source-closure/empty-wp-cli.yml');
putenv('WP_CLI_PACKAGES_DIR=' . getcwd() . '/packages-disabled');
require dirname(__DIR__) . '/vendor/wp-cli/wp-cli/php/boot-fs.php';
