<?php
declare(strict_types=1);

/** Pure owned refusal seam: no admission, config parsing, target include or vendor load. */
function headless_cli_boundary(string $cwd, array $arguments, array $environment): void {
    if (!in_array($arguments, [['--info'], ['cli', 'info'], ['cli', 'version'], ['cli', 'cmd-dump']], true) || !is_dir($cwd) || count(scandir($cwd)) !== 2) {
        throw new RuntimeException('Only diagnostic commands in an empty non-WordPress directory are admitted.');
    }
    foreach (['WP_CLI_REQUIRE', 'WP_CLI_EARLY_REQUIRE', 'WP_CLI_CONFIG_PATH'] as $name) {
        if (isset($environment[$name]) && $environment[$name] !== false && $environment[$name] !== '') { throw new RuntimeException('Ambient WP-CLI require/config input: ' . $name); }
    }
    for ($path = $cwd; ; $path = dirname($path)) {
        if (is_link($path)) { throw new RuntimeException('Symlinked CLI working directory/ancestor.'); }
        foreach (['wp-cli.yml', 'wp-cli.local.yml'] as $name) {
            $config = $path . DIRECTORY_SEPARATOR . $name;
            if (file_exists($config) || is_link($config)) { throw new RuntimeException('Ancestor WP-CLI project config is not admitted: ' . $config); }
        }
        if (dirname($path) === $path) { break; }
    }
}
