<?php
declare(strict_types=1);

/** Owned defense-in-depth: data/filesystem checks only; never loads vendor or WordPress. */
function headless_reject_symlink_path(string $path): void {
    for ($entry = $path; ; $entry = dirname($entry)) {
        if (is_link($entry)) { throw new RuntimeException('Symlink root/ancestor is not admitted: ' . $entry); }
        if (dirname($entry) === $entry) { break; }
    }
}
function headless_inventory(string $directory): array {
    headless_reject_symlink_path($directory);
    if (!is_dir($directory)) { throw new RuntimeException('Missing inventory root: ' . $directory); }
    $result = [];
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST) as $file) {
        headless_reject_symlink_path($file->getPathname());
        if ($file->isFile()) {
            $relative = str_replace('\\', '/', substr($file->getPathname(), strlen($directory) + 1));
            $result[$relative] = hash_file('sha256', $file->getPathname());
        } elseif (!$file->isDir()) { throw new RuntimeException('Nonregular inventory input: ' . $file->getPathname()); }
    }
    ksort($result);
    return $result;
}
function headless_relative_key($path): string {
    if (!is_string($path) || $path === '' || str_contains($path, '\\') || str_starts_with($path, '/') || array_intersect(explode('/', $path), ['', '.', '..'])) { throw new RuntimeException('Unsafe admission relative path.'); }
    return $path;
}
function headless_hash_map($map): array {
    if (!is_array($map) || !$map) { throw new RuntimeException('Missing complete admission inventory.'); }
    foreach ($map as $path => $hash) {
        headless_relative_key($path);
        if (!is_string($hash) || !preg_match('/^[0-9a-f]{64}$/D', $hash)) { throw new RuntimeException('Invalid admission hash.'); }
    }
    ksort($map);
    return $map;
}
function headless_source_inputs(string $root): array {
    $result = [];
    foreach (['composer.json', 'composer.lock'] as $name) {
        headless_reject_symlink_path($root . '/' . $name);
        $result[$name] = hash_file('sha256', $root . '/' . $name);
    }
    foreach (headless_inventory($root . '/build/dependency-sources') as $name => $hash) { $result['build/dependency-sources/' . $name] = $hash; }
    $composer = json_decode(file_get_contents($root . '/composer.json'), true, 512, JSON_THROW_ON_ERROR);
    $paths = ['access-functions.php'];
    foreach (['autoload', 'autoload-dev'] as $section) {
        $config = $composer[$section] ?? [];
        $paths = array_merge($paths, $config['files'] ?? [], $config['classmap'] ?? []);
        foreach (['psr-4', 'psr-0'] as $mapping) {
            foreach ($config[$mapping] ?? [] as $value) { $paths = array_merge($paths, is_array($value) ? $value : [$value]); }
        }
    }
    foreach (array_unique($paths) as $path) {
        $path = headless_relative_key(rtrim($path, '/'));
        headless_reject_symlink_path($root . '/' . $path);
        if (is_dir($root . '/' . $path)) {
            foreach (headless_inventory($root . '/' . $path) as $name => $hash) { $result[$path . '/' . $name] = $hash; }
        } elseif (is_file($root . '/' . $path)) { $result[$path] = hash_file('sha256', $root . '/' . $path); }
        else { throw new RuntimeException('Missing root autoload input: ' . $path); }
    }
    ksort($result);
    return $result;
}
function headless_harness_inputs(string $root): array {
    $result = [];
    foreach (['bin/run-source-closure-tests.py', 'bin/verify-source-closure.py', 'bin/security-wp-cli.php'] as $name) {
        headless_reject_symlink_path($root . '/' . $name);
        $result[$name] = hash_file('sha256', $root . '/' . $name);
    }
    foreach (headless_inventory($root . '/tests/source-closure') as $name => $hash) { $result['tests/source-closure/' . $name] = $hash; }
    ksort($result);
    return $result;
}
function headless_source_closure_admission(): array {
    $root = dirname(__DIR__, 2);
    headless_reject_symlink_path($root);
    $receipt = getenv('HEADLESS_CLOSURE_ADMISSION');
    if (!$receipt || !is_file($receipt)) { throw new RuntimeException('Explicit independently reviewed complete installed admission required.'); }
    headless_reject_symlink_path($receipt);
    $admission = json_decode(file_get_contents($receipt), true, 512, JSON_THROW_ON_ERROR);
    foreach (['schema', 'php_version', 'php_binary', 'php_binary_sha256', 'source_hashes', 'harness_files', 'vendor_files', 'removed_api_review'] as $field) {
        if (!is_array($admission) || !array_key_exists($field, $admission)) { throw new RuntimeException('Incomplete admission schema.'); }
    }
    if ($admission['schema'] !== 'headless-source-closure-installed-admission/v1' || $admission['php_version'] !== '8.2.34') { throw new RuntimeException('Invalid admission schema/PHP version.'); }
    foreach (['source_hashes' => headless_source_inputs($root), 'harness_files' => headless_harness_inputs($root), 'vendor_files' => headless_inventory($root . '/vendor')] as $field => $actual) {
        if ($actual !== headless_hash_map($admission[$field])) { throw new RuntimeException('Admission membership/hash mismatch: ' . $field); }
    }
    foreach (['autoload.php', 'composer/installed.json', 'phpunit/phpunit/phpunit', 'symfony/process/Process.php'] as $name) {
        if (!isset($admission['vendor_files'][$name])) { throw new RuntimeException('Missing mandatory vendor entrypoint binding.'); }
    }
    if (!is_string($admission['php_binary']) || !preg_match('~^(?:/|[A-Za-z]:[\\\\/])~', $admission['php_binary']) || !is_string($admission['php_binary_sha256']) || !preg_match('/^[0-9a-f]{64}$/D', $admission['php_binary_sha256'])) { throw new RuntimeException('Exact admitted PHP path/hash required.'); }
    headless_reject_symlink_path($admission['php_binary']);
    if (realpath(PHP_BINARY) !== realpath($admission['php_binary']) || PHP_VERSION !== '8.2.34' || hash_file('sha256', PHP_BINARY) !== $admission['php_binary_sha256']) { throw new RuntimeException('Actual admitted PHP executable/version differs.'); }
    if (!is_array($admission['removed_api_review'])) { throw new RuntimeException('Invalid API review.'); }
    foreach ($admission['removed_api_review'] as $name => $record) {
        headless_relative_key($name);
        if (!isset($admission['vendor_files'][$name]) || !is_array($record) || ($record['sha256'] ?? null) !== $admission['vendor_files'][$name] || !is_string($record['disposition'] ?? null) || trim($record['disposition']) === '') { throw new RuntimeException('Invalid API disposition.'); }
    }
    return $admission;
}
