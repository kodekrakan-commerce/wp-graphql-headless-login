# Headless-owned WP-CLI development bundle

Identity: `kodekrakan-commerce/headless-wp-cli-bundle`, `dev-codex-headless-source-closure`.
This metapackage adapts upstream `wp-cli/wp-cli-bundle v2.12.0`, source
`d639a3dab65f4b935b21c61ea3662bf3258a03a5`. `UPSTREAM-COMPOSER.json` and the MIT license
retain its baseline. Every framework and default-command requirement is preserved.
The owned PHP floor is 8.2; the only command-graph change removes the obsolete
`wp-cli/process:5.9.99` fork and adds genuine `symfony/process:5.4.51`
(`467bfc56f18f5ef6d5ccb09324d7e988c1c0a98f`). No Process code, PHAR, autoloader or
upstream build scripts are copied here.

Use the Headless canonical root lock after separate review and installation admission.
The package is mirrored from a relative path repository, never symlinked or assigned
an official upstream version/replace alias. The parent source manifest binds all files
and modes; path `reference:config` alone does not bind source bytes. Query advisories
under both owned and upstream identities at each build and before final admission;
review every command dependency under its original identity. Recheck supported
upstream releases and return to a qualified official successor when suitable.

Tests use the explicit reviewed `bin/security-wp-cli.php` source launcher and the
canonical installed framework/default commands. No existing or floating WP-CLI PHAR
is admitted. wp-browser's shell factory has a separate download path and remains a
consumer gate. This is development-only source and must be excluded from every
runtime archive; see `tests/source-closure/README.md`.
