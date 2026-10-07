# Source-closure acceptance for the owned development packages

This source preview has no accepted new lock or installed development graph. PHP
tests below are prepared and unrun. Only owned Python source validators/negative
controls, PHP syntax checks, and plainly labelled owned filesystem/refusal seams
may run at this milestone. A later successful solve
alone does not admit execution.

Before a reviewed solve/install/build, run `bin/verify-source-closure.py` from an
ordinary clean checkout. It checks exact package membership, hashes, modes,
licenses, copied testcase source bytes, owned identities, the preserved command
map and the narrow root delta. Track every file. Verify the sorted manifest again
against the resulting owning source commit and lock; Composer path config references
are not content hashes. Run source controls with explicit immutable official Process
archive and old-fork source paths (both read only):

```sh
PYTHONDONTWRITEBYTECODE=1 HEADLESS_OFFICIAL_PROCESS_ARCHIVE=/absolute/verified/source.zip HEADLESS_OLD_PROCESS_FILE=/absolute/f0aec5ca/Process.php python3 tests/source-closure/source_gate_controls.py
PYTHONDONTWRITEBYTECODE=1 HEADLESS_SOURCE_CONTROL_PHP=/absolute/reviewed/host/php HEADLESS_OFFICIAL_PROCESS_ARCHIVE=/absolute/verified/source.zip python3 tests/source-closure/guard_review_controls.py
```

Controls prove changed/copied/unlisted/symlinked source, helper callable consumers,
old/falsely labelled Process source and dev-source archive leaks are rejected without
executing PHP from those inputs. The complete official Process PHP source-family
manifest is bound to `467bfc56...`; all 17 non-test PHP files must match before
autoload. This is a source identity check, not a substitute for real behavior tests.
The additional review controls use inert entrypoint fixtures and mocked dispatch;
the host PHP seams execute only owned inventory functions and launcher refusals.
No vendor PHP, selected harness suite or unreviewed config require target executes.

After separately reviewed lock/install/admission, scan every development PHP file
and autoload/callable string with `--vendor /absolute/vendor`. Review every returned
removed-API candidate in context: unrelated Console `getOptions` is not a Process
failure, while a real removed method/class user cannot be suppressed. Bind each
disposition to its file hash in the installed admission receipt. Verify the mirrored
owned testcase package exactly matches its tracked files. Exactly one Symfony
Process namespace provider may survive; old fork/helper/root identities are rejected.

The future runner is `bin/run-source-closure-tests.py --admission /absolute/receipt.json`.
The independently reviewed receipt schema is
`headless-source-closure-installed-admission/v1`; it must supply `php_version`
exactly `8.2.34`, exact absolute `php_binary`, `php_binary_sha256`, and complete
`source_hashes` for root composer.json/lock, all dependency-source metadata/content,
and every root Composer autoload/autoload-dev input outside vendor (including
access-functions.php, src, vendor-prefixed and the helper classmap). It also binds
complete `vendor_files` path-to-SHA256 inventory, complete `harness_files`, and
`removed_api_review` path-to-`{sha256, disposition}`. It may only be issued after the
actual full graph, source manifests, source commit, advisory/copy and install gates
are accepted. This preview deliberately provides no receipt pretending those gates
passed. The Python runner independently derives complete source/vendor/harness
membership and validates every hash/schema/disposition before any process dispatch.
Mandatory vendor bindings include PHPUnit's entrypoint, autoload.php, installed.json
and Process.php. Mandatory harness bindings include all three owned bin entrypoints
and every file under tests/source-closure: config, tests, controls, fixtures and guards.
Root, ancestor and descendant symlinks are refused before inventory traversal/read.
The first dispatch executes only the bound PHP binary and an owned version expression;
vendor PHPUnit is reached only after all guards and the actual version check pass.
PHP defense-in-depth repeats complete inventories and executable identity checks.
PHP bootstrap refuses changed files, symlinks, another PHP version/binary,
non-native replacements of native strings, or the removed helper globals.
The launcher first rejects wp-cli.yml and wp-cli.local.yml at the working directory
and every ancestor, and refuses ambient WP_CLI_REQUIRE, WP_CLI_EARLY_REQUIRE and
WP_CLI_CONFIG_PATH. This happens before admission or vendor boot. It then overrides
global config/package discovery with the bound empty YAML configuration and a
nonexistent package directory inside the empty fixture working directory.
The static helper and removed-API scans preserve line boundaries, comments, strings
and heredocs, and compare PHP identifiers/callables/classes/methods case-insensitively.
They report conservative raw literal candidates requiring contextual classification;
no-candidate output is not proof of lexical or dynamic-call absence.

The genuine PHP 8.2.34 offline suite exercises:

- Process array/shell construction, upstream escaping vectors, empty/Unicode/quoted
  arguments, cwd/env, stdout/stderr, nonzero exit, timeout and cleanup.
- Composer ProcessExecutor array/shell synchronous and asynchronous settlement.
- wp-browser adapter start-time/factory/stop and WorkerProcess stream reflection.
- WebDriver's real private construction method without starting a browser.
- WP-CLI source launcher/CLI version/default command registration in an empty
  non-WordPress directory, using explicit constructor argument six for CliProcess.
- Genuine QueryConstraint/Successful/Error envelopes, FIELD/OBJECT/NODE/EDGE and
  negation rules, error path/message/invalid rules, failure details, logger events,
  and native STARTS/ENDS matching/nonmatching/empty/case/multibyte vectors.
- A deliberately wrong PHPUnit assertion must return exit1 and FAILURE output;
  a startup failure is not accepted as assertion propagation.

Concrete consumer gates remain. The adapter forwards a sixth options argument to a
five-parameter genuine parent. The prepared non-default option assertion exposes
possible ignored options and may fail; classify actual full-graph uses before
acceptance, then review a separate adapter fix if required. Its createNewConsole
reflection/destructor Windows option path remains Windows-specific and unrun.
CliProcess::fromShellCommandline always selects a floating PHAR even when callers
otherwise use a custom bin; never execute that path until actual consumers are
classified and a reviewed no-download path exists. Constructor injection does not
fix that factory. Numeric ERROR_PATH rules require real WordPress `absint`; the
offline fixture covers nonnumeric paths, and numeric/WordPress testcase-parent
semantics require the later separately admitted synthetic WordPress boundary.
The copied WPGraphQL testcase parents still extend `Codeception\TestCase\WPTestCase`
and `WP_UnitTestCase`; their real alias/parent loading is a future native/runner gate,
not established by the offline QueryConstraint tests or syntax parsing.

Use only exact reviewed executable paths; do not call floating `composer:v2`,
`wp-cli`, wp-browser's download fallback, package-root scripts, in-test Composer
require/install, or coverage bootstrap/downloads. The custom launcher is a reviewed
PHP file, not the upstream shell wrapper that chooses PHP from PATH. Record its
path/hash and actual class defining paths. The diagnostic allowlist permits only
`--info`, `cli info`, `cli version`, `cli cmd-dump` in an empty directory, with no
ambient require/early-require/config input or ancestor project config.
No WordPress/site/database/browser/provider
activation follows from this suite.

Windows is a separate required lane. Retained upstream test source/provenance and
the exact fixed Process archive are immediate source evidence. Run
`WindowsProcessSecurityTest.php` with the same complete pre-entrypoint inventory
admission and bound PHPUnit/bootstrap on an
explicitly admitted Windows/Git Bash/MSYS2 PHP 8.2.34 environment. Its sentinel test
fails if Windows/MSYSTEM admission is absent; the offline POSIX suite neither runs
it nor claims it passed. Also run all upstream escaping vectors on that lane; do
not count an upstream markTestSkipped result as Windows behavioral qualification.

Root archive.exclude explicitly contains `/build/dependency-sources`. Before any
runtime packaging acceptance, run the static archive-membership gate with
`--archive /absolute/distribution.zip` and prove no owned package, WP-CLI/Process,
testcase/helper or dependency-source bytes leaked. No archive/build is run in this
preview. Later auth/provider/refresh/issuer/horizon and rebuilt source-profile/native
qualification remain independent; frozen official-asset receipts retain their inputs.
