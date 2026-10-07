# Tagged checker qualification — prepared, unrun

Use only separately admitted PHP8.2.34 and exact PHPCS3.13.6/checker sources. Before
the PHPCS entrypoint, `validate_admission` and `checker_installed_gate` must bind
all source/harness/vendor members, hashes, modes, bytes and the four exact tagged
refs. Pending Git/tag/tree proof blocks execution. No Composer installer plugin,
project script, auto-fixer, global config write or download is admitted here.

Register each actual standard path explicitly in a private reviewed PHPCS config;
prove discovery of WPGraphQL, all six AxePress rulesets, PHPCompatibilityWP,
PHPCompatibility and both Paragonie standards. Record the complete `phpcs -e`
sniff registry. Registration/CLI spelling must be verified against admitted3.13.6
before execution; a missing standard or silently reduced registry fails admission.

Run actual PHPCS with JSON reports, warnings enabled, severity1, extensionsphp and
an explicit target; never manufacture checker reports. The small fixture matrix:

| Input / real standard | Target | Required result |
| --- | --- | --- |
| php82-positive.php / PHPCompatibility | 8.2 | zero compatibility errors/warnings |
| php82-positive.php / PHPCompatibility | 8.1 | Classes.NewReadonlyClasses.Found at line2, FunctionDeclarations.NewParamTypeDeclarations.DNFTypeFound and NewReturnTypeDeclarations.DNFTypeFound at line5; all ERROR with independently source-reviewed PHPCS severity, nonzero |
| removed-deprecated.php / PHPCompatibilityWP | 8.2 | utf8_encode deprecation, each removal, dollar-brace interpolation deprecation; exact emitted codes/types/severities and nonzero |
| php83-negative.php / PHPCompatibility | 8.2 | Classes.NewTypedConstants.Found error, nonzero |
| wp-polyfill.php / PHPCompatibility | synthetic7.4 | str_contains newer-feature plus each deprecation |
| wp-polyfill.php / PHPCompatibilityWP | synthetic7.4 | str_contains WP polyfill exception, retain each diagnostic |

The8.3 literal is derived from tagged NewTypedConstantsStandard.xml, retained with
its exact source/member hash in fixtures-provenance.json; fixtures are checker
input text and never required/executed as PHP. Targets8.1/7.4 are negative controls,
not deployment targets. Keep existing primary exclusions/rules/severity unchanged;
only `.phpcs.xml.dist` testVersion changes7.4-→8.2. Its included source files remain
access-functions.php, plugin entrypoint, activation/deactivation and src/.

Run the complete inherited primary scan uncached (`--no-cache`) first. In a bounded
disposable copy of included src, append one `each([])` call to an included source
file and require the full configured scan to fail with RemovedFunctions.eachFound
and a path in src; a startup failure is not the expected diagnostic. Remove only
that disposable copy. Also put defects in excluded vendor/tool fixture paths and
prove exclusion does not mask the seeded src failure. Do not auto-fix unrelated
style findings from AxePress2.1.0; classify them explicitly.

Repeat fixture matrix and full source scan with private fresh cache, then cached
repeat; compare exact path/code/type/severity sets and exit behavior with uncached
reports. A stale green cache fails. Record source/ref/registry/PHP/binary paths and
production archive/autoloader exclusion of all checker/dev packages. These are
required genuine later controls, not results claimed by source-only guard tests.

The future selected PHPCS registration JSON must live under tests/source-closure/checker, be present in the complete admitted harness inventory and match its exact hash before any dispatch. A changed/unbound registration or truthy non-boolean source-verification field is refused. The current preview issues no such genuine registration/admission.

## Review corrections: fail closed before checker execution

Both activation.php and deactivation.php are mandatory complete source-hash inputs
in Python and PHP. Inert changes or missing lifecycle files refuse before dispatch.

The runner also requires `--expected-roster` pointing to a independently
SOURCE-reviewed JSON under this checker harness directory. Its complete membership
and hash must be bound in the independently reviewed installed admission. Schema:
`headless-checker-source-expected-roster/v1`. Required strict boolean fields are
`source_reviewed`, `cli_registry_parser_source_verified`, and
`diagnostic_contract_source_reviewed`, all true. `source_hashes` and `vendor_files`
must exactly equal the complete installed admission maps, including primary XML,
all inherited rulesets/sniff/engine sources and configured exclusions. The sorted,
unique three-part `expected_sniffs` list and its `expected_sniffs_sha256` (SHA256 of
sorted identifiers joined by newlines plus final newline) must be derived from
those inspected source declarations/configuration and independently reviewed.
They must never be populated from this runner's discovery/registry output.

`fixture_sha256` binds unchanged php82-positive.php. `php81_error_severity` is a
strict integer1–10 established from the exact admitted PHPCS engine/error/config
source. The held compatibility sniffs call addError without a severity override;
they establish exact ERROR codes, not a currently executed engine severity.
No populated genuine roster/parser/severity proof exists in this preview. Missing
or unbound proof refuses before even the owned PHP version probe or vendor PHP.
Do not describe this source requirement as a genuine registration/registry result.

Discovery parses individual standard identifiers and requires exact membership
of all ten named standards, including base WPGraphQL. The actual inherited -e
registry must equal the independent expected sniff set: missing, extra, duplicate
or a single compatibility sniff refuses. The CLI output parser spelling itself
requires source review against exactPHPCS3.13.6 before genuine use.

For the8.1 fixture every cache mode must contain all three exact source-derived
readonly/parameter-DNF/return-DNF errors at the intended file/lines, each ERROR
with the bound engine severity. Readonly alone, either missing DNF diagnostic,
a wrong location/type/severity all fail. Native owned controls use plainly labelled
synthetic reports/expectations; they establish validator refusal only. The8.2
positive and all other genuine fixture/full-source/cache cases stay prepared UNRUN.
