# Headless-owned PHP 8.2 GraphQL testcase

Identity: `kodekrakan-commerce/headless-graphql-testcase`,
`dev-codex-headless-source-closure`. All 12 `src/` files and the MIT license are
unchanged bytes from upstream `wp-graphql/wp-graphql-testcase v3.4.0`, source
`572d4c51e9a0a33ec1b99970155fe005f468f4ec`. Namespace `Tests\WPGraphQL\`, PSR-4 and
the `src/` classmap remain unchanged. `UPSTREAM-COMPOSER.json` retains the baseline;
the owned manifest declares PHP >=8.2 and explicitly omits the abandoned helper.
No case-insensitive helper API is copied, aliased or represented as native PHP.

The inspected upstream and Headless sources use the native case-sensitive string
functions only. That static finding is the removal rationale, not whole-graph proof:
scan the complete installed development graph/autoload/callable references and run
the genuine constraint tests before acceptance. An injected case-insensitive helper
consumer must fail the closure gate. If a real consumer appears, stop removal for an
owning consumer migration or namespaced compatibility decision.

The upstream suggested prerequisites remain documented in
`../advisory-source-mappings.json`: Codeception asserts/universalframework, Guzzle,
wp-browser, PHPUnit, WP PHPUnit and Yoast polyfills where their testcase parents
need them. Headless supplies its actual admitted graph; this adaptation does not
assert those suggestions are all installed or qualified. Do not run the historical
package-root Docker/WordPress/bootstrap scripts or their separate dev graph.

The Headless owner maintains this adaptation locally. Query both original and owned
advisory identities and recheck upstream releases/support at each build and final
admission. No active upstream support guarantee was established by its non-archived
repository. Return to a suitable qualified official successor when available. The
source manifest binds copied bytes/modes before solve/install/test/package; install
must mirror and match them. This package never belongs in a runtime archive.
