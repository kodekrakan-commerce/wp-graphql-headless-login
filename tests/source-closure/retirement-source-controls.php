<?php
/** SOURCE-ONLY native seam. Stand-in base/error declarations; no real GraphQL/OAuth/WP/vendor. */
namespace GraphQL\Error { class UserError extends \RuntimeException {} }
namespace WPGraphQL\Login\Auth\ProviderConfig\OAuth2 { class OAuth2Config {} }
namespace {
	function esc_html__( $text, $domain ): string { return $text; }
	function __( $text, $domain ): string { return $text; }
	function apply_filters( ...$arguments ) { throw new \RuntimeException( 'Unexpected registry/filter boundary.' ); }
	function is_user_logged_in() { throw new \RuntimeException( 'Unexpected user lookup/effect boundary.' ); }
	$root = dirname( __DIR__, 2 );
	require $root . '/src/Auth/ProviderConfig/OAuth2/Instagram.php';
	require $root . '/src/Auth/Client.php';
	require $root . '/src/Auth/Auth.php';
	require $root . '/src/Auth/ProviderRegistry.php';
	spl_autoload_register( static function ( $class ): void { throw new \RuntimeException( 'Unexpected external autoload: ' . $class ); } );
	$metadata = new \ReflectionClass( \WPGraphQL\Login\Auth\ProviderConfig\OAuth2\Instagram::class );
	$inert = $metadata->newInstanceWithoutConstructor();
	$registry = ( new \ReflectionClass( \WPGraphQL\Login\Auth\ProviderRegistry::class ) )->newInstanceWithoutConstructor();
	$members = $registry->get_providers();
	$metadataProperty = new \ReflectionProperty( $registry, 'providers' );
	$metadataProperty->setValue( $registry, [ 'filtered-alias' => $inert ] );
	$cases = [
		'constructor' => static fn () => new \WPGraphQL\Login\Auth\ProviderConfig\OAuth2\Instagram(),
		'client-before-registry' => static fn () => new \WPGraphQL\Login\Auth\Client( 'instagram' ),
		'login-before-user/session/token' => static fn () => \WPGraphQL\Login\Auth\Auth::login( [ 'provider' => 'instagram' ] ),
		'link-before-user/meta' => static fn () => \WPGraphQL\Login\Auth\Auth::link_user_identity( [ 'provider' => 'instagram' ] ),
		'registry-alias-lookup' => static fn () => $registry->get_provider_config( 'filtered-alias' ),
		'registry-lookup' => static fn () => $registry->get_provider_config( 'instagram' ),
		'authentication' => static fn () => $inert->authenticate_and_get_user_data( [] ),
		'resource-owner' => static fn () => $inert->get_resource_owner( [] ),
		'user-data' => static fn () => $inert->get_user_data( [] ),
		'user-lookup' => static fn () => $inert->get_user_from_data( [] ),
		'authorization' => static fn () => $inert->get_authorization_url(),
		'provider-access' => static fn () => $inert->get_provider(),
	];
	$passed = [];
	foreach ( $cases as $name => $operation ) {
		try { $operation(); throw new \RuntimeException( 'Retirement did not refuse: ' . $name ); }
		catch ( \GraphQL\Error\UserError $error ) {
			if ( ! str_contains( $error->getMessage(), 'Instagram Basic Display login is retired' ) ) { throw $error; }
			$passed[] = $name;
		}
	}
	if ( [] !== $registry->get_providers() ) { throw new \RuntimeException( 'Retired filtered instance remained active.' ); }
	if ( \WPGraphQL\Login\Auth\ProviderConfig\OAuth2\Instagram::is_enabled() || \WPGraphQL\Login\Auth\ProviderConfig\OAuth2\Instagram::get_slug() !== 'instagram' ) { throw new \RuntimeException( 'Retired metadata changed.' ); }
	fwrite( STDOUT, json_encode( [ 'source_only' => true, 'standins' => [ 'GraphQL error', 'OAuth base', 'translation/user/filter boundary functions', 'autoload spy' ], 'refusals' => $passed, 'genuine_runtime_qualified' => false ], JSON_PRETTY_PRINT ) . "\n" );
}
