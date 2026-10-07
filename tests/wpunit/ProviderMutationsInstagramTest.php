<?php
/** Genuine retired-service regressions; UNRUN until separate native/profile admission. */
use GraphQL\Error\UserError;
use WPGraphQL\Login\Auth\Auth;
use WPGraphQL\Login\Auth\Client;
use WPGraphQL\Login\Auth\User;
use WPGraphQL\Login\Auth\ProviderRegistry;
use WPGraphQL\Login\Auth\ProviderConfig\OAuth2\Instagram;
use WPGraphQL\Login\Auth\ProviderConfig\OAuth2\Generic;
use WPGraphQL\Login\Admin\Settings\ProviderSettings;
use WPGraphQL\Login\Type\Enum\ProviderEnum;

class RetirementInitializationSentinel extends Generic {
	public static int $initializations = 0;
	public static function is_enabled(): bool { return true; }
	public function __construct() { ++self::$initializations; throw new \RuntimeException( 'Registry initialization reached.' ); }
}

class RetiredAliasSentinel extends Instagram {
	public static int $initializations = 0;
	public static function is_enabled(): bool { return true; }
	public function __construct() { ++self::$initializations; throw new \RuntimeException( 'Retired alias initialized.' ); }
}

class ProviderMutationsInstagramTest extends \Tests\WPGraphQL\TestCase\WPGraphQLTestCase {
	public $tester;
	private array $effects = [];
	private $recorder;
	private const EFFECT_HOOKS = [ 'graphql_login_after_provider_init', 'graphql_login_client_init', 'graphql_login_before_authenticate', 'graphql_login_after_authenticate', 'graphql_login_get_user_from_data', 'wp_login', 'added_user_meta', 'updated_user_meta', 'deleted_user_meta', 'user_register' ];
	public function setUp(): void {
		parent::setUp();
		$this->tester->reset_utils_properties();
		$this->tester->reset_provider_registry();
		$this->recorder = function (): void { $this->effects[] = current_filter(); };
		foreach ( self::EFFECT_HOOKS as $hook ) { add_action( $hook, $this->recorder ); }
	}
	public function tearDown(): void {
		foreach ( self::EFFECT_HOOKS as $hook ) { remove_action( $hook, $this->recorder ); }
		$this->tester->reset_utils_properties();
		$this->tester->reset_provider_registry();
		$this->clearSchema();
		parent::tearDown();
	}
	private function refuse( callable $operation ): void {
		try { $operation(); $this->fail( 'Retired service accepted operation.' ); }
		catch ( UserError $error ) { $this->assertStringContainsString( 'Instagram Basic Display login is retired', $error->getMessage() ); }
	}
	/** @dataProvider legacyFlags */
	public function test_disabled_saved_and_filter_enabled_flags_refuse_before_effects( bool $enabled ): void {
		$config = [ 'slug' => 'instagram', 'isEnabled' => $enabled, 'clientOptions' => [ 'clientId' => 'fixture', 'clientSecret' => 'fixture-secret', 'scope' => [ 'user_profile' ] ], 'loginOptions' => [ 'createUserIfNoneExists' => true ] ];
		$this->tester->set_client_config( 'instagram', $config );
		$before = get_option( ProviderSettings::$settings_prefix . 'instagram' );
		$session = [ session_status(), session_id(), $_SESSION ?? [], headers_list() ];
		$settings_filter = static fn ( $settings, $slug ) => 'instagram' === $slug ? array_merge( $settings, [ 'isEnabled' => true ] ) : $settings;
		$registry_filter = static fn () => [ 'instagram' => RetirementInitializationSentinel::class, 'google' => RetirementInitializationSentinel::class ];
		add_filter( 'graphql_login_provider_settings', $settings_filter, 10, 2 );
		add_filter( 'graphql_login_registered_provider_configs', $registry_filter );
		RetirementInitializationSentinel::$initializations = 0;
		$this->effects = [];
		try {
			$this->assertFalse( Instagram::is_enabled() );
			$this->refuse( static fn () => new Instagram() );
			$this->refuse( static fn () => new Client( 'instagram' ) );
			$this->refuse( static fn () => Auth::login( [ 'provider' => 'instagram', 'oauthResponse' => [ 'code' => 'fixture' ] ] ) );
			$this->refuse( static fn () => Auth::link_user_identity( [ 'provider' => 'instagram', 'userId' => 123, 'oauthResponse' => [ 'code' => 'fixture' ] ] ) );
			$this->assertSame( 0, RetirementInitializationSentinel::$initializations );
			$this->assertSame( $before, get_option( ProviderSettings::$settings_prefix . 'instagram' ) );
			$this->assertSame( $session, [ session_status(), session_id(), $_SESSION ?? [], headers_list() ] );
			$this->assertSame( [], $this->effects );
		} finally { remove_filter( 'graphql_login_provider_settings', $settings_filter, 10 ); remove_filter( 'graphql_login_registered_provider_configs', $registry_filter ); }
	}
	public static function legacyFlags(): array { return [ 'disabled' => [ false ], 'legacy-enabled' => [ true ] ]; }
	public function test_metadata_lookup_and_existing_identity_preserved(): void {
		$filter = static fn () => [ 'instagram' => RetirementInitializationSentinel::class ];
		add_filter( 'graphql_login_registered_provider_configs', $filter );
		try {
			$id = $this->factory()->user->create();
			update_user_meta( $id, User::get_identity_meta_key( 'instagram' ), 'legacy-subject' );
			$before = get_user_meta( $id ); $this->effects = [];
			$registry = ProviderRegistry::get_instance();
			$this->assertSame( Instagram::class, $registry->get_registered_providers()['instagram'] );
			$this->assertArrayNotHasKey( 'instagram', $registry->get_providers() );
			$this->refuse( static fn () => $registry->get_provider_config( 'instagram' ) );
			$this->assertSame( 'legacy-subject', User::get_user_identities( $id )['instagram'] );
			$this->assertSame( $before, get_user_meta( $id ) );
			$this->assertArrayHasKey( 'deprecationReason', ProviderEnum::get_values()['INSTAGRAM'] );
			$this->assertArrayHasKey( 'scope', Instagram::get_client_options_schema() );
			$this->assertArrayHasKey( 'clientSecret', Instagram::get_client_options_fields() );
			$this->assertStringContainsString( 'Retired provider', ProviderSettings::get_config()[ ProviderSettings::$settings_prefix . 'instagram' ]['isEnabled']['label'] );
			$this->assertSame( [], $this->effects );
		} finally { remove_filter( 'graphql_login_registered_provider_configs', $filter ); }
	}
	public function test_retired_class_aliases_are_never_initialized_or_returned(): void {
		$filter = static fn () => [ 'filtered-alias' => RetiredAliasSentinel::class ];
		add_filter( 'graphql_login_registered_provider_configs', $filter );
		RetiredAliasSentinel::$initializations = 0;
		try {
			$registry = ProviderRegistry::get_instance();
			$this->assertSame( [], $registry->get_providers() );
			$this->assertSame( 0, RetiredAliasSentinel::$initializations );
			$inert = ( new \ReflectionClass( Instagram::class ) )->newInstanceWithoutConstructor();
			$property = new \ReflectionProperty( $registry, 'providers' );
			$property->setValue( $registry, [ 'filtered-alias' => $inert ] );
			$this->refuse( static fn () => $registry->get_provider_config( 'filtered-alias' ) );
			$this->assertSame( [], $registry->get_providers() );
			$this->assertSame( [], $this->effects );
		} finally { remove_filter( 'graphql_login_registered_provider_configs', $filter ); }
	}
	public function test_graphql_login_and_link_return_clear_retirement_error(): void {
		$this->clearSchema();
		foreach ( [ 'login' => 'authToken refreshToken', 'linkUserIdentity' => 'success' ] as $mutation => $fields ) {
			$extra = 'linkUserIdentity' === $mutation ? ', userId: "123"' : '';
			$response = $this->graphql( [ 'query' => 'mutation { ' . $mutation . '(input: {provider: INSTAGRAM, oauthResponse: {code: "fixture"}' . $extra . '}) { ' . $fields . ' } }' ] );
			$this->assertNotEmpty( $response['errors'] );
			$this->assertStringContainsString( 'Instagram Basic Display login is retired', $response['errors'][0]['message'] );
			$this->assertEmpty( $response['data'][ $mutation ] ?? null );
		}
	}
	public function test_rebuilt_classes_have_no_basic_display_or_helper(): void {
		$this->assertFalse( class_exists( 'WPGraphQL\\Login\\Vendor\\League\\OAuth2\\Client\\Provider\\Instagram' ) );
		$this->assertFalse( class_exists( 'League\\OAuth2\\Client\\Provider\\Instagram' ) );
		$this->assertFalse( function_exists( 'http_build_url' ) );
	}
}
