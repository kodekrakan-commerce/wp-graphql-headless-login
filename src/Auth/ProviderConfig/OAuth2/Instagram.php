<?php
/**
 * The Instagram Provider class.
 *
 * @package WPGraphQL\Login\Auth\ProviderConfig\OAuth2
 * @since 0.0.3
 */

declare( strict_types = 1 );

namespace WPGraphQL\Login\Auth\ProviderConfig\OAuth2;

use GraphQL\Error\UserError;

/**
 * Class - Instagram
 */
class Instagram extends OAuth2Config {
	/**
	 * The Constructor.
	 */
	public function __construct() {
		self::assert_available();
	}

	/**
	 * Refuse the retired service without reading settings or initializing OAuth.
	 *
	 * @throws \GraphQL\Error\UserError Always, because Instagram Basic Display login is retired.
	 */
	public static function assert_available(): never {
		throw new UserError( esc_html__( 'Instagram Basic Display login is retired and unavailable. Use another login provider; existing settings and linked identities are preserved. A new Instagram integration requires a separate migration.', 'wp-graphql-headless-login' ) );
	}

	/** Saved or filtered legacy flags cannot reactivate the retired service. */
	public static function is_enabled(): bool {
		return false;
	}

	/**
	 * {@inheritDoc}
	 */
	public static function get_name(): string {
		return __( 'Instagram (retired)', 'wp-graphql-headless-login' );
	}

	/**
	 * {@inheritDoc}
	 */
	public static function get_slug(): string {
		return 'instagram';
	}

	/**
	 * {@inheritDoc}
	 */
	protected function get_options( array $settings ): array {
		self::assert_available();
	}

	/**
	 * {@inheritDoc}
	 */
	protected static function client_options_schema(): array {
		return [
			'scope' => [
				'type'        => 'array',
				'description' => __( 'Scope', 'wp-graphql-headless-login' ),
				'help'        => __( 'Retained legacy scope settings. Instagram Basic Display login is retired; these values cannot enable login.', 'wp-graphql-headless-login' ),
				'order'       => 12,
				'advanced'    => true,
				'items'       => [
					'type' => 'string',
				],
			],
		];
	}

	/**
	 * {@inheritDoc}
	 */
	protected static function client_options_fields(): array {
		return [
			'scope' => [
				'type'        => [ 'list_of' => 'String' ],
				'description' => static fn () => __( 'Retained legacy scope settings for retired Instagram Basic Display login.', 'wp-graphql-headless-login' ),
			],
		];
	}

	/**
	 * {@inheritDoc}
	 */
	protected static function login_options_fields(): array {
		// Instagram doesnt give us enough information to link an existing user.
		return [];
	}

	/**
	 * {@inheritDoc}
	 */
	protected static function login_options_schema(): array {
		// Instagram doesnt give us enough information to link an existing user.
		return [];
	}

	/**
	 * {@inheritDoc}
	 */
	public function get_user_data( array $owner_details ): array {
		self::assert_available();
	}

	/** {@inheritDoc} */
	public function authenticate_and_get_user_data( array $input ) {
		self::assert_available();
	}

	/** {@inheritDoc} */
	public function get_user_from_data( $user_data ) {
		self::assert_available();
	}

	/** {@inheritDoc} */
	public function get_provider() {
		self::assert_available();
	}

	/** {@inheritDoc} */
	public function get_authorization_url(): string {
		self::assert_available();
	}

	/** {@inheritDoc} */
	public function get_resource_owner( array $args ): array {
		self::assert_available();
	}
}
