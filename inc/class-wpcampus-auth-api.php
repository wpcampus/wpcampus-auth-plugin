<?php

final class WPCampus_Auth_API {

	/**
	 * Name of WP database option for access token.
	 *
	 * @var string
	 */
	private $option_name_access_token = 'http_wpc_auth_access_token';

	/**
	 * Name of PHP request header for access token.
	 *
	 * @var string
	 */
	private $header_auth_access = 'wpcauthaccess';

	/**
	 * We don't need to instantiate this class.
	 */
	protected function __construct() { }

	/**
	 * Register our hooks.
	 */
	public static function register() {

		$plugin = new self();

		add_filter( 'rest_pre_serve_request', [ $plugin, 'add_rest_headers' ] );

		add_action( 'rest_api_init', [ $plugin, 'register_routes' ] );

		add_filter( 'jwt_auth_token_before_dispatch', [ $plugin, 'filter_jwt_auth_dispatch' ], 10, 2 );

		add_filter( 'jwt_auth_expire', [ $plugin, 'filter_jwt_auth_expire' ], 10, 2 );

	}

	/**
	 * Register our API routes.
	 */
	public function register_routes() {

		// Get current user per the JWT token. Depends on JWT plugin.
		register_rest_route(
			'wpcampus',
			'/auth/user/',
			[
				'methods'  => 'GET',
				'callback' => [ $this, 'get_current_user' ],
			]
		);
	}

	/**
	 * Returns our access token.
	 *
	 * @return string
	 */
	private function get_access_token() {

		return get_option( $this->option_name_access_token );
	}

	/**
	 * Returns access token sent in request.
	 *
	 * @return string
	 */
	private function get_request_access_token() {

		$auth_access_key = 'HTTP_' . strtoupper( $this->header_auth_access );

		return ! empty( $_SERVER[ $auth_access_key ] ) ? $_SERVER[ $auth_access_key ] : '';
	}

	/**
	 * Returns true if the request access token matches our access token.
	 *
	 * @return bool
	 */
	private function has_valid_access_token() {

		return $this->get_access_token() === $this->get_request_access_token();
	}

	/**
	 * Add any necessary headers for REST requests.
	 *
	 * @param $value
	 *
	 * @return mixed
	 */
	public function add_rest_headers( $value ) {

		/*
		 * Only allow for these specific REST paths.
		 */
		$rest_paths = [ '/wp-json/jwt-auth/v1/token', '/wp-json/wpcampus/auth/user' ];

		if ( ! in_array( $_SERVER['REQUEST_URI'], $rest_paths ) ) {
			return $value;
		}

		// @TODO: Only allow from WPCampus domains?
		//$origin = ! empty( $_SERVER['HTTP_ORIGIN'] ) ? $_SERVER['HTTP_ORIGIN'] : '';

		header( 'Access-Control-Allow-Headers: Accept, Authorization, Content-Type, ' . $this->header_auth_access );
		header( 'Cache-Control: no-cache, must-revalidate, max-age=0' );
		header( 'Access-Control-Allow-Origin: *' );

		return $value;
	}

	/**
	 * Filter the auth token returned by JWT Authentication for WP-API
	 * plugin to include the user data we need.
	 *
	 * @param $data
	 * @param $user
	 *
	 * @return array
	 */
	public function filter_jwt_auth_dispatch( $data, $user ) {

		if ( ! $this->has_valid_access_token() ) {
			return [];
		}

		$new_data = [
			'token' => $data['token'],
			'user'  => $this->prepare_user_data( $user ),
		];

		return $new_data;
	}

	/**
	 * Filter when the JWT Authentication for WP-API plugin
	 * auth token expires. The default is a week.
	 *
	 * The Gatsby app is set to expire every 48 hours.
	 *
	 * @param $expiration - string - timestamp
	 * @param $issued     - string - timestamp
	 *
	 * @return float|int
	 */
	public function filter_jwt_auth_expire( $expiration, $issued ) {

		return $issued + ( DAY_IN_SECONDS * 7 );
	}

	/**
	 * Prepare the user data we need from the WP_User object.
	 *
	 * @param $user - WP_User object
	 *
	 * @return array|object
	 */
	private function prepare_user_data( $user ) {

		if ( ! $this->has_valid_access_token() ) {
			return [];
		}

		$user_data = $user->data;

		// Clean up response. We only need specific user data.
		$data_to_remove = [ 'user_pass', 'user_nicename', 'user_activation_key' ];
		foreach ( $data_to_remove as $key ) {
			unset( $user->{$key} );
		}

		$user_data->roles = $user->roles;
		$user_data->caps  = $user->allcaps;

		return $user_data;
	}

	/**
	 * This route depends on the "JWT Authentication for WP-API" plugin which:
	 * - intercepts the request
	 * - validates the token
	 * - sets the current user
	 *
	 * @param WP_REST_Request $request
	 *
	 * @return WP_Error|WP_REST_Response
	 */
	public function get_current_user( WP_REST_Request $request ) {

		if ( ! function_exists( 'run_jwt_auth' ) ) {
			return new WP_Error( 'wpcampus', __( 'This request requires functionality that is missing.', 'wpcampus-auth' ), [ 'status' => 500 ] );
		}

		if ( empty( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			return new WP_Error( 'wpcampus', __( 'An authorization token is required.', 'wpcampus-auth' ), [ 'status' => 401 ] );
		}

		$response = wp_get_current_user();

		if ( empty( $response->ID ) || empty( $response->data ) ) {
			return new WP_Error( 'wpcampus', __( 'This user is invalid.', 'wpcampus-auth' ), [ 'status' => 500 ] );
		}

		// Clean up response. We only need specific user data.
		$user = $this->prepare_user_data( $response );

		return new WP_REST_Response( $user );
	}
}

WPCampus_Auth_API::register();