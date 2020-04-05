<?php

final class WPCampus_Auth_API {

	/**
	 * Name of WP database option for JWT secret key.
	 *
	 * @var string
	 */
	private $option_name_jwt_secret_key = 'http_wpc_auth_secret_key';

	/**
	 * We don't need to instantiate this class.
	 */
	protected function __construct() { }

	/**
	 * Register our hooks.
	 */
	public static function register() {
		$plugin = new self();

		$plugin->define_jwt_secret_key();

		add_action( 'rest_api_init', [ $plugin, 'init_rest_api' ] );

		add_action( 'rest_api_init', [ $plugin, 'register_routes' ] );

		add_filter( 'rest_authentication_errors', [ $plugin, 'process_rest_authentication' ] );

		add_filter( 'rest_pre_serve_request', [ $plugin, 'add_rest_headers' ] );

		add_filter( 'jwt_auth_token_before_dispatch', [ $plugin, 'filter_jwt_auth_dispatch' ], 10, 2 );

		add_filter( 'jwt_auth_expire', [ $plugin, 'filter_jwt_auth_expire' ], 10, 2 );

	}

	/**
	 * Fires when preparing to serve an API request.
	 *
	 * @param $wp_rest_server - WP_REST_Server - Server object.
	 */
	public function init_rest_api( $wp_rest_server ) {

		// Remove the default headers so we can add our own.
		remove_filter( 'rest_pre_serve_request', 'rest_send_cors_headers' );

		return;

		/*
		 * Disable REST API link in HTTP headers
		 * Link: <https://example.com/wp-json/>; rel="https://api.w.org/"
		 */
		//remove_action( 'template_redirect', 'rest_output_link_header', 11 );

		/*
		 * Disable REST API links in HTML <head>
		 * <link rel='https://api.w.org/' href='https://example.com/wp-json/' />
		 */
		//remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
		//remove_action( 'xmlrpc_rsd_apis', 'rest_output_rsd' );
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
	 * Restrict access to the REST API.
	 *
	 * @filter rest_authentication_errors
	 *
	 * @param $access - WP_Error|null|bool
	 *                WP_Error if authentication error,
	 *                null if authentication method wasn't used,
	 *                true if authentication succeeded.
	 *
	 * @return WP_Error|null|bool
	 */
	public function process_rest_authentication( $access ) {

		$current_route = wpcampus_get_current_rest_route();

		// Allow open access for these specific REST paths.
		$rest_paths = [
			'/jwt-auth/v1/token',
			'/jwt-auth/v1/token/validate',
			'/wpcampus/auth/user',
			'/wpcampus/data/notifications',
			'/wpcampus/data/public/sessions',
			'/wpcampus/data/videos',
			'/wp/v2/posts' ];

		if ( in_array( $current_route, $rest_paths ) ) {
			return $access;
		}

		/*
		 * Require login and permissions for access.
		 *
		 * @TODO check for specific permissions?
		 */
		if ( current_user_can( 'manage_options' ) ) {
			return $access;
		}

		$error_message = 'Only authenticated users can access this route.';
		$rest_error_code = 'wpcampus_auth_rest_login_required';
		$rest_required_code = rest_authorization_required_code();

		if ( is_wp_error( $access ) ) {
			$access->add( $rest_error_code, $error_message, [ 'status' => $rest_required_code ] );
			return $access;
		}

		return new WP_Error( $rest_error_code, $error_message, [ 'status' => $rest_required_code ] );
	}

	/**
	 * Add any necessary headers for REST requests.
	 *
	 * Also disables the cache.
	 *
	 * @param   $value - bool - Whether the request has already been served. Default false.
	 *
	 * @return  bool - the filtered value
	 */
	public function add_rest_headers( $value ) {

		//$current_route = wpcampus_get_current_rest_route();

		// @TODO temporary for Gatsby
		header( 'Access-Control-Allow-Origin: *' );

		/*if ( preg_match( '/^\/wp\-json\/wpcampus\/data\/notifications/i', $_SERVER['REQUEST_URI'] ) ) {
			header( 'Access-Control-Allow-Origin: *' );
		} else {

			// @TODO: Only allow from WPCampus domains?
			//$origin = ! empty( $_SERVER['HTTP_ORIGIN'] ) ? $_SERVER['HTTP_ORIGIN'] : '';

			// Only allow from WPCampus domains.
			$origin = get_http_origin();

			if ( $origin ) {

				// Requests from file:// and data: URLs send "Origin: null"
				//if ( 'null' !== $origin ) {
					//$origin = esc_url_raw( $origin );
				//}

				// Only allow from production or Pantheon domains.
				if ( preg_match( '/([^\.]\.)?wpcampus\.org/i', $origin )
				     || preg_match( '/([^\-\.]+\-)wpcampus\.pantheonsite\.io/i', $origin ) ) {
					header( 'Access-Control-Allow-Origin: ' . esc_url_raw( $origin ) );
				}
			}
		}*/

		// Only allow GET requests.
		header( 'Access-Control-Allow-Headers: Accept, Authorization, Content-Type' );
		header( 'Access-Control-Allow-Methods: GET' ); // OPTIONS, GET, POST, PUT, PATCH, DELETE
		//header( 'Access-Control-Allow-Credentials: true' );

		// Disable the cache.
		wpcampus_add_header_nocache();
		header( 'Vary: Origin', false );

		return $value;
	}

	/**
	 * Define the secret key for the JWT plugin.
	 */
	private function define_jwt_secret_key() {
		define( 'JWT_AUTH_SECRET_KEY', get_option( $this->option_name_jwt_secret_key ) );
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
		return [
			'token' => $data['token'],
			'user'  => $this->prepare_user_data( $user ),
		];
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
		return $issued + ( DAY_IN_SECONDS * 2 );
	}

	/**
	 * Prepare the user data we need from the WP_User object.
	 *
	 * @param $user - WP_User object
	 *
	 * @return array|object
	 */
	private function prepare_user_data( $user ) {

		$user_data = $user->data;

		// Clean up response. We only need specific user data.
		$data_to_remove = [ 'user_pass', 'user_nicename', 'user_status', 'user_activation_key', 'spam', 'deleted' ];
		foreach ( $data_to_remove as $key ) {
			unset( $user->{$key} );
		}

		$user_data->roles = $user->roles;
		$user_data->caps = $user->allcaps;

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

		$response = wp_get_current_user();

		if ( empty( $response->ID ) || empty( $response->data ) ) {
			return new WP_Error( 'wpcampus', __( 'This user is invalid.', 'wpcampus-auth' ), [ 'status' => rest_authorization_required_code() ] );
		}

		// Clean up response. We only need specific user data.
		$user = $this->prepare_user_data( $response );

		return new WP_REST_Response( $user );
	}
}

WPCampus_Auth_API::register();