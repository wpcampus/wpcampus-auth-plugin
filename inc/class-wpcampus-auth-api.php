<?php

final class WPCampus_Auth_API {

	/**
	 * We don't need to instantiate this class.
	 */
	protected function __construct() { }

	/**
	 * Register our hooks.
	 */
	public static function register() {

		$plugin = new self();

		add_action( 'rest_api_init', [ $plugin, 'register_routes' ] );
	}

	/**
	 * Register our API routes.
	 */
	public function register_routes() {

		// Get current user per the JWT token. Depends on JWT plugin.
		register_rest_route(
			'wpcampus',
			'/auth/user/',
			array(
				'methods'  => 'GET',
				'callback' => array( $this, 'get_current_user' ),
			)
		);
	}

	/**
	 * Prepare the user data we need from the WP_User object.
	 *
	 * @param $user - WP_User object
	 *
	 * @return object
	 */
	private function prepare_user_data( $user ) {

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
			return new WP_Error( 'wpcampus', __( 'This request requires functionality that is missing.', 'wpcampus-auth' ), array( 'status' => 500 ) );
		}

		if ( empty( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			return new WP_Error( 'wpcampus', __( 'An authorization token is required.', 'wpcampus-auth' ), array( 'status' => 401 ) );
		}

		$response = wp_get_current_user();

		if ( empty( $response->ID ) || empty( $response->data ) ) {
			return new WP_Error( 'wpcampus', __( 'This user is invalid.', 'wpcampus-auth' ), array( 'status' => 500 ) );
		}

		// Clean up response. We only need specific user data.
		$user = $this->prepare_user_data( $response );

		return new WP_REST_Response( $user );
	}
}

WPCampus_Auth_API::register();