<?php
/**
 * Plugin Name:     WPCampus: Authentication
 * Plugin URI:      https://github.com/wpcampus/wpcampus-auth-plugin
 * Description:     Manages authentication for the WPCampus website.
 * Version:         1.0.0
 * Author:          WPCampus
 * Author URI:      https://wpcampus.org
 * Text Domain:     wpc-auth
 * Domain Path:     /languages
 *
 * @package         WPCampus_Auth
 */

defined( 'ABSPATH' ) or die();

require_once plugin_dir_path( __FILE__ ) . 'inc/class-wpcampus-auth-api.php';
