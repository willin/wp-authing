<?php

/*
Plugin Name: Authing Authentication
Plugin URI: https://developer.wordpress.org/plugins/wp-authing/
Description: Enables Authing integration for WordPress
Version: 0.0.4
Author: Willin Wang
Author URI: https://willin.wang/
License: GPL2
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Text Domain: authing
Domain Path: /languages
Documentation: https://docs.authing.cn/
*/

defined ( 'ABSPATH' ) or die( 'No dice.' );

if( ! class_exists( 'Authing' ) ) {

  class Authing {

    public function __construct () {

      /*
      Authing Variables
      */
      if ( ! function_exists( 'is_plugin_active_for_network' ) ) {
        require_once( ABSPATH . '/wp-admin/includes/plugin.php' );
      }
      $is_network = is_plugin_active_for_network( 'wp-authing/authing.php' );

      $this->org_url = defined( 'AUTHING_ORG_URL' ) ? AUTHING_ORG_URL : ( $is_network ? get_site_option( 'authing_org_url' ) : get_option( 'authing_org_url' ) );
      $this->client_id = defined( 'AUTHING_CLIENT_ID' ) ? AUTHING_CLIENT_ID : ( $is_network ? get_site_option( 'authing_client_id' ) : get_option( 'authing_client_id' ) );
      $this->client_secret = defined( 'AUTHING_CLIENT_SECRET' ) ? AUTHING_CLIENT_SECRET : ( $is_network ? get_site_option( 'authing_client_secret' ) : get_option( 'authing_client_secret' ) );
      $this->auth_secret = base64_encode( $this->client_id . ':' . $this->client_secret );
      $this->base_url = $this->org_url;

      add_action( 'init', array ($this, 'I18n') );

      /*
      Redirect URI for Authing authentication loop
      */

      add_action( 'rest_api_init', array ( $this, 'RestApiInit' ) );

      /*
      Add Authing button to login page
      */

      add_action( 'login_message', array( $this, 'LoginMessage' ) );

      /*
      Register settings
      */

      add_action( 'admin_init', array( $this, 'AdminInit' ) );

      /*
      Admin menu
      */

      if ( $is_network ){
        add_action( 'network_admin_menu', array( $this, 'NetworkAdminMenu' ) );
        add_action( 'network_admin_edit_authing', array ( $this, 'SettingsSave' ) );
      }else{
        add_action( 'admin_menu', array( $this, 'AdminMenu' ) );
      }

      /*
      Deactivation
      */

      register_deactivation_hook( __FILE__, array( $this, 'Deactivate' ) );

    }

    function I18n () {
      $domain = 'authing';
      $locale = apply_filters( 'plugin_locale', get_locale(), $domain );

      // wp-content/languages/plugin-name/plugin-name-de_DE.mo
      load_textdomain( $domain, trailingslashit( WP_LANG_DIR ) . $domain . '/' . $domain . '_' . $locale . '.mo' );
      // wp-content/plugins/plugin-name/languages/plugin-name-de_DE.mo
      load_plugin_textdomain( $domain, FALSE, basename( dirname( __FILE__ ) ) . '/languages/' );

    }

    /*
    Register the rest API endpoint
    */

    function RestApiInit () {

      register_rest_route ( 'authing', '/auth', array(
        'methods' => 'GET',
        'callback' => array( $this, 'Auth' ),
      ) );

    }

    /*
    Authorize the user in Authing
    */

    function Auth ( WP_REST_Request $request ) {

      /*
      Validate the code and state
      */

      if ( array_key_exists ( 'state', $request ) && $request['state'] !== $state ) {

        die ( 'State does not match.' );

      }

      /*
      Convert the code to a token
      */

      $token = $this->Token ( $_GET['code'] );
      if ( is_wp_error( $token ) ) {
        die( 'TOKEN ERROR' );
      }

      /*
      Validate the token and return user data
      */

      $token = json_decode( $token['body'] );
      if ( null === $token || empty ( $token->access_token ) ){
        die( 'TOKEN ERROR' );
      }

      /*
      Get user detail
      */

      $user = $this->User ( $token->access_token );
      if ( is_wp_error ( $user ) ) {
        die( 'USER ERROR' );
      }

      /*
      Login the user
      */

      $user = json_decode ( $user['body'] );
      $this->Login ( $user );

    }

    /*
    Convert the code to a token
    */

    function Token ( $code ) {

      $url = $this->base_url . '/oidc/token';

      $response = wp_safe_remote_post( $url, array(
        'headers' => array(
          'Accept' => 'application/json',
          'Content-Type' => 'application/x-www-form-urlencoded'
        ),
        'body' => array (
          'client_id' => $this->client_id,
          'client_secret' => $this->client_secret,
          'grant_type' => 'authorization_code',
          'code' => $code
        ),
        'sslverify' => false
      ) );

      return $response;

    }

    /*
    Get user detail
    */

    function User ( $token ){

      $url = $this->base_url . '/oidc/me?' . http_build_query (
        [
          'access_token' => $token
        ]
      );

      $response = wp_safe_remote_get ( $url, array(
        'headers' => array (
          'Accept' => 'application/json',
          'Content-Length' => 0,
          'Content-Type' => 'application/x-www-form-urlencoded'
        ),
        'sslverify' => false
      ) );

      return $response;

    }

    /*
    Login the user
    */

    function Login ( $user_response ){

      /*
      Get the user
      */

      $user = $this->GetUser ( $user_response );
      if ( is_wp_error ( $user ) ) {
        die( $user->get_error_message() );
      }

      /*
      Login the user
      */

      wp_set_current_user ( $user->ID, $user->user_login );
      wp_set_auth_cookie ( $user->ID );
      do_action ( 'wp_login', $user->user_login, $user );

      /*
      Redirect the user
      */

      if ( ! is_network_admin () ) {
        wp_redirect ( admin_url () );
      } else {
        wp_redirect ( network_admin_url () );
      }

      exit();

    }

    /*
    Gets or creates a user from the user response.
    */

    function GetUser( $user_response ){

      /*
      Allow filtering of field to get user ID
      */

      $user_id = apply_filters ( 'authing_user_get', false, $user_response );

      if ( false === $user_id ) {

        /*
        Check to see if the user already exists
        */
        if( $user_response->preferred_username ){
            $temp_name = $user_response->preferred_username;
        } elseif ( $user_response->username ){
            $temp_name = $user_response->username;
        } elseif ( $user_response->name ){
            $temp_name = $user_response->name;
        } elseif ( $user_response->phone_number ){
            $temp_name = "u" . $user_response->phone_number;
        } else {
            $temp_name = substr( $user_response->email, 0, strrpos( $user_response->email, "@" ) );
        }
        $username = apply_filters ( 'authing_username', $temp_name );
        $user_id  = username_exists ( $username );
      }

      $default_role = apply_filters ( 'authing_default_role', get_option( 'default_role' ), $user_response );

      /*
      Create user if not found
      */

      if ( ! $user_id ){

        $user_data = apply_filters( 'authing_user_insert', array(
          'user_login' => $username,
          'user_pass'  => wp_generate_password(),
          'role'       => $default_role,
          'nickname'   => $user_response->nickname ? $user_response->nickname : $user_response->name,
          'email'      => $user_response->email ? $user_response->email : ''
        ), $user_response );
        $user_id   = wp_insert_user ( $user_data );
        if ( is_wp_error( $user_id ) ){
          return $user_id;
        }
      }

      $user = get_user_by( 'id', $user_id );
      if ( is_wp_error( $user ) ){
        return $user;
      }

      /*
      Add user to multisite
      */

      if ( empty( $user->roles ) ){
        $user->set_role( $default_role );
      }

      return $user;
    }

    /*
    Add the Authing button to wp-login.php
    */

    function LoginMessage () {

      $url = apply_filters ( 'authing_login', $this->base_url . '/login?' . $query = http_build_query (
        [
          'app_id' => $this->client_id,
          'response_type' => 'code',
          'response_mode' => 'query',
          'scope' => 'openid profile',
          'redirect_uri' => get_rest_url( null, 'authing/auth' ),
          'state' => 'wordpress',
          'nonce' => wp_create_nonce( 'authing' )
        ]
      ) );

      $vendor_name = apply_filters( 'authing_login_name', __( 'Authing', 'authing' ) );

      ?>
      <style>
      .authing-logo{
        background-image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMjUgNDIiPjxkZWZzPjxzdHlsZT4uY2xzLTF7ZmlsbDojZmZmO30uY2xzLTIsLmNscy0ze2ZpbGw6IzIxNWFlNTt9LmNscy0ye2ZpbGwtcnVsZTpldmVub2RkO308L3N0eWxlPjwvZGVmcz48dGl0bGU+6LWE5rqQIDI8L3RpdGxlPjxnIGlkPSLlm77lsYJfMiIgZGF0YS1uYW1lPSLlm77lsYIgMiI+PGcgaWQ9IuWbvuWxgl8xLTIiIGRhdGEtbmFtZT0i5Zu+5bGCIDEiPjxyZWN0IGNsYXNzPSJjbHMtMSIgd2lkdGg9IjEyNSIgaGVpZ2h0PSI0MiIvPjxwYXRoIGNsYXNzPSJjbHMtMiIgZD0iTTQ0LjM5LDEyLjg2aDIuNzdMNTIuNzUsMzBoLTNsLTEuMzctNC40MUg0Mi4yNEw0MC44NywzMGgtM2w1LjU5LTE3LjE3Wm0uOTEsMi45Mkw0My4wOCwyMi45aDQuNDNaIi8+PHBhdGggY2xhc3M9ImNscy0zIiBkPSJNNzEsMTQuMTdINjguMjN2Mi42N2gtMnYyLjcxaDJWMjkuOTFINzFWMTkuNTVoMlYxNi44NEg3MVoiLz48cGF0aCBjbGFzcz0iY2xzLTMiIGQ9Ik04OC4yNiwyOS45MUg5MVYxNy4xN0g4OC4yNloiLz48cGF0aCBjbGFzcz0iY2xzLTMiIGQ9Ik02MS45MywyNC40di4zOGEyLjg5LDIuODksMCwwLDEtNS43OCwwVjI0LjRsMC03LjU3SDUzLjQ1djhhNS41OCw1LjU4LDAsMCwwLDExLjE2LDB2LThINjEuOTFaIi8+PHBhdGggY2xhc3M9ImNscy0yIiBkPSJNMTE4LDE2Ljg0djguNDhoMFYzMGE1LjYxLDUuNjEsMCwxLDEtMTEuMjEsMGgyLjc0YTIuODYsMi44NiwwLDEsMCw1LjcyLDB2LS43NWgwVjI3LjlhNSw1LDAsMCwxLTMuNzIsMS41N2MtMi45NCwwLTUuMzMtMi4zNi01LjMzLTYuNDYsMC0zLjg5LDIuMzktNi40Niw1LjMzLTYuNDZhNSw1LDAsMCwxLDMuNzIsMS42OXYtMS40Wk0xMDkuMjIsMjNjMCwyLjYxLDEuMzUsNC4xMiwzLDQuMTJzMy0xLjQzLDMtNC4xMmMwLTIuNS0xLjM3LTQuMTMtMy00LjEzUzEwOS4yMiwyMC41MywxMDkuMjIsMjNaIi8+PHBhdGggY2xhc3M9ImNscy0zIiBkPSJNODkuNjIsMTIuMjZBMS43OCwxLjc4LDAsMSwwLDkxLjQsMTRhMS43OCwxLjc4LDAsMCwwLTEuNzgtMS43OCIvPjxwYXRoIGNsYXNzPSJjbHMtMyIgZD0iTTEwMC4yOCwxNi4zOWgtLjYxYy0xLjQ1LDAtMy42MywxLjA1LTMuNjMsMy4wNXYtMkg5My4zMlYyOS44N0g5NnYtNy44QTMuMSwzLjEsMCwwLDEsOTkuMTUsMTlhMi43OSwyLjc5LDAsMCwxLDIuNzgsMi43OHY4LjE2aDNWMjEuMDVhNC42Niw0LjY2LDAsMCwwLTQuNjYtNC42NiIvPjxwYXRoIGNsYXNzPSJjbHMtMyIgZD0iTTgxLjQ5LDE2LjM5aC0uNjFhMy41NCwzLjU0LDAsMCwwLTMuNDcsMi4xMlYxMS45Mkg3NC42OVYyOS44MWgyLjcyVjIxLjA5QTMuMSwzLjEsMCwwLDEsODAuMzUsMTlhMi43OSwyLjc5LDAsMCwxLDIuNzksMi43OHY4LjE2aDNWMjEuMDVhNC42Niw0LjY2LDAsMCwwLTQuNjUtNC42NiIvPjxwYXRoIGNsYXNzPSJjbHMtMiIgZD0iTTE5LjM3LDdsMTIuMzYsNy41NGMwLC4yMiwwLC40NCwwLC42N0EyMy4xMywyMy4xMywwLDAsMSwxOS4zNywzNS42OSwyMy4xMSwyMy4xMSwwLDAsMSw3LDE1LjIxYzAtLjIzLDAtLjQ1LDAtLjY3Wk05LjUsMTYuNDVhMTguNDUsMTguNDUsMCwwLDAsOS44NywxNi4zNCwxOC40NSwxOC40NSwwLDAsMCw5Ljg3LTE2LjM0YzAtLjE4LDAtLjM2LDAtLjU0bC05Ljg2LTYtOS44Niw2QzkuNTEsMTYuMDksOS41LDE2LjI3LDkuNSwxNi40NVoiLz48cGF0aCBjbGFzcz0iY2xzLTMiIGQ9Ik0yMS41OCwxMy40NmwtMi4xOSw0LjA2LDIuNTIsNC42LTIuNTIsNC0yLjUzLTQsMi41My00LjYtMi4xNS00LjA4LTUuNDgsMy42MXYuNDNhMTQuMzUsMTQuMzUsMCwwLDAsNy42OSwxMi43NCwxNC40LDE0LjQsMCwwLDAsNy42OS0xMi43NHYtLjQzWiIvPjwvZz48L2c+PC9zdmc+);
        background-position: center;
        background-repeat: no-repeat;
        height: 30px;
        margin-bottom: 20px;
        overflow: hidden;
        text-indent: 100%;
      }
      </style>
      <form style="padding-bottom: 26px; text-align: center;">
        <div class="authing-logo">
          <?php echo esc_html( $vendor_name ); ?>
        </div>
        <a href="<?php echo esc_url( $url ); ?>" class="button">
          <?php printf(
            esc_html__( 'Log In with %s', 'authing' ),
            esc_html( $vendor_name )
          ); ?>
        </a>
      </form>
      <p style="margin-top: 20px; text-align: center;">
        <?php esc_html_e( 'or', 'authing' ); ?>
      </p>
      <?php

    }

    /*
    Register settings
    */

    function AdminInit () {

      register_setting ( 'authing', 'authing_org_url' );
      register_setting ( 'authing', 'authing_client_id' );
      register_setting ( 'authing', 'authing_client_secret' );

    }

    /*
    Create the settings page
    */

    function AdminMenu () {

      add_menu_page ( 'Authing Authentication', 'Authing', 'manage_options', 'authing', array( $this, 'SettingsPage' ), 'dashicons-lock' );

    }

    /*
    Create the settings page
    */

    function NetworkAdminMenu () {

      add_menu_page ( 'Authing Authentication', 'Authing', 'manage_network_options', 'authing', array( $this, 'SettingsPage' ), 'dashicons-lock' );

    }

    /*
    Render the settings page
    */

    function SettingsPage () {

      ?>
      <div class="wrap">
        <h1>
          <?php esc_html_e( 'Authing Authentication', 'authing' ); ?>
        </h1>
        <form action="<?php echo esc_url( is_network_admin() ? network_admin_url( 'edit.php?action=authing' ) : admin_url( 'options.php' ) ); ?>" method="post" autocomplete="off">
          <?php settings_fields ( 'authing' ); ?>
          <?php do_settings_sections ( 'authing' ); ?>
          <h2 class="title">
            <?php esc_html_e( 'Step 1', 'authing' ); ?>
          </h2>
          <p>
            <a href=https://console.authing.cn/login" target="_blank">
              <?php esc_html_e('Log in to or sign up', 'authing' ) ?>
            </a> <?php esc_html_e('for an Authing account. It\'s free to create a developer account.', 'authing' ) ?>
          </p>
          <h2 class="title">
            <?php esc_html_e( 'Step 2', 'authing' ); ?>
          </h2>
          <p>
            <?php esc_html_e( 'Go to the Dashboard of your Developer Console. At the top right of the screen, you should see your App URL (ex: https://dev-123.authing.cn). Copy and paste that URL into the field below.', 'authing' ); ?>
          </p>
          <table class="form-table">
            <tr valign="top">
              <th scope="row">
                <?php esc_html_e( 'App URL', 'authing' ); ?>
              </th>
              <td>
                <input type="url" name="authing_org_url" value="<?php echo esc_url( $this->org_url ); ?>" size="40"<?php echo esc_attr( defined( 'AUTHING_ORG_URL' ) ? ' disabled readonly' : '' ); ?>>
              </td>
            </tr>
          </table>
          <h2 class="title">
            <?php esc_html_e( 'Step 3', 'authing' ); ?>
          </h2>
          <p>
            <?php esc_html_e( 'Go to the Applications section of your Developer Console. Create a new Web application and enter these URLs when prompted.', 'authing' ); ?>
          </p>
          <table class="form-table">
            <tr valign="top">
              <th scope="row">
                <?php esc_html_e( 'Base URI', 'authing' ); ?>
              </th>
              <td>
                <a href="<?php echo esc_url( get_site_url() ); ?>" target="_blank">
                  <?php echo esc_url( get_site_url() ); ?>
                </a>
              </td>
            </tr>
              <tr valign="top">
                <th scope="row">
                  <?php esc_html_e( 'Login Redirect URI', 'authing' ); ?>
                </th>
                <td>
                  <a href="<?php echo esc_url( get_rest_url( null, 'authing/auth' ) ); ?>" target="_blank">
                    <?php echo esc_url( get_rest_url( null, 'authing/auth' ) ); ?>
                  </a>
                </td>
              </tr>
          </table>
          <h2 class="title">
            <?php esc_html_e( 'Step 4', 'authing' ); ?>
          </h2>
          <p>
            <?php esc_html_e( 'Once you\'ve created the application, go to the General tab and scroll down to the Client Credentials section. Copy and paste those values in the fields below.', 'authing' ); ?>
          </p>
          <table class="form-table">
            <tr valign="top">
              <th scope="row">
                <?php esc_html_e( 'App ID', 'authing' ); ?>
              </th>
              <td>
                <input type="text" name="authing_client_id" value="<?php echo esc_attr( $this->client_id ); ?>" size="40"<?php echo esc_attr( defined( 'AUTHING_CLIENT_ID' ) ? ' disabled readonly' : '' ); ?>>
              </td>
            </tr>
            <tr valign="top">
              <th scope="row">
                <?php esc_html_e( 'App Secret', 'authing' ); ?>
              </th>
              <td>
                <input type="password" name="authing_client_secret" value="<?php echo esc_attr( $this->client_secret ); ?>" size="40"<?php echo esc_attr( defined( 'AUTHING_CLIENT_SECRET' ) ? ' disabled readonly' : '' ); ?>>
              </td>
            </tr>
          </table>
          <?php submit_button (); ?>
        </form>
      </div>
      <?php

    }

    /*
    Update settings for multisite network
    */

    function SettingsSave () {

      /*
      Validate the request via nonce, referrer and capabilities
      */

      if ( ! wp_verify_nonce( $_POST['_wpnonce'], 'authing-options' ) || ! current_user_can( 'manage_network_options' ) ) {
        wp_die( 'No dice.' );
      }else{
        check_admin_referer( 'authing-options' );
      }

      /*
      Update network settings
      */

      if ( isset( $_POST['authing_org_url'] ) && filter_var( $_POST['authing_org_url'], FILTER_VALIDATE_URL ) ) {
        update_site_option( 'authing_org_url', esc_url_raw( $_POST['authing_org_url'], array( 'https' ) ) );
      }
      if ( isset( $_POST['authing_client_id'] ) ) {
        update_site_option( 'authing_client_id', sanitize_text_field( $_POST['authing_client_id'] ) );
      }
      if ( isset( $_POST['authing_client_secret'] ) ) {
        update_site_option( 'authing_client_secret', sanitize_text_field( $_POST['authing_client_secret'] ) );
      }

      /*
      Redirect the user
      */

      wp_redirect ( $_POST['_wp_http_referer'] );
      exit();

    }

    function Deactivate () {

      if ( is_network_admin () ) {

        /*
        Delete network settings
        */

        delete_site_option ( 'authing_org_url' );
        delete_site_option ( 'authing_client_id' );
        delete_site_option ( 'authing_client_secret' );

      } else {

        /*
        Delete blog settings
        */

        delete_option ( 'authing_org_url' );
        delete_option ( 'authing_client_id' );
        delete_option ( 'authing_client_secret' );


      }
    }

  }

  new Authing;

}