<?php
/***
* Plugin Name: MS Graph WP Login
* Description: Enable Wordpress login via Microsoft Graph API using an enterprise Tennent ID and Active Directory.
* Version: 2.0
* Author: Russell Ramey
* Author URI: https://russellramey.dev/
* API Docs: https://docs.microsoft.com/en-us/graph/auth/
***/

class MSGWPLAuthUser
{

    /**
     *
     * Configuration array for API keys, secrets, and tennet.
     * @var Array
     *
    **/
    protected $config = [
        // Azure App Tennent ID
        'tennent_id' => null,
        // Azure App Client ID
        'client_id' => null,
        // Azure App Client Secrect
        'client_secret' => null,
        // Graph Scopes (default user profile, offline access)
        'scopes' => 'user.read+offline_access',
        // Cookie name for tokens
        'cookie_hash' => null
    ];

    /**
     *
     * Valid configuration array
     * @var Boolean
     *
    **/
    protected $valid_config = true;

    /**
     *
     * Class constructor
     *
    **/
    public function __construct()
    {
        // Check for Tennent ID
        if(defined('MSGWPL_TENNENT_ID')){
            $this->config['tennent_id'] = MSGWPL_TENNENT_ID;
        }
        // Check for Client ID
        if(defined('MSGWPL_CLIENT_ID')){
            $this->config['client_id'] = MSGWPL_CLIENT_ID;
        }
        // Check for Client Secret
        if(defined('MSGWPL_CLIENT_SECRET')){
            $this->config['client_secret'] = MSGWPL_CLIENT_SECRET;
        }
        // Check for Graph Scopes
        if(defined('MSGWPL_CLIENT_SCOPES')){
            $this->config['scopes'] = MSGWPL_CLIENT_SCOPES;
        }
        // Check for config secret, generate hash string
        if(isset($this->config['client_secret'])){
            $this->config['cookie_hash'] = hash('sha256', $this->config['client_secret'] . (isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'MSGWPL'));
        }

        // Check each value in $config array
        foreach($this->config as $key => $value){
            // If value is null or empty
            if(!$value || empty($value)){
                // set $defined_config to false
                $this->valid_config = false;
            }
        }

        // If $config is valid
        if($this->valid_config){
            // Add action to redirect wp_login_url
            add_action( 'login_redirect', function(){
                // Call private function directly
                $this->MSGWPL_LoginRedirect();
            });
            // Add action to redirect wp_lostpassword_url
            add_action( 'lostpassword_redirect', function(){
                // Die, with error
                wp_die('This action is not allowed.');
            });
        }
    }

    /**
     *
     * Redirect WP Login
     * Main login url redirect
     * @return null
     *
    **/
    private function MSGWPL_LoginRedirect()
    {

        // Watch for logout action
        $this->MSGWPL_LogoutUser();

        // If user is already authenticated
        if($this->MSGWPL_AuthenticateUser()) {

            // Redirect to WP Dashboard
            header('Location: ' . get_dashboard_url());
        
        } 

        // If refresh_token cookie exists 
        elseif(isset($_COOKIE['msgwpl_refresh_token_' . $this->config['cookie_hash']])) {

            // Request user access token via Refresh_Token
            $request = $this->MSGWPL_RequestUserToken($_COOKIE['msgwpl_refresh_token_' . $this->config['cookie_hash']], 'refresh_token');

            // If request has Access Token
            if ($request && isset($request->access_token)) {
                // Authenticate users access token
                $user = $this->MSGWPL_RequestUserProfile($request->access_token);

                // If user exists
                if (isset($user->id) && isset($user->mail)) {

                    // Attempt to login User to WP
                    $this->MSGWPL_LoginUser($user);

                }
            // If no access token
            } else {

                // Redirect to microsoft
                $this->MSGWPL_SSORedirect();

            }

        }

        // If user is not authenticated (default)
        else {

            // Get Auth Code from MS API
            if(isset($_GET["code"])) {

                // Request user access token via Authorization Code
                $request = $this->MSGWPL_RequestUserToken($_GET["code"], 'authorization_code');

                // If result has Access Token
                if (isset($request->access_token)) {

                    // Authenticate users access token
                    $user = $this->MSGWPL_RequestUserProfile($request->access_token);

                    // If $user exists
                    if (isset($user->id) && isset($user->mail)) {

                        // Attempt to login User to WP
                        $this->MSGWPL_LoginUser($user);

                    }

                } else {

                    // WP error
                    wp_die( __( 'Sorry, you are not allowed to access this part of the site.' ) );

                }

            } else {

                // Redirect to MS login
                $this->MSGWPL_SSORedirect();

            }
        }

        // Exit
        exit();
    }

    /**
     *
     * Authenticate Current User
     * Verify that current WP User and current MS Graph user are the same
     * @return Boolean
     *
    **/
    private function MSGWPL_AuthenticateUser()
    {
        // Authenticatied boolean
        $isAuthenticated = false;

        // If user is already authenticated, verify cookie with MS Graph and WP
        if(is_user_logged_in()) {

            // Get current WP user object
            $wp_user = wp_get_current_user();

            // If access token exists
            if(isset($_COOKIE['msgwpl_access_token_' . $this->config['cookie_hash']])){
                // Authenticate users access token with MS Graph
                $msg_user = $this->MSGWPL_RequestUserProfile($_COOKIE['msgwpl_access_token_' . $this->config['cookie_hash']]);
            }
            // Else if refresh token exits
            elseif(isset($_COOKIE['msgwpl_refresh_token_' . $this->config['cookie_hash']])){
                // Request user access token via Refresh_Token
                $request = $this->MSGWPL_RequestUserToken($_COOKIE['msgwpl_refresh_token_' . $this->config['cookie_hash']], 'refresh_token');

                // If request has Access Token
                if (isset($request->access_token)) {
                    // Authenticate users access token
                    $msg_user = $this->MSGWPL_RequestUserProfile($request->access_token);
                }
            }

            // If Graph user email is not equal to current WP user email
            if ($wp_user && $msg_user && (strtolower($msg_user->mail) === strtolower($wp_user->user_email))) {
                // Return true
                $isAuthenticated = true;
            }

        }

        // Return
        return $isAuthenticated;
    }

    /**
     *
     * Request user token
     * Make a request to MS Graph to request user access token
     * @param String - $code
     * @param Array - $config
     * @return Object - $data
     *
    **/
    private function MSGWPL_RequestUserToken($auth_code, $auth_type)
    {
        // Get wordpress login url, assign to $config array
        $wp_login_url = rtrim(wp_login_url(), '/');

        // Build API Token Url
        $url = "https://login.microsoftonline.com/" . $this->config['tennent_id'] . "/oauth2/v2.0/token";
        // Parameter fields
        $fields = [
            'client_id=' . $this->config['client_id'],
            'client_secret=' . $this->config['client_secret'],
            'scope=' . $this->config['scopes'],
            'redirect_uri=' . $wp_login_url,
            'grant_type=' . $auth_type
        ];

        // Validate auth_type, check for Authorization Code or Refresh Token
        if(isset($auth_type) && $auth_type === 'refresh_token'){
            $code_field = 'refresh_token=' . $auth_code;
        } else {
            $code_field = 'code=' . $auth_code;
        }

        // Push code_field value to fields array
        array_push($fields, $code_field);

        // cURL Initiate
        $ch = curl_init();

        // cURL Settings
        curl_setopt($ch,CURLOPT_URL, $url);
        curl_setopt($ch,CURLOPT_HTTPHEADER, array("Content-Type: application/x-www-form-urlencoded"));
        curl_setopt($ch,CURLOPT_POST, 1);
        curl_setopt($ch,CURLOPT_POSTFIELDS, implode('&', $fields));
        curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);

        // cURL Execute
        $data = curl_exec($ch);
        $data = json_decode($data);

        // cURL Close
        curl_close($ch);

        // Set MSGWPL access and refresh tokens as COOKIES
        // COOKIEPATH & COOKIE_DOMAIN are default Wordpress constants
        if(isset($data->access_token) && isset($data->refresh_token)){
            setcookie('msgwpl_access_token_' . $this->config['cookie_hash'], $data->access_token, time() + 3600, '/', COOKIE_DOMAIN, true, true); // Expire 1 Hour
            setcookie('msgwpl_refresh_token_' . $this->config['cookie_hash'], $data->refresh_token, time() + 259200, '/', COOKIE_DOMAIN, true, true); // Expire 3 Days
        }

        // Return response data
        return $data;
    }

    /**
     *
     * Authenticate User with access token
     * Make a request to MS Graph to request user profile
     * @param String - $token
     * @return Object - $data
     *
    **/
    private function MSGWPL_RequestUserProfile($token)
    {
        // cURL Initiate
        $ch = curl_init();

        // cURL Settings
        curl_setopt($ch,CURLOPT_URL, "https://graph.microsoft.com/v1.0/me");
        curl_setopt($ch,CURLOPT_HTTPHEADER, array("Authorization: bearer " . $token, "Host: graph.microsoft.com"));
        curl_setopt($ch,CURLOPT_RETURNTRANSFER,1);

        // cURL Execute
        $data = curl_exec($ch);
        $data = json_decode($data);

        // cURL Close
        curl_close($ch);

        // Return response data
        return $data;
    }

    /**
     *
     * Login User
     * Login user if they exist in Wordpress
     * Set SP auth cookies
     * @param Object - $user
     * @return null
     *
    **/
    private function MSGWPL_LoginUser($user)
    {
        // Get WP user by Email (provided by $user object from MS Graph)
        $wp_user = get_user_by( 'email', $user->mail );

        // If user is found
        if($wp_user){

            // If user is WP administrator or editor only
            if(in_array('administrator', $wp_user->roles) || in_array('editor', $wp_user->roles)) {

                // Clear WP auth cookies
                wp_clear_auth_cookie();
                // Set current auth user
                wp_set_current_user( $wp_user->ID, $wp_user->user_login );
                // Set WP auth cookies
                wp_set_auth_cookie( $wp_user->ID );

                // Redirect to WP Dashboard
                header('Location: ' . get_dashboard_url());

            } else {

                // WP error
                wp_die( __( 'Sorry, you are not allowed to access this part of the site.' ) );

            }

        } else {

            // WP error
            wp_die( __( 'Sorry, you are not allowed to access this part of the site.' ) );

        }

        // Exit
        exit();
    }

    /**
     *
     * Logout User
     * Logout user of Wordpress, clear cookies
     * @return null
     *
    **/
    private function MSGWPL_LogoutUser()
    {
        // Watch for default WP logout url
        if(isset($_GET["loggedout"]) && $_GET["loggedout"] === "true") {

            // Clear WP cookies
            wp_clear_auth_cookie();

            // If MSGWPL cookies exists
            if(isset($_COOKIE['msgwpl_access_token_' . $this->config['cookie_hash']]) || isset($_COOKIE['msgwpl_refresh_token_' . $this->config['cookie_hash']])){

                // Clear MSGWPL cookies
                // COOKIEPATH & COOKIE_DOMAIN are default Wordpress constants
                setcookie('msgwpl_access_token_' . $this->config['cookie_hash'], null, time()-300, '/', COOKIE_DOMAIN);
                setcookie('msgwpl_refresh_token_' . $this->config['cookie_hash'], null, time()-300, '/', COOKIE_DOMAIN);

                // Microsoft logout url
                $msg_logout = 'https://login.microsoftonline.com/' . $this->config['tennent_id'] . '/oauth2/logout?post_logout_redirect_uri=' . get_bloginfo('url');

                // WP error with user message and Microsoft Logout link
                wp_die( __( '<p>You have successfully logged out of: ' . get_bloginfo('url') . '.</p><p><b>Would you also like to logout out of your Microsoft Profile?</b><br><span style="font-size:94%;font-style:italic">(Recommended if you are using a public or shared access computer)</span></p>'), 'Logout', ['link_url'=>$msg_logout, 'link_text'=>'Yes, log out of Microsoft', 'response'=>200] );

            } else {

                // Redirect to home
                header('Location: ' . get_home_url());

            }

            // Exit
            exit();

        }
    }

    /**
     *
     * Microsoft Redirect Link
     * Redirect to Microsoft sso login page
     * @return header
     *
    **/
    private function MSGWPL_SSORedirect()
    {
        // Get wordpress login url, assign to $config array
        $wp_login_url = rtrim(wp_login_url(), '/');
        // Redirect to MS login
        return header("Location: https://login.microsoftonline.com/" . $this->config['tennent_id'] . "/oauth2/v2.0/authorize?client_id=" . $this->config['client_id'] . "&scope=" . $this->config['scopes'] . "&resource_mode=query&response_type=code&redirect_uri=" . $wp_login_url);
    }

}

/**
 *
 * Create new MSGWPLAuthUser instance
 *
**/
new MSGWPLAuthUser();
