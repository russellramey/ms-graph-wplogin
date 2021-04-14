<?php
/***
* Plugin Name: MS Graph WP Login
* Description: Enable Wordpress login via Microsoft Graph API using an enterprise Tennent ID and Active Directory.
* Version: 1.0
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
            // Add action to redirect wp login url
            add_action( 'login_redirect', function(){
                // Call private function directly
                $this->MSGWPL_LoginRedirect();
            });
            // // Add action to all wp-admin requests, validate current user
            // add_action( 'admin_init', function(){
            //     // Validate existing user
            //     if(!$this->MSGWPL_AuthenticateUser()){
            //         // WP error
            //         wp_die( __( 'Sorry, you are not allowed to access this part of the site. Please <a href="' . wp_login_url() . '">login</a> to continue.' ) );
            //     };
            // });
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

        // If user is not authenticated
        } else {

            // Get wordpress login url, assign to $config array
            $wp_login_url = rtrim(wp_login_url(), '/');

            // Get Auth Code from MS API
            if(isset($_GET["code"])) {

                // Request user access token
                $request = $this->MSGWPL_RequestUserToken($_GET["code"], $this->config);

                // If result has Access Token
                if ($request->access_token) {

                    // Save access and refresh tokens as COOKIES
                    // COOKIEPATH & COOKIE_DOMAIN are default Wordpress constants
                    setcookie('msgwpl_access_token', $request->access_token, time() + 3600, COOKIEPATH, COOKIE_DOMAIN);
                    setcookie('msgwpl_refresh_token', $request->refresh_token, time() + 3600, COOKIEPATH, COOKIE_DOMAIN);

                    // Authenticate users access token
                    $user = $this->MSGWPL_RequestUserProfile($request->access_token);
                    // If $user exists
                    if (isset($user->id) && isset($user->mail)) {

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

                    }

                }

            } else {

                // Redirect to MS login
                header("Location: https://login.microsoftonline.com/" . $this->config['tennent_id'] . "/oauth2/v2.0/authorize?client_id=" . $this->config['client_id'] . "&scope=" . $this->config['scopes'] . "&resource_mode=query&response_type=code&redirect_uri=" . $wp_login_url);

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
        if(is_user_logged_in() && isset($_COOKIE['msgwpl_access_token'])) {

            // Authenticate users access token with MS Graph
            $user = $this->MSGWPL_RequestUserProfile($_COOKIE['msgwpl_access_token']);
            // Get current WP user object
            $wp_user = wp_get_current_user();

            // If Graph user email is not equal to current WP user email
            if ($wp_user && (strtolower($user->mail) === strtolower($wp_user->user_email))) {

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
    private function MSGWPL_RequestUserToken($code, $config)
    {
        // Get wordpress login url, assign to $config array
        $wp_login_url = rtrim(wp_login_url(), '/');

        // Build API Token Url
        $url = "https://login.microsoftonline.com/" . $this->config['tennent_id'] . "/oauth2/v2.0/token";
        $fields = 'client_id=' . $this->config['client_id'] . '&client_secret=' . $this->config['client_secret'] . '&scope=' . $this->config['scopes'] . '&grant_type=authorization_code' . '&code=' . $code . '&redirect_uri=' . $wp_login_url;

        // cURL Initiate
        $ch = curl_init();

        // cURL Settings
        curl_setopt($ch,CURLOPT_URL, $url);
        curl_setopt($ch,CURLOPT_HTTPHEADER, array("Content-Type: application/x-www-form-urlencoded"));
        curl_setopt($ch,CURLOPT_POST, 1);
        curl_setopt($ch,CURLOPT_POSTFIELDS, $fields);
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

            // Clear SSO cookies
            // COOKIEPATH & COOKIE_DOMAIN are default Wordpress constants
            setcookie('msgwpl_access_token', null, time()-300, COOKIEPATH, COOKIE_DOMAIN);
            setcookie('msgwpl_refresh_token', null, time()-300, COOKIEPATH, COOKIE_DOMAIN);

            // Redirect user to home page
            header('Location: ' . home_url());

            // Exit
            exit();

        }
    }

}

/**
 *
 * Create new MSGWPLAuthUser instance
 *
**/
new MSGWPLAuthUser();
