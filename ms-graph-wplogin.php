<?php
/***
* Plugin Name: MS Graph WP Login
* Description: Enable Wordpress login via Microsoft Graph API using an enterprise Tennent ID and Active Directory.
* Version: 1.0
* Author: Russell Ramey
* Author URI: https://russellramey.dev/
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

        // If $definded_config is validated
        if($this->valid_config){
            // Add action to wp login redirect
        }
    }

    /**
     *
     * Redirect WP Login
     * Main login url redirect function
     * @return null
     *
    **/
    private function MSGWPL_LoginRedirect()
    {

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
     * Make a request to MS Graph with returned Access Token to validate user
     * @param String - $token
     * @return Object - $data
     *
    **/
    private function MSGWPL_AuthenticateUser($token)
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
