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

}

/**
 *
 * Create new MSGWPLAuthUser instance
 *
**/
new MSGWPLAuthUser();
