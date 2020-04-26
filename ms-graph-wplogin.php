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

}

/**
 *
 * Create new MSGWPLAuthUser instance
 *
**/
new MSGWPLAuthUser();
