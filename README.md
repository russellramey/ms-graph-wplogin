# Microsoft Graph Wordpress Login
Create a single sign on experience for Wordpress users who all belong to the same organization, and that organization utilizes Microsoft Azure and Active Directory. This plugin will enable Wordpress login via Microsoft Graph API using an enterprise Tennent ID and Active Directory. Redirect login request to Microsoft to authenticate if valid Microsoft user under supplied organization Tennent ID. Return back to Wordpress login page with authenticated user. If authenticated Microsoft user has a Wordpress account using the same authenticated email, user will be automatically logged in as a Wordpress user, and redirected to the default Wordpress Dashboard.

## Setup
1. Register new application with Microsoft Azure
2. Setup newly registered Azure application to generate Client ID and Client Secret
3. Add Wordpress login url as the authenticated Redirect Url within the Azure application web client options
4. Modify the `wp-config.php` file, define required constants: `MSGWPL_TENNENT_ID`, `MSGWPL_CLIENT_ID`, `MSGWPL_CLIENT_SECRET`
5. Install, and activate the plugin

## Define constants in wp-config
Open the `wp-config.php` file, and look for the area towards the bottom of the file. You will see a comment that says `"That's all, stop editing."`. Place the below code just above that comment. **Without these constants defined the plugin will not work**.

```php
    // This is the enterprise organization ID
    define('MSGWPL_TENNENT_ID', 'YOUR-VALUE-HERE');

    // This is the Client ID of the registered Application within Azure
    define('MSGWPL_CLIENT_ID', 'YOUR-VALUE-HERE');

    // This is the Client Secret of the registered Application within Azure
    define('MSGWPL_CLIENT_SECRET', 'YOUR-VALUE-HERE');
```

Replace `YOUR-VALUE-HERE` with the information that Microsoft provided you when you created your application. Having these values stored in the `wp-config.php` file, helps protect the privacy and security of your application credentials. For even better protection you can enable domain whitelists within the Microsoft Azure application dashboard (recommended).
