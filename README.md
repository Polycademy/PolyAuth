PolyAuth
=========

[![Build Status](https://travis-ci.org/Polycademy/PolyAuth.png?branch=master)](https://travis-ci.org/Polycademy/PolyAuth)

PolyAuth is a PHP authentication and authorisation library that is independent from any frameworks and any databases.

NOTE: This library is not yet ready for prime time! Still need to fix some bugs. If you find any, make sure to tell me on the issues. But it's being actively worked on.

Dependencies
------------

- PHP >= 5.4.12
- PDO + MySQL or any storage adapter
- leighmacdonald/php_rbac
- ircmaxell/password-compat
- PHPMailer/PHPMailer
- php-fig/log
- tedivm/stash

Features
---------

- Authentication Flow Implementations: HTTP Basic, HTTP Digest, Hawk, Cookie, OAuth 1 & 2 Consumer Access Delegation, OAuth 2 Provider, OpenID Consumer and Persona Consumer.
- User Account Management (includes account bans) - Make sure your identity is unique, if you're using the identity as the display name, don't allow duplicate display names. You can mix up usernames and emails, so that emails are identitities and usernames are display names.
- Role Based Access Control at NIST Level 1
- Password Encryption based on Bcrypt
- Automatic Emailing for Activation and Forgotten Identity/Password (can be turned off and used manually (SMTP/mail support))
- Utilisation of loggers that support the PSR log interface
- Custom Session Handling that's extendable to many backe ends
- Manipulation of the session object such as adding in a shopping cart.
- File locks on the session file are automatically resolved by closing the handle immediately. This prevents AJAX race conditions.
- PSR 1 Compatible and Framework Independent
- PDO based Database Queries (only MySQL atm) (if using Codeigniter use $this->db->conn_id)
- Logging in & Logging out
- Optional login throttling based on exponential timeouts (timeout = 1.8^(number of attempts-1)), this can be set to ip address, login identity or both. There are advantages and disadvantages to using each.
- Autologin using a range of authentication strategies.
- SQL, Codeigniter and Phinx Migrations
- Configurable Language for Returned Errors
- Error handling through exceptions that extend from "PolyAuthException"
- Highly Configurable User Data/Profile
- Password Complexity Checks
- Excellent Random Token Generator
- Unit tested with Continuous Integration at Travis so you can trust that it works!
- Supports storage adapters for Database Independent Functionality

To Do
------

- Add OpenId provision & OpenId delegation & Persona provision
- SQL Migration, Phinx Migation
- Add Redis Persistence
- Add more storage adapters
- Add a commandline tool that allows the manipulation of RBAC, such as creating roles/permissions and doing every AccountsManager does. It should be able to parse a RBAC JSON configuration file (perhaps in YAML or JSON, definitely not ini file.) This should support hierarchies (so LEVEL 2 RBAC). Use https://github.com/nategood/commando for this binary file. Could even compile to phar! This will need database access, so we need to pass a relevant storage adapter? Perhaps pointing to a file, or command line options, also needs pointing to the relevant options to use. How about polyauth_conf.json (overload Options and DB options) and polyauth_rbac.json (permission hierarchy to process).
//Cookie strategy is vulnerable to CSRF. But not XSS when you have HTTPONLY.
//Authorisation Header is not vulnerable to CSRF. But it is vulnerable to XSS!
- Need to have the ability to ask does this user has these permissions in these set of roles (that is not counting all roles that the user owns, but only specific types of roles). This can be useful if the users themselves can also create roles for other users to access their resources.
- Regarding OAuth2 Server: https://github.com/php-loep/oauth2-server and https://github.com/bshaffer/oauth2-server-php
- Reduce PHP version requirement to 5.3 (need to do some testing)
- Streamline the storage adapter

Forgotten Password checking and reset password has somethings that need to change.

1. The forgotten_password automatically sends the email through the emailer. There needs to be a way to set this to manual. To allow the user to send the email themselves if necessary.
2. The forgotten_password functionality is a bit too complex. It should just reset the password to a random one and give that back to be sent via the email.
3. The reset_password should go directly to the database source, it should not call change_password because the change_password may throw an exception if the random generator was not random enough
The whole emailing thing needs an overhaul because emailing doesn't make sense. It should be optionally inserted and instantiated by itself with any templates passed into the class. It should not be part of the Options table.

LoginPasswordComplexity needs to be optional with just a false!

All queries should have some order by option!

UserAccount::authorized requires scopes and owners implementation

Need to compensate for nested transactions by using inTransaction boolean that is part of PDO. Ask if in a transaction before attempting to start a transaction.

Add the possibility of implementing private cloud. Private cloud versions of PolyAuth. So that data is fully encrypted in the database. Basically virtual applicance of PolyAuth.

UserAccount should be __clone, __toString and __serialise and any of the other magic functions. One way would be an easy way to export all of the UserAccount data. Since UserAccount implements array interface, it should also implement traversable interface... etc. The user data needs to be preloaded with the roles and permissions as well. One way would be a 'roles' => an array of all the roles including hierarchical roles. Perhaps it essentially is hierarchal? Also a 'permissions' => an array of all the permissions that is calculated from all inherited roles. Currently these 2 properties are not added to the user object, but are hidden in the parent objects. We need to pass this data to the client (AngularJS) so that AngularJS can calculate what to show and what not to show in the UI depending on their roles and permissions. Of course everything goes through a double authentication. First on the UI to check if the user is logged in and has the necessary role/permission/scope and then when an action is requested to view data or modify data, the request is authenticated again on the server side. The server side holds the master state, and is the ultimate judge. But the client needs to be able to show or not show particular things on its own judgement to help with user experience. You can't send an AJAX request to ask whether it is able to show things or not, all the roles and permissions will be loaded in as soon as the user is logged in.

Encryption should use phpseclib so that it can work without the mcrypt extension!
The encryption algorithm isn't secure enough. See the example here: http://au2.php.net/manual/en/function.mcrypt-encrypt.php

For QueryToken strategy:

1. Needs a queryToken field that is separate from autoCode because the autoCode is always linked to the CookieStrategy's autoCode and cannot be automatically refreshed.
2. Everytime someone logs in and has a ?query_token= field in in the URL parameters, the queryToken needs to be reset. Even if the queryToken strategy didn't get activated. This si because if the queryToken remains the same on the URL. This is essentially presenting a temporary password that is publicly available if someone looks over the shoulders or someone forgets to close the browser. The resetting logic therefore needs to be in the Authenticator strategy. Also these queryTokens should also have an expiry just like the autoCode. Perhaps queryDate?
3. The AccountsManager needs the ability to reset queryToken and queryDate and reset the autoCode and autoDate.
4. The AccountsManager/Authenticator needs the ability to log out everybody, by destroying all sessions, or destroying all access tokens, all autoCodes, all queryTokens, all IP authorisations, and all user-agent device authorizations. Furthermore it should also be able to do this for a single account. This is useful if an account gets compromised. This requires the SessionManager to get all sessions and find the ones that match a particular user id.

PolyAuth should standardise the options class and use it for all options to keep it one place. Research better presentation and perhaps use something like Symfony Options.. Device tracking uses user agent and will have to deal with empty user agents. Empty user agents should be considered as suspicious. But there will be different levels of suspicion: Maximum suspicion, block all user agents not added to the list of approved user agents. Or high, block user agents that are not recognised major browsers or similar browsers (like different versions of Firefox if the user always uses Firefox!). Everything can have a whitelist. There can even rules between ip address and user agent. Of course, block all ip addresses that originating from previous logins!

Remember to suggest GEO-IP2 for finding the Location of the IP. Geo IP would be good to use if one needs to know if the IP is not in the same location. We could just ban all ips that are dissimilar. Just remember this is a problem if people use dynamic IPs. So location: city based tracking would be more lenient, but require the GEO IP add on. https://github.com/maxmind/MaxMind-DB-Reader-php

Supply autoloader for each library even if composer is available. Also Dragoon needs an autoloader that is capable of autoloading external modules, register PSR-4 and PSR-3 modules in case they are brought into the source code. Also cut down on simple external dependencies. I think PolyAuth doesn't need the PHP Mailer, there should be functions that return the email data. Also provide variable dependencies that uses the ~ operator for PolyAuth for certain dependencies. Imagine someone registers, instead of auto sending an email. If you want to send an email, you call the function get_activation_data/email() and this will give you back an array of data relevant to activating somebody.

Definitely add in ip location tracking and 2 factor login!! Multidevice tracking too. Multifactor login. Like logging into a new ip or new device.

Use next significant release for the composer dependencies! ~ https://getcomposer.org/doc/01-basic-usage.md#next-significant-release-tilde-operator-

Support for Client Certificate Authentication/Mutual Authentication strategy: http://nategood.com/nodejs-ssl-client-cert-auth-api-rest
http://blog.nategood.com/client-side-certificate-authentication-in-ngi
http://cweiske.de/tagebuch/ssl-client-certificates.htm
http://pilif.github.io/2008/05/why-is-nobody-using-ssl-client-certificates/ (Client Certificate Auth is for enhancing password usage, not replacing password usage. Since that native 2 factor because it's about something you have, and something you know. This means that passwordless SSH is actually less secure. The best would be to combine a certificate that you must have, and a password you know. In a way this strategy can allow passwordless login or with password login too!)
http://wiki.cacert.org/Technology/KnowledgeBase/ClientCerts

Multi device authentication.

Tracking logging in statistics from devices.

And tracking login statistics in general.

Can authorise from different devices, and alerting via email when logging in from a new device. Then keeping track of the device.

http://blog.authy.com/multi-device

Also just like steam guard + gmail! 

Add a sudo mode. To allow reauth for important actions: https://help.github.com/articles/sudo-mode

Use HMAC client tokens. This much better than storing tokens on the server side: http://lucumr.pocoo.org/2013/11/17/my-favorite-database/ The tokens might still need to be stored on the server side, but now the associated information like expiration date can be stored on the client side! One could actually simply store the token as an encrypted version of the user's id. Get the ID, and then you know which user this applies to!

Test with hhvm. The PolyAuth service may require hhvm + Dragoon.

```
language: php

php:
  - 5.3
  - 5.4
  - 5.5
  - hhvm

script:
  - phpunit --coverage-text
  - phpunit --group unicode --coverage-text

matrix:
  allow_failures:
    - php: hhvm
  fast_finish: true
```

Non activated accounts should not be prevented from logging in. Many sites allow partial access to their account, or even setting up settings, before being activated properly. Perhaps even set a time limit, that if the account hasn't been activated yet, it gets deleted (cant be banned). We need to have a STATUS column to indicate primary status. ACTIVE - BANNED - UNACTIVATED - DELETED (soft delete) - PENDING. Or these can be roles that are created, and assigned to the USER. The RBAC should take over this. In the sense that if an account is not activated then it lacks certain permissions.

Account merging so when there are 2 accounts, you can merge ownership and proxy the account to a primary account.

Install with Composer
---------------------

```
"polycademy/polyauth": "*"
```

Testing
-------

Use --defer-flush with Codeception

Notes
-----

Make sure the `session_save_path()` is writable!

This does not do filtering or validation of data input. You still need to do this to prevent any problems. This does not do CSRF checks. I do not consider that to be part of a user authentication system. This also does not force you or check for SSL, that should be your job!

Authorization header needs to be available to the PHP runtime. Apache and Fast-CGI will work. However PHP-FPM currently does not support `getallheaders()`, but most web servers such as NGINX will pass the Authorization header. If you're paranoid, just check if `HTTP_AUTHORIZATION` is present your `$_SERVER` global variable, and if isn't you'll need to manually it in the web server configuration. Test with a non HTTP basic Authorization header. It could just be `Authorization: Lol`.