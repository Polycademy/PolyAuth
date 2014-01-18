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