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

This does not do filtering or validation of data input. You still need to do this to prevent any problems. This does not do CSRF checks. I do not consider that to be part of a user authentication system. This also does not force you or check for SSL, that should be your job!