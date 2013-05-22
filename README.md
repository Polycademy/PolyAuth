PolyAuth
=========

PolyAuth is a PHP authentication and authorisation library that is framework independent.

It relies on this current stack:

PHP >= 5.4.0 (due to special session functions)
PDO + MySQL (although may work with any SQL database that supports foreign keys)
Aura/Session
leighmacdonald/php_rbac
ircmaxell/password-compat
PHPMailer/PHPMailer
php-fig/log
tedivm/stash

Features:

- User Account Management (includes account bans)
- Role Based Access Control at NIST Level 1
- Password Encryption based on Bcrypt
- Automatic Emailing for Activation and Forgotten Identity/Password (can be turned off and used manually (SMTP/mail support))
- Utilisation of loggers that support the PSR log interface
- Automatic Session Handling (with optional encryption) based on PHP sessions. You can extend it from EncryptedSessionHandler or implement your own SessionHandlerInterface
- Manipulation of the session object such as adding in a shopping cart.
- File locks on the session file are automatically resolved by closing the handle immediately. This prevents AJAX race conditions.
- PSR 1 Compatible and Framework Independent
- PDO based Database Queries (only MySQL atm)
- Logging in & Logging out (with optional timeout based login throttling based on cookies and/or ip address)
- Autologin using a range of authentication strategies.
- SQL and Codeigniter Migrations
- Configurable Language for Returned Errors
- Error handling through exceptions that extend from "PolyAuthException"
- Highly Configurable User Data/Profile
- Password Complexity Checks
- Excellent Random Token Generator
- Authentication Strategy Interface Server Side Implementation - Can be used for HTTP Basic, Cookie, OAuth 1 & 2 Consumer Access Delegation, OAuth 2 Provider, OpenID, Hawk and Oz. (HTTP Digest is not supported due to its crytographic constraints)
- SpecBDD tested with Continuous Integration at Travis so you can trust that it works!
- Optional caching library involving APC or Filesystem. It's also extendable with the caching interface.

To Do:

- Complete Authentication Strategies
- Complete SQL Migration
- User Access Logs (just use Monolog)
- Storage Interface for Database Independent Functionality, will need to abstract PHPRBAC

Note that this does not do filtering or validation of data input. You still need to do this to prevent any problems. This does not do CSRF checks. I do not consider that to be part of a user authentication system.
This also does not force you or check for SSL, that should be your job!

Install with Composer:

"polycademy/polyauth": "*"