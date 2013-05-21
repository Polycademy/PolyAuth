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

- User Account Management
- Role Based Access Control at NIST Level 1
- Password Encryption based on Bcrypt
- Automatic Emailing for Activation and Forgotten Identity/Password (can be turned off and used manually (SMTP/mail support))
- Utilisation of loggers that support the PSR log interface
- Automatic Session Handling based on PHP sessions but extendable by Session Handler Interface
- PSR 1 Compatible and Framework Independent
- PDO based Database Queries (only MySQL atm)
- Logging in & Logging out
- Autologin with Cookies
- SQL and Codeigniter Migrations
- Configurable Language for Returned Errors
- Error handling through exceptions that extend from "PolyAuthException"
- Highly Configurable User Data/Profile
- Password Complexity Checks
- Excellent Random Token Generator
- Authentication Strategy Interface - Can be used for (HTTP Basic/Digest, Cookie, OAuth 1 & 2 Consumer, OAuth 2 Provider, OpenID)
- SpecBDD tested with Continuous Integration at Travis so you can trust that it works!
- Optional caching library involving APC or Filesystem. It's also extendable with the caching interface.

To Do:

- Storage Interface for Database Independent Functionality, will need to abstract PHPRBAC
- User Access Logs (just use Monolog)
- Complete SQL Migration
- Complete Authentication Strategy Interface

Note that this does not do filtering or validation of data input. You still need to do this to prevent any problems.
This does not do CSRF checks. I do not consider that to be part of a user authentication system.

Install with Composer:

"polycademy/polyauth": "*"