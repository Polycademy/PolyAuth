PolyAuth
=========

PolyAuth is a PHP authentication and authorisation library that is framework independent.

It relies on this current stack:

PDO + MySQL (although may work with any SQL database that supports foreign keys)
Aura/Session
leighmacdonald/php_rbac
ircmaxell/password-compat
PHPMailer/PHPMailer
php-fig/log

Features:

- User Account Management
- Role Based Access Control at NIST Level 1
- Password Encryption based on Bcrypt
- Automatic Emailing for Activation and Forgotten Identity/Password (can be turned off and used manually (SMTP/mail support))
- Utilisation of loggers that support the PSR log interface
- Automatic Session Handling based on PHP sessions but extendable by Session Handler Interface
- PSR 1 Compatible and Framework Independent
- PDO based Database Queries
- Logging in & Logging out
- Autologin with Cookies
- SQL setup as Codeigniter Migrations (easy to turn into your own)
- Configurable Language for Returned Errors
- Highly Configurable User Data/Profile
- Password Complexity Checks
- Excellent Random Token Generator

To Do:
- OAuth 1 & 2 Consumer
- OAuth 2 Provider

Install with Composer:
"polycademy/polyauth": "*"