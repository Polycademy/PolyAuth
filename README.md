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

Activation: four ways:

1. Prevent login - Option or RBAC (in fact, one could have login callbacks of some sort...?)
2. Allow full access but need activation within certain amount of time - Reimplementation
3. Prevent features unless fully activated - RBAC
4. What happens if the user changed their email? Is the account still activated? I think changing the email needs the email to be revalidated, unless you don't care. In most cases, changing the email require that email to be confirmed, because the change is committed.

There needs to be an easy way to figure out whether a user owns a particular resource? Often actions are only allows if the user owns a particular resource, and this can occur in a collection resource too. Such as being able to delete a resource of a collection.

The solution to this is to have an `auth_resources` table:

(id might not be required as users is 1 to 1 for this auth_resources table)
Also this means you do not need any userId columns on other tables now.
(Removed the id, lets keep it lean)
| userId (primary indexed) | blogIds | logIds | commentsIds | resIds... | 

    1                         {4}      {2,4}        {78}         {9}... (the {} is serialized)

This is an relational table creating a many to many to many relationship between `users`, `collections`, and `resources`. Remember this has nothing to do with OAuth delegated resource requests. Multiple users can own the same resource. In this of delegation, you must check the relational entities in the other table where access token table. This is therefore a table in which users delegate access tokens to other users... etc

User1 - - CollectionA - Resource76
    \                \
     \                Resource89
      \
       \               Resource12 (Owned by both User1 and User2)
        \            /
        CollectionB - Resource25
      /
User2 
      \
        CollectionC - Resource4

On the creation or deletion or updating of collections, a corresponding column is created in the auth_resources table.

This allows us to establish relational ownership of resources between users.

Allowing validation of requests to be simply:

$this->user->authorized([
    'owners' <--  this actually refers to delegated requests I think, basically you know what the resource's owner is, so then you check if the user currently has the ability to access this ownership, either as the user itself, as delegated access, it needs a better name!
    'resources' => [ (AND BASIS)
        'blog (resource)'  => id
        OR
        'blog (resource)'  => [id, id]
    ]
])

OR

resources => ['blog#4', 'log#9']

OR

resources => 'blog4'

This means you can do this in many requests:

if($this->user->authorized([
    'roles' => 'admin'
], [
    'resources' => 'blog#4'
])){
    
    //proceed with the knowledge that the user either is an admin, or owns the 4th blog post

}

All tables need to be standardised under auth_... etc.

Also on startup, these things will be parsed and loaded under the user account object.

foreach($resources as $key => value){
    $key ---> blog..etc
    $value ---> unserialize($value) ---> [4, 5, 6, 7, 8]
}

AUTH RESOURCES should use CLOSURE TABLE method. IT's the best for MySQL.
http://www.slideshare.net/billkarwin/models-for-hierarchical-data

BTW we should shift to using Collection objects rather than arrays.

Now updating this auth_resources table involves 2 things, either adding more columns to represent resources (finite) or adding more ids to a particular collection. It should be done through the accounts_manager class. Because the user_account object is temporal, it's a copy not a reference to the saved user_account object.

Also use json_encode/decode not serialize/unserialize. The encoding is faster, decoding is slightly slower, but the size is much better with json_encode/decode, also it's easily readable and processable by other languages.

Hierarchal RBAC can be turned into Hierarchal object namespaced permissions. This allows roles to be interchangeable with multitenancy such as organisations. No longer checking for roles or permissions, instead you just check permissions => 'role.subrole.permission'. Hierarchal permissions! Since permissions are namespaced, they can have the same name. Thus a UI could be built for it.

SessionManager should use the Cache interfaces like PoolInterface and DriverInterface.
The point is SessionManager needs a persistence object.
The persistence object can be SessionPersistence.
This thing requests a Stash\Interfaces\PoolInterface essentially the cache to be put in. This should eventually be standardised into PSR-6 caching interface.
And that's it. We shift the complexity and the flexibility of setting up the cache to the end user.
Also everything should be DI based and interface based, no more creating default dependencies.
Instead of requesting an Options object, request an array. And pass in global options when needed, pass in specific options when otherwise. Also collection object would be better! Since you could have something like lenient array access.

Remove Emailer, instead create Interfaces folder holding a Notification interface that allows PolyAuth to notify people in whatever ways they want.

Create a Config folder holding Options and Language.

Create Utilities folder and put the utilities into this including the LoggerTrait and Random and other stuff.

Temporary tokens like Autologin token, forgotten password token, temporary login tokens should be moved to a separate table. These are temporary, so they could even be put in something like Redis or other caching systems.

Note that OAuth tokens are permanent, so they need to be put into a safe data source.

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

Plan
----

Account federation/joining is definitely required. Especially if one has created the same account twice. Will set one as precedent, and the other as merging.

Use the new collection: https://github.com/schmittjoh/php-collection/pull/15

Links:
http://www.php.net/manual/en/spl.exceptions.php
https://github.com/schmittjoh/php-option
http://jmsyst.com/libs/php-collection
http://jmsyst.com/libs/serializer
http://symfony.com/doc/current/components/options_resolver.html
www.slideshare.net/billkarwin/models-for-hierarchical-data (RELATIONAL TO USERS)
https://github.com/piwik/device-detector/issues/1

FSM for the users

registered - INITIAL
unactivated - NORMAL
activated - NORMAL
banned - FINAL

registered -> activated => activation
registered -> banned => banning
registered -> unactivated => deactivation

unactivated -> activated => reactivation
unactivated -> banned => banning

activated -> banned => bannding

FSM for the tracking

unconfirmed (initial) -> confirmed (final) => confirming


WE NEED A STATELESS EMAIL ACTIVATION MODEL!

Stateless solution

    Take email of the user and sign it cryptographically
    Send email to the user with the link to our website containing the signature
    Once user has clicked the link in the email, verify digital signature and if it's valid, we confirm his email

This could be done for every token. Then we don't need the database fields to hold the state of the token!

Basically the idea is that, PolyAuth has a private key and "unknown" cryptographic algorithm, it takes the email address and encrypts it while signing it with the key. When the signed encrypted comes back, we decrypt it, and check if the email exists on our system. We could even sign it with additional parameters like timestamp, which would allow us to make sure codes are only fresh for a particular period of time. http://lucumr.pocoo.org/2013/11/17/my-favorite-database/
I think the user ID also needs to be part of the payload. Maybe...

NOTES
-----

pa_identities - Subjects and their permanent profile data + user state. Anything else should be stored somewhere else. This includes both owners and clients, meaning both owners and clients are subjects.
pa_tokens - Long lived tokens (forgotten password, activation, one time login tokens). All these tokens have a expiry date. Each token is linked to a userId. Forgotten password and activation tokens are one to one. One time login tokens can also be one to one, or one to many.
pa_providers - List of: id, userId, providerName, providerUniqueId, one identity to many providers (meaning federated providers). Each provider record is a one to one link to access_delegation record (which will always be an external access token). Identities that are provisioned by PolyAuth is not recorded here.
pa_roles - Roles are like a common set of permissions required to execute a particular function in an organisation. Roles are also the scopes. Roles are assigned to subjects.
pa_permissions - Permissions are setup here and called upon by resources. They are assigned to to roles.
pa_access_delegation - Contains access tokens relating to owners (identities), clients (subjects) and providers (can be PolyAuth itself). Every identity can have access tokens in which it is an owner, but it can also have access tokens in which it is the client. This means identities can both delegate access to other identities, and can be delegated access from other identities.
pa_security_log - Actions by the user that is logged and remembered. This might 
pa_associations -> Closure Table, associates subjects with tokens, providers, roles, roles to permissions, subjects to access_delegation, to security_log.
pa_tracking -> Login tracking, everytime someone logs in, we'll take their fingerprint, and compare against previous fingerprints. If they don't match, we'll raise an exception which can be handled to be notified. Just like Steamguard. Also we can't match exact IPs although that is possible, it's better to use countries.

1. Login attempt data
pa_login_attempts => Converted to cache. Now we have to store all login attempts, but also can purge them. Also login attempts are discovered by either identity, or ip address or both. 
2. Session data
pa_sessions => Converted to cache (this is server held session data for the particular request, if the session id is kept, the session data is kept, note that session data can just as easily be done from the client side instead)

EMAILS:

1. If they are a unique record:
    a) Makes a hell of a lot easier to "login" with passwords when necessar
    b) Means that anytime anyone tries to login via a third party provider, if the provider provides the same email address but not the same provider id, then an account will not be created, and instead an exception is thrown. The developer should login into their previous account and merge accounts instead. If the previous account was an account with a external provider, they can use forgotten password, which would generate one. Unless of course the email did not exist, which can be true in the case of Twitter. At any case, the guaranteed path is to login via the third party again. Unless of course the third party no longer exists or is operational. At this point, an escalation is required, an admin will need to change this account. Specifically by adding an email, and allowing the person to "forgotten" password.
    c) Normal signup does not allow duplicate emails.
2. If they are not a unique record:
    a) Means logging in with emails is a lot of harder. This would require us to differentiate between accounts which are loginable, and accounts which are not. This means there has to be a unique combination of email and password. That is, no 2 identities must have the same email and password. So if there are identities with the same email, but no password or different password, this will not be loginnable. The same password cannot be allowed with the same email, and this would be prevented during the profile editing phase/password generation/password change phase.
    b) Logging in with third party providers is easy.
    c) Normal signup allows duplicate emails, or not allow duplicate emails... it depends. If you're using OAuth, then you should prevent duplicate emails.

If you are not using email as login identity, then this is irrelevant. That is, email does not need to be a unique record, and and you won't be logging in with emails anyway.

The above applies to usernames as well. Except that if usernames is unique, then you don't have to prevent the creation of the account, but you can just modify the usernames by adding a random suffix.

One could also have "display names".

THE SIMPLEST SOLUTION IS:

1. EMAILS ARE UNIQUE
2. 


Convert to PSR-4
Add a bootstrap?

DEVELOP  HRBAC

Also Options class implements Config class. We need this to be typehinted, such that an array object can be entered.

All collections are implemented as collections.
When passed into objects, they need to pass through iterator_to_array().

OK so Configuration and Language will be bassed as Config objects.

Objects expecting configuration do not typehint for array.
Instead they check if the object is traversable.

How about this:

Configular reads the configuration.
Options object takes Configula, and maps it into a collection object.
Objects expecting options will check for whether it's an array or Traversable. If Traversable, it will change it to array before proceeding. Then also use OptionsResolver. Everything is injected.


OK with regards to email addresses or even usernames.
Because we cannot trust remote services to make sure that a subject actually owns a particular email address, and that different providers will have subjects using the same email address and also potentially username. We will create a new identity for every unique providerId. This means acquiring basic data like username and email data and adding them into the database of identities. This means there can be multiple identities with the same username and the email address. This effects password login and password signup:
1. Password login operates on a one of any rule. It checks for any records matching the login identity, if there are multiple, it checks if the password matches any of them.

Mutual SSL Auth!
http://www.codeproject.com/Articles/326574/An-Introduction-to-Mutual-SSL-Authentication

Kato Sign Up/Sign in Flow

1. Ask for Email
2. Send activation (stateless style)
3. Allow usage immediately (timed activation, repeated reminders to activate, every time you use it)
4. Allow repeat activation
5. Passwordless session for the duration of usage without actiavtion
6. Once activated, asks for password (upon activation, and upon signing in (with email))

Things that are missing: Social Sign In, Open ID, Composable auths...
Perhaps with social sign in, you can skip all those, and proceed to using the app immediately, while allowing the user to set passwords and email addresses later (confirm email address upon setting)

User FSM:

Registered 
  -> activation -> Activated
    -> banning -> Banned
  -> deactivation -> Unactivated
    -> reactivated -> Activated
    -> banning -> Banned
  -> banning -> Banned

OCR Model:

Owner authenticates against the Client and Resource.
Client authenticates against the Resource
Resource grants the Client access on behalf of the Owner

O - Owner - a user
C - Client - an user
R - Resource

Auth Code:
O - Roger
C - PolyAuth
R - Facebook

Implicit:
O - Roger
C - PolyAuth (running Publicly)
R - Facebook

Resource Owner Password:
O - Roger
C - SPA (client app)
R - PolyAuth

Client Credentials
O - SPA
C - SPA
R - PolyAuth

Non Use of OAuth
O - Roger
C - Roger's HTTP Client (unknown)
R - PolyAuth

Every access token is a unique relaionship between a Client, Owner and Resource.
Every access token is held by the Client.
Clients can have many access tokens.
Each access token has a particular set of scopes associated with a particular Owner and Resource.
The Resource grants auth to the Client based on the Client's Roles + Permissions AND the Client's Access Token's Scopes based on the Access Token's associated Owner.
Permission hierarchy is defined by: Client Access Token (Scope + User) < Clients Roles + Permissions.
Access token scope + user is overwritten by (overrode) the Client's Roles + Permissions.

Permission Model:

All permissions are derived from:

C - Write permissions
R - Read permissions
U - Update permissions
P - Patch permissions
D - Delete permissions

They should be encoded via binary numbers. So you can kind of do C & R ... etc.

Every resource can have many permissions.
Every resource can have sub resources.
Every resource could have abstract resources.
Resources are operated like a directed graph. (Graph database)
Permissions for categorically abstract resources map onto child subresources.

Therefore scopes are just permissions relative to a particular user account resource.
User accounts are pretty abstract resources, thus containing many sub/child resources. For example User's Comments, User's Blog Posts.
The sub resource inherits the parent resource.
Because resources are in a graph model, each resource can be hierarchally child of many parent resources.
For example a blog post may be subject to the Blogs resource, but because each blog post is created and owned by a User, they also fall subject to the User X's Blogs resource, where X is the particular user ID.
So it's a many to many graph model of hierarchal inheritance: http://blog.neo4j.org/2010/03/modeling-categories-in-graph-database.html
This means a immutable graph database is the best tool to model this. Other databases can store temporal domain representations for when you need more efficiency (such as for example when we convert MySQL's row model into an object model).
I recommend Neo4j or FoundationDB.

This means roles are simply convenience wrappers or syntactic sugar for specifying many permissions in one go. Packaged permissions basically.

Given a graph model of resources, one could setup transactions across the directed graph. This should be pretty seamless, so that say if one of the resources in the graph hit an exception (because perhaps of a permission not allowed), it should throw an exception (this might have to be done through a wrapper, exceptions static class, and this will check if the pipeline has be transacted or partial, if transacted, it should fail hard and rollback everything, if partial, it should fail soft, ignore move on to the next independent operation)

Ok, let's imagine our resources are in a graph. Now every resource has their set of CRUPD permissions, this doesn't have be saved, the model is dynamic specified in code.

Clients are the objects that hold permissions (and their associated roles). If they have a roles, this gets automatically flattened and merged as a set of permissions (all permissions are unique btw, because CRUPD is always linked a single resource). Now what they essentially have is R1:CRUPD, R2:CRUPD, R3:CRUPD. But instead of specifying low level RXs, those RXs can be high level resources. Remember how permissions are hierarchal, as the subresource permissions inherit from parent resource permissions. So say for example, if I give the permission to read blog posts, hence BLOGS:R, theis means the user can also read blog post 1, or blog post 2, so BLOGS:R means BLOGS->BLOG1:R and BLOGS->BLOG2:R. UNLESS say BLOG2 said must have permission to read "STRICT", meaning the user must have the read permission strictly for this. This reduces storage size, since we don't have to remember that a client has all the subpermissions, but just the highlevel permissions, and the resources when asking for a permissions, simply traverse the inheritance chain.

Thus scopes and permissions are merged!
Roles are just syntactic sugar for scopes and permissions, and can be assigned to both clients or access tokens! They expand into permissions eventually.