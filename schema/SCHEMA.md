SCHEMA
======

PolyAuth is a stateful library. Therefore it needs a schema for both durable and temporal state. For every stateful adapter that is added to PolyAuth, a suite of tests need to be written for the adapter. Even "schemaless" NoSQL needs have structure imposed, or else all we get is implicit schema, and nobody knows how to interact with the data.

Durable Schema
--------------

These are schemas related to durable data.

Currently we support schemas in:

* MySQL

Any seed data is provided by the CLI tool, not by the schema.

Temporal Schema
---------------

These are schemas related to temporal data. There aren't explicit schemas, as these are defined at runtime. However the following describes the type of data that is stored.

Any seed data is provided by the test themselves, not the schema.

1. Login attempt data
pa_login_attempts => Converted to cache. Now we have to store all login attempts, but also can purge them. Also login attempts are discovered by either identity, or ip address or both. 
2. Session data
pa_sessions => Converted to cache (this is server held session data for the particular request, if the session id is kept, the session data is kept, note that session data can just as easily be done from the client side instead). This also keeps the IP ADDRESS data. Because the ip address is not relational to the account, but relational to the session. Furthermore, it will also include the lastLogin time, because this is relational to the SESSION.
3. Token data
pa_tokens -> activation time + token code!
pa_tokens - Long lived tokens (forgotten password, activation, one time login tokens, autologin tokens, change (change emails or change passwords, anything that requires a third party activation, unstaged changes will be encoded into the request, we won't keep that state) tokens, sudo token (which means the user has verified their login details within a set of time)). All these tokens have a expiry date. Each token is linked to a userId. Forgotten password and activation tokens are one to one. One time login tokens can also be one to one, or one to many.

Our Cache needs to support:

1. Login Attempts
    a) identity
    b) ipAddress
    c) count increment
2. Session Data (this can be committed to a log for tracking)
    a) ipAddress
    b) lastLogin
    c) expiry (refreshed upon each access)
    d) sudo - sudo mode
3. Token Data:
    a) forgottenCode & forgottenExpiry
    b) activationCode & activationExpiry
    c) autologinCode & autologinExpiry
    d) confirmCode & confirmExpiry -> for password change confirmation, but also authorisation confirmation (for device tracking for example)
    e) loginCode & loginExpiry

All of which expire over time. So this is why an in-memory cache is useful here, as it can do automatic garbage cleaning over time.