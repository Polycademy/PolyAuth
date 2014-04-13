-- PolyAuth Testing Schema
-- For MySQL Testing

/**
 * Configuration
 */

SET @database = 'test';
SET @table_prefix = 'pa_';
SET @table_accounts = CONCAT(@table_prefix, 'accounts');
SET @table_groups = CONCAT(@table_prefix, 'groups');
SET @table_roles = CONCAT(@table_prefix, 'roles');
SET @table_permissions = CONCAT(@table_prefix, 'permissions');
SET @table_providers = CONCAT(@table_prefix, 'providers');
SET @table_delegation = CONCAT(@table_prefix, 'delegation');
SET @table_tracking = CONCAT(@table_prefix, 'tracking');
SET @table_security = CONCAT(@table_prefix, 'security');
SET @table_associations = CONCAT(@table_prefix, 'associations');

/**
 * Creating the test database
 */

SET @database_create = CONCAT(
    'CREATE DATABASE IF NOT EXISTS ', 
    @database, 
    ' DEFAULT CHARACTER SET utf8 COLLATE utf8_general_ci'
);
SET @database_use = CONCAT('USE ', @database);

PREPARE statement FROM @database_create;
EXECUTE statement;
PREPARE statement FROM @database_use;
EXECUTE statement;

/**
 * PolyAuth Accounts
 * Accounts table specifies a collection of accounts that are registered as part of PolyAuth.
 * This means all users and clients. There is no distinction between human users and robot clients.
 * Which means in the case of OAuth, third party clients and users are both registered here.
 * It is possible for a human user to have multiple accounts due to OAuth or multiple identities.
 * Multitenancy can be resolved with roles or groups or both.
 * User status can be: registered, activated, unactivated, or banned.
 */

SET @account_create = CONCAT(
    'CREATE TABLE IF NOT EXISTS ',
    @table_accounts,
    ' (
        `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
        `status` varchar(50) NOT NULL DEFAULT '',
        `email` varchar(255) NOT NULL,
        `username` varchar(255) NOT NULL,
        `password` varchar(255) NOT NULL,
        `passwordChange` tinyint(1) NOT NULL DEFAULT '0',
        `sharedKey` text NOT NULL,
        `date` datetime NOT NULL,
        `profile` text NOT NULL,
        PRIMARY KEY (`id`)
    ) ',
    ' ENGINE=InnoDB DEFAULT CHARSET=utf8'
);

PREPARE statement FROM @account_create;
EXECUTE statement;

/**
 * PolyAuth Groups
 * Groups table allows accounts to associate each other into a particular group.
 * Do not use Groups for assigning roles or permissions. Use the RBAC instead.
 * This is intended as a flexible way to setup multitenancy.
 * Groups are as much a subject as accounts, so they can have their own roles, and permissions.
 * What they lack however, is a "logginable"/"signupable" identity.
 * To give groups agency however, they must have accounts elected as leaders.
 * Further group functionality will require custom coding.
 */

SET @group_create = CONCAT(
    'CREATE TABLE IF NOT EXISTS ',
    @table_groups,
    ' (
        `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
        `date` datetime NOT NULL,
        `profile` text NOT NULL,
        PRIMARY KEY (`id`)
    ) ',
    ' ENGINE=InnoDB DEFAULT CHARSET=utf8'
);

PREPARE statement FROM @group_create;
EXECUTE statement;

/**
 * PolyAuth Roles
 * Roles are hierarchal, in that they can contain other roles.
 * Roles contain permissions, but not all permissions have to be assigned to a role.
 * It is recommended to namespace your roles, so they don't get out of hand!
 * Every role name has to be unique.
 */

SET @roles_create = CONCAT(
    'CREATE TABLE IF NOT EXISTS ',
    @table_roles,
    ' (
        `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
        `name` varchar(255) CHARACTER SET utf8 NOT NULL,
        `description` text CHARACTER SET utf8 NOT NULL,
        `date` datetime NOT NULL,
        PRIMARY KEY (`id`),
        UNIQUE KEY `uniq_name` (`name`) USING BTREE
    ) ',
    ' ENGINE=InnoDB DEFAULT CHARSET=utf8'
);

PREPARE statement FROM @roles_create;
EXECUTE statement;

/**
 * PolyAuth Permissions
 * Permissions can be assigned to roles or to accounts or to groups.
 * Think of roles as grouping the permissions. Thus creating a set that is easier to manage.
 * Resources will be demanding permissions for access.
 * Permissions also work like OAuth scopes when assigned directly to users.
 * It is recommended to namespace your permissions, so they don't get out of hand!
 * Every permission name has to be unique.
 */

SET @permissions_create = CONCAT(
    'CREATE TABLE IF NOT EXISTS ',
    @table_permissions,
    ' (
        `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
        `name` varchar(255) CHARACTER SET utf8 NOT NULL,
        `description` text CHARACTER SET utf8 NOT NULL,
        `date` datetime NOT NULL,
        PRIMARY KEY (`id`),
        UNIQUE KEY `uniq_perm` (`name`) USING BTREE
    ) ',
    ' ENGINE=InnoDB DEFAULT CHARSET=utf8'
);

PREPARE statement FROM @permissions_create;
EXECUTE statement;

/**
 * PolyAuth Providers
 * Providers are OAuth service providers. PolyAuth can also be a OAuth service provider.
 * Each user can have many providers, including PolyAuth itself.
 * If a user registers via an OAuth service provider, then there will be a record created here.
 * Providers are identified by their unique name.
 * Providers also contain an identifier key and identifier value. This is used so that users
 * logging from external providers can be recognised and be placed in a registered account.
 * PolyAuth will not automatic account federation. Account federation should be an option to the
 * end user.
 */

SET @providers_create = CONCAT(
    'CREATE TABLE IF NOT EXISTS ',
    @table_providers,
    ' (
        `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
        `provider` varchar(255) NOT NULL,
        `providerIdentifierKey` varchar(255) NOT NULL,
        `providerIdentifierValue` varchar(255) NOT NULL,
        `createdOn` datetime NOT NULL,
        PRIMARY KEY (`id`)
    ) ',
    ' ENGINE=InnoDB DEFAULT CHARSET=utf8'
);

PREPARE statement FROM @providers_create;
EXECUTE statement;

/**
 * PolyAuth Delegation
 * The delegation table specifies a unique relationship between the owner, client and provider.
 * The owner is the owner of the resource. The client is accessor of the resource. The provider
 * provides the resource.
 * This particular table does not use the associations table. This is because although each record
 * is related to the accounts table, there are 2 different ways in which it relates, in terms of
 * owner and/or client. It therefore uses the adjacency list model.
 */

SET @delegation_create = CONCAT(
    'CREATE TABLE IF NOT EXISTS ',
    @table_delegation,
    ' (
        `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
        `ownerId` int(11) UNSIGNED NOT NULL,
        `clientId` int(11) UNSIGNED NOT NULL,
        `providerId` int(11) UNSIGNED NOT NULL,
        `accessToken` text NOT NULL,
        `accessTokenExpiry` datetime NOT NULL,
        `refreshToken` text NOT NULL,
        PRIMARY KEY (`id`)
    ) ',
    ' ENGINE=InnoDB DEFAULT CHARSET=utf8'
);

PREPARE statement FROM @delegation_create;
EXECUTE statement;

/**
 * PolyAuth Tracking
 * This will be tracking and fingerprinting all requests, so it can guard against nefarious 
 * behaviour or account hijacking. Each user can have one to many relationship to tracking rows.
 * This will only submit unique fingerprints. There will not be duplicate fingerprints. 
 * The date field will be updated to the last time such as session was utilised.
 * The status field indicates whether this fingerprint has been confirmed or unconfirmed.
 */

SET @tracking_create = CONCAT(
    'CREATE TABLE IF NOT EXISTS ',
    @table_tracking,
    ' (
        `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
        `status` varchar(50) NOT NULL,
        `date` datetime NOT NULL,
        `ipAddress` varbinary(16) NOT NULL,
        `country` varchar(255) NOT NULL,
        `city` varchar (255 NOT NULL,
        `useragent` text NOT NULL,
        `os` text NOT NULL,
        `device` text NOT NULL,
        `model` text NOT NULL,
        PRIMARY KEY (`id`),
        UNIQUE KEY `uniq_tracking` (
            `ipAddress`, 
            `country`, 
            `city`, 
            `useragent`, 
            `os`, 
            `device`, 
            `model`
        ) USING BTREE
    ) ',
    ' ENGINE=InnoDB DEFAULT CHARSET=utf8'
);

PREPARE statement FROM @tracking_create;
EXECUTE statement;

/**
 * PolyAuth Security
 * This will be logging all interesting actions made by all accounts and groups. This is not a 
 * diagnostic programming log. It's an action log. It allows people to investigate the actions 
 * made, in terms of what, when and how.
 * The action is setup as a schemaless entry, to allow unstructured data to be sent in.
 * PolyAuth will store dynamic json in the action field.
 */

SET @security_create = CONCAT(
    'CREATE TABLE IF NOT EXISTS ',
    @table_security,
    ' (
        `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
        `ipAddress` varbinary(16) NOT NULL,
        `action` text NOT NULL AUTO_INCREMENT,
        `date` datetime NOT NULL,
        PRIMARY KEY (`id`)
    ) ',
    ' ENGINE=InnoDB DEFAULT CHARSET=utf8'
);

PREPARE statement FROM @security_create;
EXECUTE statement;

/**
 * PolyAuth Associations
 * This is a multi-table closure table. It's like a super junction.
 * It's the MULTITABLE SUPER-JUNCTION CLOSURE!!!!!!
 * It describes every relationship between an ancestor node to a descendant node.
 * A node can connect to itself, which means both the ancestor and descendant are the same node.
 * In MySQL a node refers to a particular row in a particular table.
 * This table is specific to relational databases. It allows an easy way to discover hierarchies
 * and ownership chains between the accounts and resources that exist within PolyAuth and resources
 * outside PolyAuth's domain.
 * For example, accounts own roles, roles own permissions, and thus accounts own permissions.
 * In this table, that would be represented by:
 *     accounts     X  accounts     X  DEPTH:0
 *     accounts     X  roles        Y  DEPTH:1
 *     accounts     X  permissions  Z  DEPTH:2
 *     roles        Y  roles        Y  DEPTH:0
 *     roles        Y  permissions  Z  DEPTH:1
 *     permissions  Z  permissions  Z  DEPTH:0
 * Where X is the account ID, Y is the role ID, Z is the permission ID. The depth is relative.
 * In practice, this will be used to quickly determine if a resource is owned by an account. This 
 * is often required when securing resources.
 * This means that whenever you create a resource or a sub resource, if it is any moment related to
 * the accounts, either directly or indirectly via a chain, you must setup this relationship using
 * PolyAuth's account tools. The account tools will provide a way to setup a immediate relationship,
 * or a chained relationship, or a single node relationship. Please note that there are no foreign
 * keys here or cascading rules. Everytime you create or delete a node, you must adjust this table
 * to ensure consistency.
 *
 * Here's an example query that acquires *all* user ancestors given a permission ID of 1:
 * 
 *     SELECT * FROM pa_accounts AS accounts 
 *     JOIN pa_associations AS associations 
 *         ON accounts.id = associations.ancestorId 
 *     WHERE associations.descendantId = 1 
 *         AND associations.descendantName = 'pa_permissions' 
 *         AND associations.ancestorName = 'pa_accounts';
 *
 * Here's an example query that inserts a relationship between the 4th role and the 10th permission:
 * 
 *     INSERT INTO pa_associations (ancestorName, ancestorId, descendantName, descendantId, depth)
 *     SELECT 
 *         ancestorName, 
 *         ancestorId, 
 *         'pa_permissions', 
 *         10,
 *         depth + 1,
 *     FROM pa_associations
 *     WHERE descendantId = 4 AND descendantName = 'pa_roles'
 *     UNION ALL SELECT 'pa_permissions', 10, 'pa_permissions', 10, 0;
 * 
 */
SET @associations_create = CONCAT(
    'CREATE TABLE IF NOT EXISTS ',
    @table_associations,
    ' (
        `ancestorName` varchar(255) CHARACTER SET utf8 NOT NULL,
        `ancestorId` int(11) UNSIGNED NOT NULL,
        `descendantName` varchar(255) CHARACTER SET utf8 NOT NULL,
        `descendantId` int(11) UNSIGNED NOT NULL,
        `depth` int(11) UNSIGNED NOT NULL,
        PRIMARY KEY (`ancestorName`, `ancestorId`, `descendantName`, `descendantId`)
    ) ',
    ' ENGINE=InnoDB DEFAULT CHARSET=utf8'
);

PREPARE statement FROM @associations_create;
EXECUTE statement;