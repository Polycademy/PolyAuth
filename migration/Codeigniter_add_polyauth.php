<?php defined('BASEPATH') OR exit('No direct script access allowed');

use RBAC\Permission;
use RBAC\Role\Role;
use RBAC\Manager\RoleManager;

/**
 * This migration file is catered towards Codeigniter 3.0 and the MySQL database.
 * However you can glean information from here on how to implement it in other frameworks and other databases.
 * 
 * This migration will not setup any sessions table, that's up to you to create if you want to use database sessions.
 * 
 * You will need to modify the configuration array to setup the default permissions and the default user.
 * You can also add to the columns of the user_accounts table, or even change the name, just make sure to configure the name properly.
 * Any added columns will simply be extra data that you can submit when registering or getting a user.
 * If table names are changed, make sure to change them in the options too.
 *
 * Of course you can edit the roles and permissions later by constructing your own back end interface, or you can programmatically do it
 *
 * The RBAC is at NIST Level 1, so the user and role land is flat, no hierarchy yet.
 */
class Migration_add_polyauth extends CI_Migration {

	public function up(){
	
		$default_user = array(
			'id'					=> '1',
			'ipAddress'				=> inet_pton('127.0.0.1'),
			'username'				=> 'administrator',
			'password'				=> '$2y$10$EiqipvSt3lnD//nchj4u9OgOTL9R3J4AbZ5bUVVrh.Tq/gmc5xIvS', //default is "password"
			'passwordChange'		=> '0',
			'email'					=> 'admin@admin.com',
			'activationCode'		=> '',
			'forgottenCode'			=> NULL,
			'forgottenDate'			=> NULL,
			'createdOn'				=> date('Y-m-d H:i:s'),
			'lastLogin'				=> date('Y-m-d H:i:s'),
			'active'				=> '1',
		);
		
		//roles to descriptions
		$default_roles = array(
			'admin'		=> 'Site Administrators',
			'member'	=> 'General Members',
		);
		
		//roles to permissions to permission descriptions
		$default_role_permissions = array(
			'admin'		=> array(
				'admin_create'	=> 'Creating administration resources.',
				'admin_read'	=> 'Viewing administration resources.',
				'admin_update'	=> 'Editing administration resources.',
				'admin_delete'	=> 'Deleting administration resources.',
			),
			'member'	=> array(
				'public_read'	=> 'Viewing public resources.',
			),
		);
		
		//default user to roles
		$default_user_roles = array(
			$default_user['id']	=> array(
				'admin',
				'member',
			),
		);
		
		// Table structure for table 'user_accounts'
		$this->dbforge->add_field(array(
			'id' => array(
				'type' => 'MEDIUMINT',
				'constraint' => '8',
				'unsigned' => TRUE,
				'auto_increment' => TRUE
			),
			'ipAddress' => array(
				'type' => 'VARBINARY',
				'constraint' => '16'
			),
			'username' => array(
				'type' => 'VARCHAR',
				'constraint' => '100',
			),
			'password' => array(
				'type' => 'VARCHAR',
				'constraint' => '255',
			),
			'passwordChange' => array(
				'type' => 'TINYINT',
				'constraint' => '1',
				'unsigned' => TRUE,
				'default' => 0,
			),
			'email' => array(
				'type' => 'VARCHAR',
				'constraint' => '100'
			),
			'activationCode' => array(
				'type' => 'VARCHAR',
				'constraint' => '40',
				'null' => TRUE
			),
			'forgottenCode' => array(
				'type' => 'VARCHAR',
				'constraint' => '40',
				'null' => TRUE
			),
			'forgottenDate' => array(
				'type' => 'DATETIME',
				'null' => TRUE
			),
			'autoCode' => array(
				'type' => 'VARCHAR',
				'constraint' => '40',
				'null' => TRUE
			),
			'autoDate' => array(
				'type' => 'DATETIME',
				'null' => TRUE
			),
			'createdOn' => array(
				'type' => 'DATETIME',
			),
			'lastLogin' => array(
				'type' => 'DATETIME',
			),
			'active' => array(
				'type' => 'TINYINT',
				'constraint' => '1',
				'unsigned' => TRUE,
				'default' => 0,
			),
			'banned' => array(
				'type' => 'TINYINT',
				'constraint' => '1',
				'unsigned' => TRUE,
				'default' => 0,
			),
		));
		
		$this->dbforge->add_key('id', TRUE);
		$this->dbforge->create_table('user_accounts', true);
		
		// Dumping data for table 'users'
		$this->db->insert('user_accounts', $default_user);
		
		// Table structure for table 'login_attempts'
		$this->dbforge->add_field(array(
			'id' => array(
				'type' => 'MEDIUMINT',
				'constraint' => '8',
				'unsigned' => TRUE,
				'auto_increment' => TRUE
			),
			'ipAddress' => array(
				'type' => 'VARBINARY',
				'constraint' => '16',
			),
			'identity' => array(
				'type' => 'VARCHAR',
				'constraint' => '100',
			),
			'lastAttempt' => array(
				'type' => 'DATETIME',
			)
		));
		
		$this->dbforge->add_key('id', TRUE);
		$this->dbforge->create_table('login_attempts', true);
	
		//This is the RBAC schema designed for MySQL, it's complex, so we use direct queries!
		//This is LEVEL 1 RBAC, later on you can update to LEVEL 2 RBAC
		
		$create_auth_permission = 
			'CREATE TABLE `auth_permission` (
				`permission_id` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
				`name`          VARCHAR(32) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
				`description`   TEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL,
				`added_on`      DATETIME NULL DEFAULT NULL,
				`updated_on`    DATETIME NULL DEFAULT NULL,
				PRIMARY KEY (`permission_id`),
				UNIQUE INDEX `uniq_perm` USING BTREE (`name`)
			) ENGINE = InnoDB;';
		
		$this->db->query($create_auth_permission);
		
		$create_auth_role = 
			'CREATE TABLE `auth_role` (
				`role_id`     INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
				`name`        VARCHAR(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL,
				`description` TEXT CHARACTER SET utf8 COLLATE utf8_general_ci NULL,
				`added_on`    DATETIME NULL DEFAULT NULL,
				`updated_on`  DATETIME NULL DEFAULT NULL,
				PRIMARY KEY (`role_id`),
				UNIQUE INDEX `uniq_name` USING BTREE (`name`)
			) ENGINE = InnoDB;';
			
		$this->db->query($create_auth_role);
		
		$create_auth_role_permissions = 
			'CREATE TABLE `auth_role_permissions` (
				`role_permission_id` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
				`role_id`            INT(10) UNSIGNED NOT NULL,
				`permission_id`      INT(10) UNSIGNED NOT NULL,
				`added_on`           DATETIME NULL DEFAULT NULL,
				PRIMARY KEY (`role_permission_id`),
				FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`permission_id`) ON DELETE CASCADE ON UPDATE CASCADE,
				FOREIGN KEY (`role_id`) REFERENCES `auth_role` (`role_id`) ON DELETE CASCADE ON UPDATE CASCADE,
				INDEX `fk_role` USING BTREE (`role_id`),
				INDEX `fk_permission` USING BTREE (`permission_id`)
			)
			ENGINE = InnoDB;';
		
		$this->db->query($create_auth_role_permissions);
		
		$create_auth_subject_role = 
			'CREATE TABLE `auth_subject_role` (
				`subject_role_id` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
				`subject_id`      INT(10) UNSIGNED NOT NULL,
				`role_id`         INT(10) UNSIGNED NOT NULL,
				PRIMARY KEY (`subject_role_id`),
				FOREIGN KEY (`role_id`) REFERENCES `auth_role` (`role_id`) ON DELETE CASCADE ON UPDATE CASCADE,
				UNIQUE INDEX `role_id` USING BTREE (`role_id`, `subject_id`),
				INDEX `fk_subjectid` USING BTREE (`subject_id`),
				INDEX `fk_roleid` USING BTREE (`role_id`)
			)
			ENGINE = InnoDB;';
		
		$this->db->query($create_auth_subject_role);
		
		//time to insert the default permission and role data
		$role_manager = new RoleManager($this->db->conn_id);
		
		foreach($default_role_permissions as $role => $permissions_array){
		
			//create the role
			$created_role = Role::create($role, $default_roles[$role]);
			
			foreach($permissions_array as $permission => $reason){

				//create the permission
				$created_permission = Permission::create($permission, $reason);
				//save the permission to the database
				$role_manager->permissionSave($created_permission);
				//add the permission to the role
				$created_role->addPermission($created_permission);
				
			}
			
			$role_manager->roleSave($created_role);
			
		}
		
		//assign the role to the default user
		foreach($default_user_roles as $user => $roles){
		
			foreach($roles as $role){
			
				$assignable_role = $role_manager->roleFetchByName($role);
				
				$role_manager->roleAddSubjectId($assignable_role, $user);
			
			}
		
		}
		
	}

	public function down(){
	
		$this->dbforge->drop_table('user_accounts');
		$this->dbforge->drop_table('login_attempts');
		//when using foreign keys, if you need to drop them, make sure to ignore them and then set them up again
		$this->db->query('SET foreign_key_checks = 0;');
		$this->dbforge->drop_table('auth_permission');
		$this->dbforge->drop_table('auth_role');
		$this->dbforge->drop_table('auth_role_permissions');
		$this->dbforge->drop_table('auth_subject_role');
		$this->db->query('SET foreign_key_checks = 1;');
	
	}
	
}