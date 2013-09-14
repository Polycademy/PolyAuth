<?php

namespace PolyAuth\Storage;

use PDO;
use PDOException;
use Psr\Log\LoggerInterface;
use PolyAuth\Options;
use PolyAuth\Storage\StorageInterface;

use RBAC\Permission;
use RBAC\Role\Role;
use RBAC\Manager\RoleManager;
use RBAC\Subject\SubjectInterface;
use RBAC\DataStore\PDOMySQLAdapter;

/**
 * MySQL PDO Adapter for PolyAuth
 * The Rbac mysql adapter will be composited with this adapter, allowing it satisfy bother interfaces
 * The Oauth library will remain using memory storage, however this will take the memory and store into mysql
 */
class MySQLAdapter implements StorageInterface{

	protected $db;
	protected $options;
	protected $logger;
	protected $rbac_storage;

	public function __construct(PDO $db, Options $options, LoggerInterface = null){

		$this->db = $db;
		$this->options = $options;
		$this->logger = $logger;
		$this->rbac_storage = new PDOMySQLAdapter($db, $logger);

	}

	/**
	 * Sets a logger instance on the object
	 *
	 * @param LoggerInterface $logger
	 * @return null
	 */
	public function setLogger(LoggerInterface $logger){

		$this->logger = $logger;
		$this->rbac_storage = new PDOMySQLADapter($this->db, $logger);
	
	}

	/**
	 * Registers a new user. It accepts an array of $data and a corresponding array of $columns
	 * @param  array $data    Array of values
	 * @param  array $columns Array of columns for the values to be inserted into
	 * @return integer        Last Insert ID
	 */
	public function register_user(array $data, array $columns){

		$insert_placeholders = implode(', ', array_fill(0, count($data), '?'));
		
		$query = "INSERT INTO {$this->options['table_users']} ($columns) VALUES ($insert_placeholders)";
		
		$sth = $this->db->prepare($query);
		
		try {
		
			$sth->execute(array_values($data));
			$last_insert_id = $this->db->lastInsertId();
			
		}catch(PDOException $db_err){

			if($this->logger){
				$this->logger->error('Failed to execute query to register a new user and assign permissions.', ['exception' => $db_err]);
			}
			
			throw $db_err;
			
		}

		return $last_insert_id;

	}

	/**
	 * Deregisters a user.
	 * @param  integer $user_id Id of the user
	 * @return Boolean
	 */
	public function deregister_user($user_id){

		$query = "DELETE FROM {$this->options['table_users']} WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue(':user_id', $user_id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			
			if($sth->rowCount() >= 1){
				return true;
			}
			
			return false;
			
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error('Failed to execute query to delete a user.', ['exception' => $db_err]);
			}
			
			throw $db_err;
		
		}

	}

	/**
	 * Checks for duplicate identity, returns true if the identity exists, false if the identity already exist
	 *
	 * @param $identity string
	 * @return boolean - true if duplicate, false if no duplicate
	 */
	public function duplicate_identity_check($identity){

		$query = "SELECT id FROM {$this->options['table_users']} WHERE {$this->options['login_identity']} = :identity";
		$sth = $this->db->prepare($query);
		$sth->bindValue(':identity', $identity, PDO::PARAM_STR);
		
		try {
		
			$sth->execute();
			if($sth->fetch()){
				return true;
			}
			return false;
			
		}catch(PDOException $db_err){

			if($this->logger){
				$this->logger->error('Failed to execute query to check duplicate login identities.', ['exception' => $db_err]);
			}
			
			throw $db_err;
			
		}

	}

	/**
	 * Forcibly activates an user
	 * @param  integer $user_id User Id
	 * @return Boolean
	 */
	public function force_activate($user_id){

		$query = "UPDATE {$this->options['table_users']} SET active = 1, activationCode = NULL WHERE id = :id";
		$sth = $this->db->prepare($query);
		$sth->bindValue(':id', $user_id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			if($sth->rowCount() < 1){
				return false;
			}else{
				return true;
			}
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to activate user $user_id.", ['exception' => $db_err]);
			}
			
			throw $db_err;
		
		}

	}

	/**
	 * Deactivates an user
	 * @param  integer $user_id         User id
	 * @param  string  $activation_code Random 40 character code
	 * @return Boolean                  
	 */
	public function deactivate($user_id, $activation_code){

		$query = "UPDATE {$this->options['table_users']} SET active = 0, activationCode = :activation_code WHERE id = :id";
		$sth = $this->db->prepare($query);
		$sth->bindValue(':activation_code', $activation_code, PDO::PARAM_STR);
		$sth->bindValue(':id', $user_id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			if($sth->rowCount() < 1){
				return false;
			}else{
				return true;
			}
			
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to deactivate user $user_id.", ['exception' => $db_err]);
			}
			
			throw $db_err;
		
		}

	}

	public function forgotten_password($user_id, $forgotten_code, $forgotten_date){

		$query = "UPDATE {$this->options['table_users']} SET forgottenCode = :forgotten_code, forgottenDate = :forgotten_date WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('forgotten_code', $forgotten_code, PDO::PARAM_STR);
		$sth->bindValue('forgotten_date', $forgotten_date, PDO::PARAM_STR);
		$sth->bindValue('user_id', $user_id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			if($sth->rowCount() < 1){
				return false;
			}
			return true;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to update user with forgotten code and date", ['exception' => $db_err]);
			}
			
			throw $db_err;
			
		}

	}

	public function password_change_flag($user_id){

		$query = "UPDATE {$this->options['table_users']} SET passwordChange = 1 WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('user_id', $user_id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			return true;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to set the the passwordChange flag to 1.", ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

	}

	public function multi_password_change_flag(array $user_ids){

		$update_placeholders = implode(",", array_fill(0, count($user_ids), '?'));
		
		$query = "UPDATE {$this->options['table_users']} SET passwordChange = 1 WHERE id IN ($update_placeholders)";
		$sth = $this->db->prepare($query);
		
		try{
		
			$sth->execute($user_ids);
			return true;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to flag the password for change.", ['exception' => $db_err]);
			}
			
			throw $db_err;
		
		}

	}

	public function forgotten_password_clear($user_id){

		$query = "UPDATE {$this->options['table_users']} SET forgottenCode = NULL, forgottenDate = NULL WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('user_id', $user_id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			return true;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to clear the forgotten code and forgotten time.", ['exception' => $db_err]);
			}
			
			throw $db_err;
		
		}

	}

	public function external_register($data){

		$query = "INSERT INTO {$this->options['table_users']} (ipAddress, createdOn, lastLogin, active) VALUES (:ip_address, :created_on, :last_login, :active)";
		$sth = $this->db->prepare($query);
		$sth->bindValue('ip_address', $data['ipAddress'], PDO::PARAM_STR);
		$sth->bindValue('created_on', $data['createdOn'], PDO::PARAM_STR);
		$sth->bindValue('lastLogin', $data['last_login'], PDO::PARAM_STR);
		$sth->bindValue('active', $data['active'], PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			return $this->db->lastInsertId();
			
		}catch(PDOException $db_err){

			if($this->logger){
				$this->logger->error('Failed to execute query to register a new user from external providers.', ['exception' => $db_err]);
			}
			
			throw $db_err;
			
		}

	}

	public function get_external_providers($external_identifier){

		$query = "
			SELECT ep.id, ep.userId, ep.provider 
			FROM {$this->options['table_external_providers']} AS ep 
			INNER JOIN {$this->options['table_users']} AS ua 
			ON ep.userId = ua.id 
			WHERE ep.externalIdentifier = :external_identifier
		";
		$sth = $this->db->prepare($query);
		$sth->bindValue('external_identifier', $external_identifier, PDO::PARAM_STR);

		try{

			$sth->execute();
			$result = $sth->fetchAll(PDO::FETCH_OBJ);
			return $result;

		}catch(PDOException $db_err){

			if($this->logger){
				$this->logger->error("Failed to execute query to find existing accounts authorised externally.", ['exception' => $db_err]);
			}
			
			throw $db_err;
		
		}

	}

	public function register_external_provider(array $data){

		$query = "INSERT INTO {$this->options['table_external_providers']} (userId, provider, externalIdentifier, tokenObject) VALUES (:user_id, :provider, :external_identifier, :token_object)";

		$sth = $this->db->prepare($query);
		$sth->bindValue('user_id', $data['userId'], PDO::PARAM_INT);
		$sth->bindValue('provider', $data['provider'], PDO::PARAM_STR);
		$sth->bindValue('external_identifier', $data['externalIdentifier'], PDO::PARAM_STR);
		$sth->bindValue('token_object', $data['tokenObject'], PDO::PARAM_STR);

		try{

			$sth->execute();
			return true;

		}catch(PDOException $db_err){

			if($this->logger){
				$this->logger->error("Failed to execute query to insert a new provider record.", ['exception' => $db_err]);
			}
			
			throw $db_err;

		}

	}

	public function deregister_external_provider(){

	}

	public function get_external_providers_by_user(){

	}

	public function update_external_provider($provider_id, array $new_data){

		$columns = array_keys($new_data);
		$update_placeholder = implode(' = ?, ', $columns) . ' = ?';
		
		$query = "UPDATE {$this->options['table_external_providers']} SET $update_placeholder WHERE id = :provider_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('provider_id', $provider_id, PDO::PARAM_INT);

		try{

			$sth->execute();
			if($sth->rowCount() >= 1){
				return true;
			}
			return false;

		}catch(PDOException $db_err){

			if($this->logger){
				$this->logger->error("Failed to execute query to update an existing provider.", ['exception' => $db_err]);
			}
			
			throw $db_err;

		}

	}

	public function get_password($user_id){

		$query = "SELECT password FROM {$this->options['table_users']} WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('user_id', $user_id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			$row = $sth->fetch(PDO::FETCH_OBJ);
			return $row->password;
			
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to get the password hash from user $user_id.", ['exception' => $db_err]);
			}
			
			throw $db_err;
			
		}

	}

	public function update_password($user_id, $new_password){

		$query = "UPDATE {$this->options['table_users']} SET passwordChange = 0, password = :new_password WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('new_password', $new_password, PDO::PARAM_STR);
		$sth->bindValue('user_id', $user_id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			
			if($sth->rowCount() < 1){
				return false;
			}

			return true;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to update password hash with user $user_id.", ['exception' => $db_err]);
			}
			
			throw $db_err;
		
		}

	}

	public function get_user($user_id){

		$query = "SELECT * FROM {$this->options['table_users']} WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('user_id', $user_id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			$row = $sth->fetch(PDO::FETCH_OBJ);
			return $row;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to select user $user_id.", ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

	}

	public function get_users(array $user_ids){

		$select_placeholders = implode(",", array_fill(0, count($user_ids), '?'));
		
		$query = "SELECT * FROM {$this->options['table_users']} WHERE id IN ($select_placeholders)";
		$sth = $this->db->prepare($query);
		
		try{
		
			$sth->execute($user_ids);
            $result = $sth->fetchAll(PDO::FETCH_OBJ);
			return $result;
			
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to select users.", ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

	}

	public function get_users_by_role(array $roles){

		$select_placeholders = implode(",", array_fill(0, count($roles), '?'));
		
		//double join
		$query = "
			SELECT asr.subject_id 
			FROM auth_subject_role AS asr 
			INNER JOIN auth_role AS ar ON asr.role_id = ar.role_id 
			WHERE ar.name IN ($select_placeholders)
		";
		
		$sth = $this->db->prepare($query);
		
		try{
			
			$sth->execute($roles);
			$result = $sth->fetchAll(PDO::FETCH_OBJ);
			return $result;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error('Failed to execute query to select subjects from auth subject role based on role names.', ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

	}

	public function get_users_by_permission(array $permissions){

		$select_placeholders = implode(",", array_fill(0, count($permissions), '?'));
		
		//triple join
		$query = "
			SELECT asr.subject_id 
			FROM auth_subject_role AS asr 
			INNER JOIN auth_role_permissions AS arp ON asr.role_id = arp.role_id
			INNER JOIN auth_permissions AS ap ON arp.permission_id = ap.permission_id
			WHERE ap.name IN ($select_placeholders)
		";
		
		$sth = $this->db->prepare($query);
		
		try{
			
			$sth->execute($permissions);
			$result = $sth->fetchAll(PDO::FETCH_OBJ);
			return $result;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error('Failed to execute query to select subjects from auth subject role based on permission names.', ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

	}

	public function update_user($user_id, array $data, array $columns){

		$update_placeholder = implode(' = ?, ', $columns) . ' = ?';
		
		$query = "UPDATE {$this->options['table_users']} SET $update_placeholder WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('user_id', $user_id, PDO::PARAM_INT);
		
		try{
		
			//execute like an array!
			$sth->execute($data);
			if($sth->rowCount() < 1){
				return false;
			}
			
			return true;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to update user $user_id", ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

	}

	/**
	 * Gets an array of permission objects from an array of permission names
	 *
	 * @param $requested_permissions array | null
	 * @return $permissions array | null
	 */
	public function get_permissions(array $requested_permissions){

		$select_placeholders = implode(",", array_fill(0, count($requested_permissions), '?'));
		
		$query = "SELECT * FROM auth_permission WHERE name IN ($select_placeholders)";
		$sth = $this->db->prepare($query);
	
		try{
		
			$sth->execute($requested_permissions);
			//this fetches the row into an instantiated object of an existing class, which is the Permission class
			$permissions = $sth->fetchAll(PDO::FETCH_CLASS, RoleManager::CLASS_PERMISSION);
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error('Failed to execute query to select permissions from auth permission based on permission names.', ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

		return $permissions;

	}

	//////////////////////
	// RBAC COMPOSITING //
	//////////////////////

	public function getDBConn(){
		return $this->rbac_storage->getDBConn();
	};

	public function permissionSave(Permission $permission){
		return $this->rbac_storage->permissionSave($permission);
	};

	public function permissionFetchById($permission_id){
		return $this->rbac_storage->permissionFetchById($permission_id);
	};

	public function permissionFetch(){
		return $this->rbac_storage->permissionFetch();
	};

	public function permissionDelete(Permission $permission){
		return $this->rbac_storage->permissionDelete($permission);
	};

	public function roleSave(Role $role){
		return $this->rbac_storage->roleSave($role);
	};

	public function rolePermissionAdd(Role $role, Permission $permission){
		return $this->rbac_storage->rolePermissionAdd($role, $permission);
	};

	public function roleDelete(Role $role){
		return $this->rbac_storage->roleDelete($role);
	};

	public function roleFetch(){
		return $this->rbac_storage->roleFetch();
	};

	public function roleFetchByName($role_name){
		return $this->rbac_storage->roleFetchByName($role_name);
	};

	public function roleFetchById($role_ids){
		return $this->rbac_storage->roleFetchById($role_ids);
	};

	public function roleFetchSubjectRoles(SubjectInterface $subject){
		return $this->rbac_storage->roleFetchSubjectRoles($subject);
	};

	public function roleAddSubjectId(Role $role, $subject_id){
		return $this->rbac_storage->roleAddSubjectId($role, $subject_id);
	};

	public function permissionFetchByRole(Role $role){
		return $this->rbac_storage->permissionFetchByRole($role);
	};

}