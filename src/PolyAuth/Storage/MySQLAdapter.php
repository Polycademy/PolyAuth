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
use RBAC\DataStore\Adapter\PDOMySQLAdapter;

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

	public function __construct(PDO $db, Options $options, LoggerInterface $logger = null){

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

	//////////////////////
	// ACCOUNTS MANAGER //
	//////////////////////

	/**
	 * Registers a new user. It accepts an array of $data and a corresponding array of $columns
	 * @param  array $data    Array of values
	 * @param  array $columns Array of columns for the values to be inserted into
	 * @return integer        Last Insert ID
	 */
	public function register_user(array $data, array $columns){

		$columns = implode(', ', $columns);
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
		$sth->bindValue('last_login', $data['lastLogin'], PDO::PARAM_STR);
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

		//these columns need validating
		$columns = array_keys($new_data);
		$update_placeholder = implode(' = ?, ', $columns) . ' = ?';

		//bind user_id to the last '?' binding, cannot mix positional with named
		$query = "UPDATE {$this->options['table_external_providers']} SET $update_placeholder WHERE id = ?";
		$sth = $this->db->prepare($query);
		$new_data[] = $provider_id;

		try{

			$sth->execute(array_values($new_data));
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

	public function get_user_by_identity($identity){

		$query = "SELECT * FROM {$this->options['table_users']} WHERE {$this->options['login_identity']} = :identity";
		$sth = $this->db->prepare($query);
		$sth->bindValue('identity', $identity, PDO::PARAM_STR);
		
		try{
		
			$sth->execute();
			$row = $sth->fetch(PDO::FETCH_OBJ);
			return $row;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to select user $identity.", ['exception' => $db_err]);
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

		//bind user_id to the last '?' binding, cannot mix positional with named
		$update_placeholder = implode(' = ?, ', $columns) . ' = ?';
		$query = "UPDATE {$this->options['table_users']} SET $update_placeholder WHERE id = ?";
		$sth = $this->db->prepare($query);
		$data[] = $user_id;

		// may not be required, since the accounts manager should already inet_pton the ip addresses!
		//ip addresses may come in as straight strings, we need to pack it if it isn't already packed
		//ctype_print will check whether the string is printable, binary strings are not printable
		if(!empty($data['ipAddress']) AND ctype_print($data['ipAddress'])){
			$data['ipAddress'] = inet_pton($data['ipAddress']);
		}
		
		try{
		
			//execute like an array!
			$sth->execute(array_values($data));
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

	public function ban_user($user_id){

		$query = "UPDATE {$this->options['table_users']} SET banned = 1 WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('user_id', $user_id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			if($sth->rowCount() >= 1){
				return true;
			}
			return false;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to ban user $user_id.", ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

	}

	public function unban_user($user_id){

		$query = "UPDATE {$this->options['table_users']} SET banned = 0 WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('user_id', $user_id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			if($sth->rowCount() >= 1){
				return true;
			}
			return false;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to unban user $user_id.", ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

	}

	public function validate_columns($table, array $columns){

		$sth = $this->db->prepare("DESCRIBE $table");
		
		try{
		
			$sth->execute();
			//will return an numerically indexed array of field names
			$table_fields = $sth->fetchAll(PDO::FETCH_COLUMN, 0);
			
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to describe $table.", ['exception' => $db_err]);
			}
			throw $db_err;
			
		}

		//checks if the $columns values are in the $table_fields values,
		//if any of the $columns values are not in the $table_fields, 
		//then they are a non-existent column
		$difference = array_diff($columns, $table_fields);

		if(!empty($difference)){
			return false;
		}

		return true;

	}

	///////////////////
	// RBAC INTERNAL //
	///////////////////

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

	/////////////////////
	// SESSION MANAGER //
	/////////////////////

	public function get_login_check($identity){

		$query = "SELECT id, password FROM {$this->options['table_users']} WHERE {$this->options['login_identity']} = :identity";
		$sth = $this->db->prepare($query);
		$sth->bindValue('identity', $identity, PDO::PARAM_STR);
		
		try{
		
			$sth->execute();
			$row = $sth->fetch(PDO::FETCH_OBJ);
			return $row;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to login.", ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

	}

	/**
	 * Update the last login time given a particular user id.
	 *
	 * @param $user_id integer
	 * @return boolean
	 */
	public function update_last_login($user_id, $ip_address){

		$query = "UPDATE {$this->options['table_users']} SET ipAddress = :ip_address, lastLogin = :last_login WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('ip_address', $ip_address, PDO::PARAM_STR);
		$sth->bindValue('last_login', date('Y-m-d H:i:s'), PDO::PARAM_STR);
		$sth->bindValue('user_id', $user_id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			return true;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to update last login time for user $user_id.", ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

	}

	////////////////////
	// LOGIN ATTEMPTS //
	////////////////////

	public function locked_out($identity, $ip_address){

		$lockout_options = $this->options['login_lockout'];

		$query = "
			SELECT 
			MAX(lastAttempt) as lastAttempt, 
			COUNT(*) as attemptNum
			FROM {$this->options['table_login_attempts']} 
		";
		
		//if we are tracking both, it's an OR, not an AND, because a single ip address may be attacking multiple identities and a single identity may be attacked from multiple ip addresses
		if(in_array('ipaddress', $lockout_options) AND in_array('identity', $lockout_options)){
		
			$query .= "WHERE ipAddress = :ip_address OR identity = :identity";
		
		}elseif(in_array('ipaddress', $lockout_options)){
		
			$query .= "WHERE ipAddress = :ip_address";
		
		}elseif(in_array('identity', $lockout_options)){
		
			$query .= "WHERE identity = :identity";
		
		}
		
		$sth = $this->db->prepare($query);
		$sth->bindValue('ip_address', $ip_address, PDO::PARAM_STR);
		$sth->bindValue('identity', $identity, PDO::PARAM_STR);
		
		try{
		
			$sth->execute();
			$row = $sth->fetch(PDO::FETCH_OBJ);
			return $row;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error('Failed to execute query to check whether a login attempt was locked out.', ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

	}

	public function increment_login_attempt($identity, $ip_address){

		$query = "INSERT {$this->options['table_login_attempts']} (ipAddress, identity, lastAttempt) VALUES (:ip, :identity, :date)";
		$sth = $this->db->prepare($query);
		$sth->bindValue('ip', $ip_address, PDO::PARAM_STR);
		$sth->bindValue('identity', $identity, PDO::PARAM_STR);
		$sth->bindValue('date', date('Y-m-d H:i:s'), PDO::PARAM_STR);
		
		try{
		
			$sth->execute();
			return true;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error('Failed to execute query to insert a login attempt.', ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

	}

	public function clear_login_attempts($identity, $ip_address, $either_or){

		$lockout_options = $this->options['login_lockout'];

		$query = "DELETE FROM {$this->options['table_login_attempts']} ";
		
		if($either_or){
		
			//this is the most complete clearing, simultaneously clearing any ips and identities
			$query .= "WHERE ipAddress = :ip_address OR identity = :identity";
		
		}elseif(in_array('ipaddress', $lockout_options) AND in_array('identity', $lockout_options)){
		
			//this is the most stringent clearing, requiring both ip and identity to be matched
			$query .= "WHERE ipAddress = :ip_address AND identity = :identity";
		
		}elseif(in_array('ipaddress', $lockout_options)){
		
			$query .= "WHERE ipAddress = :ip_address";
		
		}elseif(in_array('identity', $lockout_options)){
		
			$query .= "WHERE identity = :identity";
		
		}
		
		$sth = $this->db->prepare($query);
		$sth->bindValue('ip_address', $ip_address, PDO::PARAM_STR);
		$sth->bindValue('identity', $identity, PDO::PARAM_STR);
		
		try{
		
			$sth->execute();
			if($sth->rowCount() >= 1){
				return true;
			}
			return false;
		
		}catch(PDOException $db_err){
			
			if($this->logger){
				$this->logger->error('Failed to execute query to clear old login attempts.', ['exception' => $db_err]);
			}
			throw $db_err;
			
		}

	}

	////////////////
	// STRATEGIES //
	////////////////

	public function check_autologin($id, $autocode, $valid_date){

		// check for expiration
		if($this->options['login_expiration'] !== 0){
			$query = "SELECT id FROM {$this->options['table_users']} WHERE id = :id AND autoCode = :autoCode AND autoDate >= :valid_date";
		}else{
			$query = "SELECT id FROM {$this->options['table_users']} WHERE id = :id AND autoCode = :autoCode";
		}
		
		$sth = $this->db->prepare($query);
		$sth->bindValue('id', $id, PDO::PARAM_INT);
		$sth->bindValue('autoCode', $autocode, PDO::PARAM_STR);
		$sth->bindValue('valid_date', $valid_date, PDO::PARAM_STR);
		
		try{
		
			$sth->execute();
			$row = $sth->fetch(PDO::FETCH_OBJ);
			return $row;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to autologin.", ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

	}

	public function set_autologin($id, $autocode){

		$query = "UPDATE {$this->options['table_users']} SET autoCode = :autoCode, autoDate = :autoDate WHERE id = :id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('autoCode', $autocode, PDO::PARAM_STR);
		$sth->bindValue('autoDate', date('Y-m-d H:i:s'), PDO::PARAM_STR);
		$sth->bindValue('id', $id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			if($sth->rowCount() >= 1){
				return true;
			}else{
				return false;
			}
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to setup autologin.", ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

	}

	public function clear_autologin($id){

		$query = "UPDATE {$this->options['table_users']} SET autoCode = NULL, autoDate = NULL WHERE id = :id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('id', $id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			if($sth->rowCount() >= 1){
				return true;
			}else{
				return false;
			}
			
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to clear autologin.", ['exception' => $db_err]);
			}
			throw $db_err;
			
		}
		
	}


	//////////////////////
	// RBAC COMPOSITING //
	//////////////////////

	public function getDBConn(){
		return $this->rbac_storage->getDBConn();
	}

	public function permissionSave(Permission $permission){
		return $this->rbac_storage->permissionSave($permission);
	}

	public function permissionFetchById($permission_id){
		return $this->rbac_storage->permissionFetchById($permission_id);
	}

	public function permissionFetch(){
		return $this->rbac_storage->permissionFetch();
	}

	public function permissionDelete(Permission $permission){
		return $this->rbac_storage->permissionDelete($permission);
	}

	public function roleSave(Role $role){
		return $this->rbac_storage->roleSave($role);
	}

	public function rolePermissionAdd(Role $role, Permission $permission){
		return $this->rbac_storage->rolePermissionAdd($role, $permission);
	}

	public function roleDelete(Role $role){
		return $this->rbac_storage->roleDelete($role);
	}

	public function roleFetch(){
		return $this->rbac_storage->roleFetch();
	}

	public function roleFetchByName($role_name){
		return $this->rbac_storage->roleFetchByName($role_name);
	}

	public function roleFetchById($role_ids){
		return $this->rbac_storage->roleFetchById($role_ids);
	}

	public function roleFetchSubjectRoles(SubjectInterface $subject){
		return $this->rbac_storage->roleFetchSubjectRoles($subject);
	}

	public function roleAddSubjectId(Role $role, $subject_id){
		return $this->rbac_storage->roleAddSubjectId($role, $subject_id);
	}

	public function permissionFetchByRole(Role $role){
		return $this->rbac_storage->permissionFetchByRole($role);
	}

}