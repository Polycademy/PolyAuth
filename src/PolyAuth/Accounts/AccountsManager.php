<?php

namespace PolyAuth\Accounts;

//for database
use PDO;
use PDOException;

//for logger
use Psr\Log\LoggerInterface;

//for options
use PolyAuth\Options;

//for languages
use PolyAuth\Language;

//for security
use PolyAuth\Accounts\BcryptFallback;
use PolyAuth\Accounts\PasswordComplexity;
use PolyAuth\Accounts\Random;

//for RBAC (to CRUD roles and permissions)
use PolyAuth\UserAccount;
use RBAC\Permission;
use RBAC\Role\Role;
use RBAC\Manager\RoleManager;

//for registration
use PolyAuth\Emailer;

//for exceptions
use PolyAuth\Exceptions\RegisterValidationException;
use PolyAuth\Exceptions\PasswordValidationException;
use PolyAuth\Exceptions\DatabaseValidationException;
use PolyAuth\Exceptions\UserDuplicateException;
use PolyAuth\Exceptions\UserNotFoundException;
use PolyAuth\Exceptions\UserRoleAssignmentException;
use PolyAuth\Exceptions\RoleNotFoundException;
use PolyAuth\Exceptions\PermissionNotFoundException;
use PolyAuth\Exceptions\RoleSaveException;
use PolyAuth\Exceptions\PermissionSaveException;

class AccountsManager{

	protected $db;
	protected $options;
	protected $lang;
	protected $logger;
	protected $role_manager;
	protected $password_manager;
	protected $random;
	protected $emailer;
	protected $bcrypt_fallback = false;
	
	//expects PDO connection (potentially using $this->db->conn_id)
	public function __construct(
		PDO $db, 
		Options $options, 
		Language $language, 
		LoggerInterface $logger = null,
		RoleManager $role_manager = null, 
		PasswordComplexity $password_manager = null,
		Random $random = null,
		Emailer $emailer = null,
		BcryptFallback $bcrypt_fallback = null
	){
	
		$this->options = $options;
		$this->lang = $language;
		
		$this->db = $db;
		$this->logger = $logger;
		$this->role_manager  = ($role_manager) ? $role_manager : new RoleManager($db, $logger);
		$this->password_manager = ($password_manager) ? $password_manager : new PasswordComplexity($options, $language);
		$this->random = ($random) ? $random : new Random;
		$this->emailer = ($emailer) ? $emailer : new Emailer($options, $language, $logger);
		
		//if you use bcrypt fallback, you must always use bcrypt fallback, you cannot switch servers!
		if($this->options['hash_fallback']){
			$this->bcrypt_fallback = ($bcrypt_fallback) ? $bcrypt_fallback : new BcryptFallback($this->options['hash_rounds']);
		}
		
	}
	
	/**
	 * Register a new user. It adds some default data and role/permissions. It also handles the activation emails.
	 * Validation of the $data array is the end user's responsibility. We don't know what custom data fields the end user may want.
	 *
	 * @param $data array - $data parameter corresponds to user columns or properties. Make sure the identity and password and any other insertable properties are part of it.
	 * @return $registered_user object | false - This is a fully loaded user object containing its roles and user data.
	 */
	public function register(array $data){
		
		//login_data should have username, password or email
		if(empty($data[$this->options['login_identity']]) OR empty($data['password'])){
			throw new RegisterValidationException($this->lang['account_creation_invalid']);
		}
		
		if($this->options['email']){
			if(empty($data['email'])){
				throw new RegisterValidationException($this->lang['account_creation_email_invalid']);
			}
		}
		
		//check for duplicates based on identity
		if(!$this->duplicate_identity_check($data[$this->options['login_identity']])){
			throw new UserDuplicateException($this->lang["account_creation_duplicate_{$this->options['login_identity']}"]);
		}
		
		//check if password is complex enough
		if(!$this->password_manager->complex_enough($data['password'])){
			throw new PasswordValidationException($this->password_manager->get_error());
		}
		
		$ip = (!empty($_SERVER['REMOTE_ADDR'])) ? $_SERVER['REMOTE_ADDR'] : '127.0.0.1';
		$data['ipAddress'] = $this->prepare_ip($ip);
		$data['password'] = $this->hash_password($data['password'], $this->options['hash_method'], $this->options['hash_rounds']);
		
		$data += array(
		    'createdOn'	=> date('Y-m-d H:i:s'),
		    'lastLogin'	=> date('Y-m-d H:i:s'),
		    'active'	=> ($this->options['reg_activation'] === false ? 1 : 0),
		);
		
		//inserting activation code into the users table, if the reg_activation is by email
		if($this->options['reg_activation'] == 'email'){
			$data['activationCode'] = $this->random->generate(40); 
		}
		
		//we need to validate that the columns actually exist
		$columns = array_keys($data);
		foreach($columns as $column){
			if(!$this->validate_column($this->options['table_users'], $column)){
				throw new DatabaseValidationException($this->lang['account_creation_invalid']);
			}
		}
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
		
		//grab the user's data that we just inserted
		$registered_user = $this->get_user($last_insert_id);
		
		//now we've got to add the default roles and permissions
		$registered_user = $this->register_user_roles($registered_user, array($this->options['role_default']));
		
		//automatically send the activation email
		if($this->options['reg_activation'] == 'email' AND $this->options['email'] AND $registered_user['email']){
			$this->emailer->send_activation($registered_user);
		}
		
		return $registered_user;
		
	}
	
	/**
	 * Removes a user
	 *
	 * @param $user object
	 * @return boolean
	 */
	public function deregister(UserAccount $user){
	
		$query = "DELETE FROM {$this->options['table_users']} WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue(':user_id', $user['id'], PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			
			if($sth->rowCount() >= 1){
				return true;
			}
			
			throw new UserNotFoundException($this->lang['account_delete_already']);
			
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error('Failed to execute query to delete a user.', ['exception' => $db_err]);
			}
			
			throw $db_err;
		
		}
	
	}
	
	/**
	 * Checks for duplicate identity, returns false if the identity already exists, returns true if identity doesn't exist
	 *
	 * @param $identity string - depends on the options
	 * @return boolean
	 */
	public function duplicate_identity_check($identity){
		
		$query = "SELECT id FROM {$this->options['table_users']} WHERE {$this->options['login_identity']} = :identity";
		$sth = $this->db->prepare($query);
		$sth->bindValue(':identity', $identity, PDO::PARAM_STR);
		
		try {
		
			//there basically should be nothing returned, if something is returned then identity check fails
			$sth->execute();
			if($sth->fetch()){
				return false;
			}
			return true;
			
		}catch(PDOException $db_err){

			if($this->logger){
				$this->logger->error('Failed to execute query to check duplicate login identities.', ['exception' => $db_err]);
			}
			
			throw $db_err;
			
		}
	
	}
	
	protected function prepare_ip($ip_address) {
	
		$platform = $this->db->getAttribute(PDO::ATTR_DRIVER_NAME);
		
		if($platform == 'pgsql' || $platform == 'sqlsrv' || $platform == 'mssql'){
			return $ip_address;
		}else{
			return inet_pton($ip_address);
		}
		
	}
	
	public function hash_password($password, $method, $cost){
	
		if(!$this->bcrypt_fallback){
			$hash = password_hash($password, $method, ['cost' => $cost]);
		}else{
			$hash = $this->bcrypt_fallback->hash($password);
		}
		return $hash;
		
	}
	
	public function hash_password_verify($password, $hash){
	
		if(!$this->bcrypt_fallback){
			if(password_verify($password, $hash)){
				return true;
			} else {
				return false;
			}
		}else{
			if($this->bcrypt_fallback->verify($password, $hash)){
				return true;
			}else{
				return false;
			}
		}
		
	}
	
	/**
	 * Either resends the activation email, or it can be used to manually begin sending the activation email.
	 * It regenerates the activation code as well.
	 *
	 * @param $user object
	 * @return boolean
	 */
	public function reactivate(UserAccount $user){
	
		if($this->deactivate($user)){
		
			if($this->options['email'] AND $user['email']){
				//$user will contain the new activation code
				return $this->emailer->send_activation($user);
			}
		
		}
		
		return false;
	
	}
	
	/**
	 * Activates the new user given the activation code, this is used after the activation email has been sent and received
	 * Can also be used to manually activate
	 *
	 * @param $user object
	 * @param $activation_code string - this is optional so you can manually activate a user without checking the activation code
	 * @return boolean
	 */
	public function activate(UserAccount $user, $activation_code = false){
	
		if(!$activation_code){
			//force activate (if the activation code doesn't exist)
			return $this->force_activate($user);
		}
		
		//$user will already contain the activationCode and id
		if($user['activationCode'] == $activation_code){
			return $this->force_activate($user);
		}
		
		return false;
	
	}
	
	protected function force_activate($user){
	
		$query = "UPDATE {$this->options['table_users']} SET active = 1, activationCode = NULL WHERE id = :id";
		$sth = $this->db->prepare($query);
		$sth->bindValue(':id', $user['id'], PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			if($sth->rowCount() < 1){
				return false;
			}else{
				$user['active'] = 1;
				$user['activationCode'] = null;
				return true;
			}
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to activate user {$user['id']}.", ['exception' => $db_err]);
			}
			
			throw $db_err;
		
		}
		
	}
	
	/**
	 * Deactivates user
	 *
	 * @param $user object
	 * @return boolean
	 */
	public function deactivate(UserAccount $user){
	
		//generate new activation code and return it if it was successful
		$activation_code = $this->random->generate(40);
		$query = "UPDATE {$this->options['table_users']} SET active = 0, activationCode = :activation_code WHERE id = :id";
		$sth = $this->db->prepare($query);
		$sth->bindValue(':activation_code', $activation_code, PDO::PARAM_STR);
		$sth->bindValue(':id', $user['id'], PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			if($sth->rowCount() < 1){
				return false;
			}else{
				$user['active'] = 0;
				$user['activationCode'] = $activation_code;
				return $activation_code;
			}
			
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to deactivate user {$user['id']}.", ['exception' => $db_err]);
			}
			
			throw $db_err;
		
		}
	
	}
	
	/**
	 * Forgotten identity, run this after you have done some identity validation such as security questions.
	 * This sends the identity to the user's email.
	 *
	 * @param $user object
	 * @return boolean
	 */
	public function forgotten_identity(UserAccount $user){
	
		return $this->emailer->send_forgotten_identity($user);
	
	}
	
	/**
	 * Forgotten password, run this after you have done some identity validation such as security questions.
	 * Generates a forgotten code and forgotten time, and the code is sent via email.
	 * This is idempotent, it can be used multiple times with no side effects other than the changing of the code.
	 * If the user accidentally hits this, it won't change anything. The forgotten code and forgotten date will persist however
	 *
	 * @param $user object
	 * @return boolean
	 */
	public function forgotten_password(UserAccount $user){
	
		$user['forgottenCode'] = $this->random->generate(40);
		$user['forgottenDate'] = date('Y-m-d H:i:s');
		
		$query = "UPDATE {$this->options['table_users']} SET forgottenCode = :forgotten_code, forgottenDate = :forgotten_date WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('forgotten_code', $user['forgottenCode'], PDO::PARAM_STR);
		$sth->bindValue('forgotten_date', $user['forgottenDate'], PDO::PARAM_STR);
		$sth->bindValue('user_id', $user['id'], PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			if($sth->rowCount() < 1){
				return false;
			}
			return $this->emailer->send_forgot_password($user);
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to update user with forgotten code and date", ['exception' => $db_err]);
			}
			
			throw $db_err;
			
		}
	
	}
	
	/**
	 * Checks if the forgotten code is valid and that it has been used within the time limit
	 * If it passes, it will update the user with the passwordChange flag, forcing a change in passwords on next login
	 *
	 * @param $user object
	 * @param $forgotten_code string
	 * @return boolean
	 */
	public function forgotten_check(UserAccount $user, $forgotten_code){
	
		//check if there is such thing as a forgottenCode and forgottenDate
		if(!empty($user['forgottenCode']) AND $user['forgottenCode'] == $forgotten_code){
		
			$allowed_duration = $this->options['login_forgot_expiration'];
			
			if($allowed_duration != 0){
		
				$forgotten_time = strtotime($user['forgottenDate']);
				//add the allowed duration the forgotten time
				$forgotten_time_duration = strtotime("+ $allowed_duration seconds", $forgotten_time);
				//compare with the current time
				$current_time = strtotime(date('Y-m-d H:i:s'));
				
				if($current_time > $forgotten_time_duration){
				
					//we have exceeded the time, so we need to clear the forgotten so that it defaults back to normal
					//or else there'd be no way of resolving this issue
					$this->forgotten_clear($user);
					return false;
				
				}
			
			}
			
			$query = "UPDATE {$this->options['table_users']} SET passwordChange = 1 WHERE id = :user_id";
			$sth = $this->db->prepare($query);
			$sth->bindValue('user_id', $user['id'], PDO::PARAM_INT);
			
			try{
			
				$sth->execute();
				$user['passwordChange'] = 1;
			
			}catch(PDOException $db_err){
			
				if($this->logger){
					$this->logger->error("Failed to execute query to set the the passwordChange flag to 1.", ['exception' => $db_err]);
				}
				throw $db_err;
			
			}
			
			return true;
		
		}
		
		//if the forgottenCode doesn't exist or the code doesn't match
		return false;
	
	}
	
	/**
	 * Finishes the forgotten cycle, clears the forgotten code and updates the user with the new password
	 * You would call this once the user passes the forgotten check, and automatically changes to the new password.
	 * If you do not call this, the user should be prompted to change on the next login. Use LoginLogout for that.
	 *
	 * @param $user object
	 * @param $forgotten_code string
	 * @return boolean
	 */
	public function forgotten_complete(UserAccount $user, $new_password){
	
		$this->forgotten_clear($user);
		
		//clear the forgotten first and update with new password
		if($this->change_password($user, $new_password)){
			return true;
		}
		
		return false;
	
	}
	
	/**
	 * Clears the forgotten code and forgotten time when we have completed the cycle or if the time limit was exceeded
	 *
	 * @param $user object
	 * @return boolean true
	 */
	public function forgotten_clear(UserAccount $user){
	
		$query = "UPDATE {$this->options['table_users']} SET forgottenCode = NULL, forgottenDate = NULL WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('user_id', $user['id'], PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			
			$user['forgottenCode'] = null;
			$user['forgottenDate'] = null;
			
			//will always return true (should be idempotent)
			return true;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to clear the forgotten code and forgotten time.", ['exception' => $db_err]);
			}
			
			throw $db_err;
		
		}
	
	}
	
	/**
	 * Changes the password of the user. If the old password was provided, it will be checked against the user, otherwise the password change will be forced.
	 * Also passes the password through the complexity checks.
	 * Also sets turns off the password change flag, this is the only place that does this.
	 *
	 * @param $user object
	 * @param $new_password string
	 * @param $old_password string optional
	 * @return boolean
	 */
	public function change_password(UserAccount $user, $new_password, $old_password = false){
	
		//if old password exists, we need to check if it matches the database record
		if($old_password){
		
			$query = "SELECT password FROM {$this->options['table_users']} WHERE id = :user_id";
			$sth = $this->db->prepare($query);
			$sth->bindValue('user_id', $user['id'], PDO::PARAM_INT);
			
			try{
			
				$sth->execute();
				$row = $sth->fetch(PDO::FETCH_OBJ);
				if(!hash_password_verify($old_password, $row->password)){
					throw new PasswordValidationException($this->lang['password_change_unsuccessful']);
				}
				
			}catch(PDOException $db_err){
			
				if($this->logger){
					$this->logger->error("Failed to execute query to get the password hash from user {$user['id']}.", ['exception' => $db_err]);
				}
				
				throw $db_err;
				
			}
			
		}
		
		//password complexity check on the new_password
		if(!$this->password_manager->complex_enough($new_password, $old_password, $user[$this->options['login_identity']])){
			throw new PasswordValidationException($this->password_manager->get_error());
		}
		
		//hash new password
		$new_password = $this->hash_password($new_password, $this->options['hash_method'], $this->options['hash_rounds']);
		
		//update with new password
		$query = "UPDATE {$this->options['table_users']} SET passwordChange = 0, password = :new_password WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('new_password', $new_password, PDO::PARAM_STR);
		$sth->bindValue('user_id', $user['id'], PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			
			if($sth->rowCount() < 1){
				return false;
			}
			
			$user['passwordChange'] = 0;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to update password hash with user {$user['id']}.", ['exception' => $db_err]);
			}
			
			throw $db_err;
		
		}
		
		return true;
	
	}
	
	/**
	 * Resets the password for $user to a random password. Will return the password.
	 * This does not pass the password complexity tests, but will be sufficiently random!
	 *
	 * @param $user object
	 * @return boolean
	 */
	public function reset_password(UserAccount $user){
	
		//find the max of the min or max
		$min = (!empty($this->options['login_password_complexity']['min'])) ? $this->options['login_password_complexity']['min'] : 0;
		$max = (!empty($this->options['login_password_complexity']['max'])) ? $this->options['login_password_complexity']['min'] : 32;
		
		$length = max($min, $max);
		$new_password = $this->random->generate($length, true);
		
		if(!$this->change_password($user, $new_password)){
			return false;
		}
		
		return $new_password;
	
	}
	
	/**
	 * Switches on the password change flag, forcing the user to change their passwords upon their next login
	 *
	 * @param $users array of objects | array of ids
	 * @return boolean true
	 */
	public function force_password_change(array $users){
	
		foreach($users as $user){
			if($user instanceof UserAccount){
				$user_ids[] = $user['id'];
			}else{
				$user_ids[] = $user;
			}
		}
		
		$update_placeholders = implode(",", array_fill(0, count($user_ids), '?'));
		
		$query = "UPDATE {$this->options['table_users']} SET passwordChange = 1 WHERE id IN ($update_placeholders)";
		$sth = $this->db->prepare($query);
		
		try{
		
			$sth->execute($user_ids);
			$user['passwordChange'] =  1;
			//if they were already flagged, then the job has been done
			return true;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to flag the password for change.", ['exception' => $db_err]);
			}
			
			throw $db_err;
		
		}
	
	}
	
	/**
	 * Gets the user according to their id. The user is an augmented object of UserAccount including all the user's data (minus the password) and with any current permissions loaded in.
	 *
	 * @param $user_id int
	 * @return $user object
	 */
	public function get_user($user_id){
	
		$query = "SELECT * FROM {$this->options['table_users']} WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('user_id', $user_id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			$row = $sth->fetch(PDO::FETCH_OBJ);
			if(!$row){
				throw new UserNotFoundException($this->lang('user_select_unsuccessful'));
			}
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to select user $user_id.", ['exception' => $db_err]);
			}
			throw $db_err;
		
		}
		
		//load in the data into the UserAccount
		unset($row->password);
		$user = new UserAccount($row->id);
		$user->set_user_data($row);
		
		//load in the roles and permissions of the user
		$this->role_manager->loadSubjectRoles($user);
		
		return $user;
		
	}
	
	/**
	 * Gets an array of users based on their user ids
	 *
	 * @param $user_ids array
	 * @return $users array | null - Array of (id => UserAccount)
	 */
	public function get_users(array $user_ids){
		
		$select_placeholders = implode(",", array_fill(0, count($user_ids), '?'));
		
		$query = "SELECT * FROM {$this->options['table_users']} WHERE id IN ($select_placeholders)";
		$sth = $this->db->prepare($query);
		
		try{
		
			$sth->execute($user_ids);
            $result = $sth->fetchAll(PDO::FETCH_OBJ);
			if(!$result){
				throw new UserNotFoundException($this->lang('user_select_unsuccessful'));
			}
			
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to select users.", ['exception' => $db_err]);
			}
			throw $db_err;
		
		}
		
		$output_users = array();
		
		foreach($result as $row){
			
			unset($row->password);
			$user = new UserAccount($row->id);
			$user->set_user_data($row);
			$this->role_manager->loadSubjectRoles($user);
			$output_users[] = $user;
		
		}
		
		return $output_users;	
	
	}
	
	/**
	 * Gets an array of users based on an array of role names
	 *
	 * @param $roles array
	 * @return $users array | null
	 */
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
			if(!$result){
				//no users correspond to any of the roles
				throw UserNotFoundException($this->lang['user_role_select_empty']);
			}
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error('Failed to execute query to select subjects from auth subject role based on role names.', ['exception' => $db_err]);
			}
			throw $db_err;
		
		}
		
		$user_ids = array();
		
		foreach($result as $row){
			$user_ids[] = $row->subject_id;
		}
		
		return $this->get_users($user_ids);
	
	}
	
	/**
	 * Gets an array of users based on an array of permission names
	 *
	 * @param $permissions array
	 * @return $users array | null
	 */
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
			if(!$result){
				//no users correspond to any of the permissions
				throw UserNotFoundException($this->lang['user_permission_select_empty']);
			}
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error('Failed to execute query to select subjects from auth subject role based on permission names.', ['exception' => $db_err]);
			}
			throw $db_err;
		
		}
		
		$user_ids = array();
		
		foreach($result as $row){
			$user_ids[] = $row->subject_id;
		}
		
		return $this->get_users($user_ids);
	
	}
	
	/**
	 * Updates a user's profile. This updates the user's information according to the database columns.
	 * If you need to change client session data, use UserSessionsManager instead.
	 *
	 * @param $user object UserAccount
	 * @param $new_user_data array optional
	 * @return $user object | null
	 */
	public function update_user(UserAccount $user, array $new_user_data = null){
	
		if($new_user_data){
			$user->set_user_data($new_user_data);
		}
		
		if(!empty($user['password'])){
		
			if(!empty($user['old_password'])){
				$this->change_password($user, $user['password'], $user['old_password']);
			}else{
				$this->change_password($user, $user['password']);
			}
		
		}
		
		//we've done with passwords
		unset($user['password']);
		unset($user['old_password']);
		
		//we never update the id
		$user_id = $user['id'];
		unset($user['id']);
		
		//now we have to update all the user's fields
		$columns = array_keys($user->get_user_data());
		foreach($columns as $column){
			if(!$this->validate_column($this->options['table_users'], $column)){
				throw new DatabaseValidationException($this->lang['account_update_invalid']);
			}
		}
		
		$update_placeholder = implode(' = ?, ', $columns) . ' = ?';
		
		$query = "UPDATE {$this->options['table_users']} SET $update_placeholder WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('user_id', $user_id, PDO::PARAM_INT);
		
		try{
		
			//execute like an array!
			$sth->execute($user->get_user_data());
			if($sth->rowCount() < 1){
				return false;
			}
			//put the id back into the user
			$user['id'] = $user_id;
			return $user;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to update user $user_id", ['exception' => $db_err]);
			}
			throw $db_err;
		
		}
	
	}
	
	/**
	 * Gets an array of role objects that contains permission objects from an array of role names
	 * If no parameter was passed in, it will get all the roles that currently exist.
	 *
	 * @param $requested_roles array | null
	 * @return $roles array | null
	 */
	public function get_roles(array $requested_roles = null){
	
		$roles = array();
		
		if($requested_roles){
		
			foreach($requested_roles as $role_name){
				if($role = $this->role_manager->roleFetchByName($role_name)){
					$roles[] = $role;
				}
			}
		
		}else{
		
			$roles = $this->role_manager->roleFetch();
		
		}
		
		if(empty($roles)){
			if(!empty($requested_roles)){
				throw new RoleNotFoundException($this->lang['role_not_exists']);
			}
			//if it was empty, we just return null as in, no roles exist
			return null;
		}
		
		//if you want the permissions, just go $roles[#]->getPermissions();
		return $roles;
	
	}
	
	/**
	 * Gets an array of permission objects from an array of permission names
	 * If no parameter was passed in, it will get all the permissions that currently exist
	 *
	 * @param $requested_permissions array | null
	 * @return $permissions array | null
	 */
	public function get_permissions(array $requested_permissions = null){
	
		$permissions = array();
		
		if($requested_permissions){
		
			$select_placeholders = implode(",", array_fill(0, count($requested_permissions), '?'));
			
			$query = "SELECT * FROM auth_permission WHERE name IN ($select_placeholders)";
			$sth = $this->db->prepare($query);
		
			try{
			
				$sth->execute($requested_permissions);
				$permissions = $sth->fetchAll(PDO::FETCH_OBJ);
			
			}catch(PDOException $db_err){
			
				if($this->logger){
					$this->logger->error('Failed to execute query to select permissions from auth permission based on permission names.', ['exception' => $db_err]);
				}
				throw $db_err;
			
			}
		
		}else{
		
			$permissions = $this->role_manager->permissionFetch();
		
		}
		
		if(empty($permissions)){
			if(!empty($requested_permissions)){
				throw new PermissionNotFoundException($this->lang['permission_not_exists']);
			}
			//if it was empty, we just return null as in, no permissions exist
			return null;
		}
		
		return $permissions;
	
	}
	
	/**
	 * Creates or updates a single role given a role name and optionally a role description
	 * Use this function if you just want to register a single role.
	 *
	 * @param $role_name string
	 * @param $role_desc string
	 * @return $roles array of objects
	 */
	public function register_role($role_name, $role_desc = false){
	
		//check if the role already exists
		if($role_object = $this->role_manager->roleFetchByName($role_name)){
			//update the existing role (if the role_desc actually exists)
			$role_object->description = ($role_desc) ? $role_desc : $role_object->description;
		}else{
			//create the new role (if the role_desc is false, pass an empty role desc string)
			$role_desc = ($role_desc) ? $role_desc : '';
			$role_object = Role::create($role_name, $role_desc);
		}
		
		if(!$this->role_manager->roleSave($role_object)){
			throw new RoleSaveException($this->lang('role_save_unsuccessful'));
		}
		
		return $role_object;
	
	}
	
	/**
	 * Creates or updates an array of roles. The array can be associative between role_name => role_desc or just role_name
	 *
	 * @param $roles array
	 * @return $output_roles array of objects
	 */
	public function register_roles(array $roles){
	
		$output_roles = array();
	
		foreach($roles as $key => $value){
		
			if(is_string($key)){
				if(!$role = $this->register_role($key, $value)){
					return false;
				}
			}else{
				if(!$role = $this->register_role($value)){
					return false;
				}
			}
			
			$output_roles[] = $role;
			
		}
		
		return $output_roles;
	
	}
	
	/**
	 * Creates permissions, and assigns them to roles that may be created if they don't already exist
	 * If they already do exist, the permissions will be replaced and updated
	 * Also capable of updating the role descriptions
	 * Use this function when you're constructing an RBAC interface for administrators to create new roles/permissions
	 *
	 * $roles_permissions is accepted in this manner:
	 * 	array(
	 * 		'role_name' => array(
	 * 			'desc' => 'Description of Role',
	 * 			'perms' => array( //<- these are optional (empty array still updates; non-existent key is ignored)
	 * 				'perm_name'	=> 'perm_desc'
	 * 			)
	 * 		),
	 * 		'role_name' => array(
	 * 			'desc' => '', //<- this is also optional (empty string still updates; non-existent key is ignored)
	 * 		),
	 * 		'role_name' => array(
	 * 			'perms' => array(
	 * 				'perm_name' => '', //<- perm_desc is not optional but can be left as an empty string
	 * 			),
	 * 		),
	 *		'role_name'	=> array(
	 *			'perms'	=> array(), //<- this would just clear all the old the permissions
	 *		),
	 * 	);
	 *
	 * @param $roles_permissions array
	 * @return $roles array of objects
	 */
	public function register_roles_permissions(array $roles_permissions){
	
		$role_names = array();
	
		//cycle through the role names
		foreach($roles_permissions as $role_name => $role_data){
		
			//we send role name and description to register role
			if(isset($role_data['desc']) AND is_string($role_data['desc'])){
				$role_object = $this->register_role($role_name, $role_data['desc']);
			}else{
				$role_object = $this->register_role($role_name);
			}
			
			//if any one of the roles failed to be registered (created/updated), fail it
			if(!$role_object){
				throw new RoleSaveException($this->lang('role_register_unsuccessful'));
			}
			
			//at this point role object has already been created or updated
			//if the perms have not been set, there's no need to update it
			if(isset($role_data['perms']) AND is_array($role_data['perms'])){
			
				//first delete all the old permissions (if they exist!)
				$old_permissions = $role_object->getPermissions();
				foreach($old_permissions as $permission_object){
					$this->role_manager->permissionDelete($permission_object);
				}				
				
				//if the perms is not empty, we add/update the new roles
				//if it were empty, we would leave it with no permissions
				if(!empty($role_data['perms'])){
				
					//all permissions will be recreated
					foreach($role_data['perms'] as $permission_name => $permission_desc){
					
						$permission_object = Permission::create($permission_name, $permission_desc);
						if(!$this->role_manager->permissionSave($permission_object)){
							throw new PermissionSaveException($this->lang('permission_save_unsuccessful'));
						}
						if(!$role_object->addPermission($permission_object)){
							throw new PermissionSaveException($this->lang('permission_assignment_unsuccessful'));
						}
						
					}
					
				}
				
				if(!$this->role_manager->roleSave($role_object)){
					throw new RoleSaveException($this->lang('role_save_unsuccessful'));
				}
				
			}
			
			$role_names[] = $role_name;
		
		}
		
		return $this->get_roles($role_names);
	
	}
	
	/**
	 * Delete a single permission
	 *
	 * @param $permission_name string
	 * @return boolean
	 */
	public function delete_permission($permission_name){
	
		if($permission_object = $this->get_permissions(array($permission_name))[0]){
			if(!$this->role_manager->permissionDelete($permission_object)){
				throw new PermissionSaveException($this->lang('permission_delete_unsuccessful'));
			}
		}
		return true;
		
	}
	
	/**
	 * Delete an array of permissions
	 *
	 * @param $permission array
	 * @return boolean
	 */
	public function delete_permissions(array $permissions){
	
		foreach($permissions as $permission_name){
			if(!$this->delete_permission($permission_name)){
				return false;
			}
		}
		return true;
	
	}
	
	/**
	 * Deletes Roles and their associated Permissions. Use this to delete roles by them selves too
	 * Roles that don't exist will be ignored, their associated permissions will also be ignored.
	 *
	 * $roles_permissions is accepted in this manner:
	 * 	array(
	 * 		'role_name' => array(
	 * 			'perm_name',
	 * 			'perm_name2',
	 * 		),
	 * 		'role_name',
	 * 	);
	 *
	 * @param $roles_permissions
	 * @return boolean
	 */
	public function delete_roles_permissions(array $roles_permissions){
	
		foreach($roles_permissions as $key => $value){
		
			if(is_array($value)){
			
				//delete permissions as well
				if($role_object = $this->role_manager->roleFetchByName($key)){
				
					foreach($value as $permission){
						$this->delete_permission($permission);
					}
					
					if(!$this->role_manager->roleDelete($role_object)){
						throw new RoleSaveException($this->lang('role_delete_unsuccessful'));
					}
				
				}
			
			}else{
			
				//just delete the role
				if($role_object = $this->role_manager->roleFetchByName($value)){
				
					if(!$this->role_manager->roleDelete($role_object)){
						throw new RoleSaveException($this->lang('role_delete_unsuccessful'));
					}
				
				}
			
			}
		
		}
		
		return true;
	
	}
	
	/**
	 * Save an array of role objects. This function is not used internally, but it's to provide a pass through API to the RBAC package.
	 * It can allow incremental updates to a single or multitude of $role objects. It can update or insert role objects.
	 *
	 * @param $roles array of objects
	 * @return boolean
	 */
	public function save_roles(array $roles){
	
		foreach($roles as $role){
			if(is_object($role)){
				//if at any times the roleSave failed, we have to return false
				if(!$this->role_manager->roleSave($role)){
					throw new RoleSaveException($this->lang('role_save_unsuccessful'));
				}
			}
		}
		return true;
		
	}
	
	/**
	 * Takes a UserAccount object and array of role names and registers those roles against the user.
	 * The roles must already exist.
	 *
	 * @param $user object
	 * @param $role_names array
	 * @return $user
	 */
	public function register_user_roles(UserAccount $user, array $role_names){
		
		foreach($role_names as $role_name){
		
			$role = $this->role_manager->roleFetchByName($role_name);
			
			if(!$role){
				throw new RoleNotFoundException($this->lang['role_not_exists']);
			}
			
			if(!$this->role_manager->roleAddSubject($role, $user)){
				throw new UserRoleAssignmentException($this->lang['role_assignment_unsuccessful']);
			}
			
		}
		
		return $user;
	
	}
	
	protected function validate_column($table, $column){
	
		$sth = $this->db->prepare("DESCRIBE $table");
		
		try{
		
			$sth->execute();
			//will return an numerically indexed array of field names
			$table_fields = $sth->fetchAll(PDO::FETCH_COLUMN, 0);
			
		}catch(PDOExcepton $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to describe $table.", ['exception' => $db_err]);
			}
			throw $db_err;
			
		}
		
		if(in_array($column, $table_fields)){
			return true;
		}
		return false;
	
	}
	
	public function get_errors(){
		if(!empty($this->errors)){
			return $this->errors;
		}else{
			return false;
		}
	}

}