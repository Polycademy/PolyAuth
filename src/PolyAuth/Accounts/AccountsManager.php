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

class AccountsManager{

	protected $db;
	protected $options;
	protected $lang;
	protected $logger;
	protected $password_manager;
	protected $random;
	protected $role_manager;
	protected $emailer;
	protected $bcrypt_fallback = false;
	
	protected $errors = array();
	
	//expects PDO connection (potentially using $this->db->conn_id)
	//SessionInterface is a copy of the PHP5.4.0 SessionHandlerInterface, this allows backwards compatibility
	public function __construct(PDO $db, Options $options, Language $language, LoggerInterface $logger = null){
	
		$this->options = $options;
		$this->lang = $language;
		
		$this->db = $db;
		$this->logger = $logger;
		$this->password_manager = new PasswordComplexity($options, $language);
		$this->random = new Random;
		$this->role_manager  = new RoleManager($db, $logger);
		$this->emailer = new Emailer($db, $options, $language, $logger);
		
		//if you use bcrypt fallback, you must always use bcrypt fallback, you cannot switch servers!
		if($this->options['hash_fallback']){
			$this->bcrypt_fallback = new BcryptFallback($this->options['hash_rounds']);
		}
		
	}
	
	/**
	 * Register a new user. It adds some default data and role/permissions. It also handles the activation emails.
	 * Validation of the $data array is the end user's responsibility. We don't know what custom data fields the end user may want.
	 *
	 * @param $data array - $data parameter corresponds to user columns or properties. Make sure the identity and password and any other insertable properties are part of it.
	 * @return $registered_user object - This is a fully loaded user object containing its roles and user data.
	 */
	public function register(array $data){
		
		//login_data should have username, password or email
		if(empty($data[$this->options['login_identity']]) OR empty($data['password'])){
			$this->errors[] = $this->lang['account_creation_invalid'];
			return false;
		}
		
		if($this->options['email']){
			if(empty($data['email'])){
				$this->errors[] = $this->lang['account_creation_email_invalid'];
				return false;
			}
		}
		
		//check for duplicates based on identity
		if(!$this->identity_check($data[$this->options['login_identity']])){
			return false;
		}
		
		//check if password is complex enough
		if(!$this->password_manager->complex_enough($data['password'])){
			$this->errors += $this->password_manager->get_errors();
			return false;
		}
		
		$data['ipAddress'] = $this->prepare_ip($_SERVER['REMOTE_ADDR']);
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
		
		$column_string = implode(',', array_keys($data));
		$value_string = implode(',', array_fill(0, count($data), '?'));
		
		$query = "INSERT INTO {$this->options['table_users']} ({$column_string}) VALUES ({$value_string})";
		$sth = $this->db->prepare($query);
		
		try {
		
			$sth->execute(array_values($data));
			$last_insert_id = $sth->lastInsertId();
			
		}catch(PDOException $db_err){

			if($this->logger){
				$this->logger->error('Failed to execute query to register a new user and assign permissions.', ['exception' => $db_err]);
			}
			$this->errors[] = $this->lang['account_creation_unsuccessful'];
			return false;
			
		}
		
		//grab the user's data that we just inserted
		$registered_user = $this->get_user($last_insert_id);
		
		//now we've got to add the default roles and permissions
		if(!$registered_user = $this->register_roles($registered_user, array($this->options['role_default']))){
			return false;
		}
		
		//automatically send the activation email
		if($this->options['reg_activation'] == 'email' AND $this->options['email'] AND $registered_user->email){
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
		$sth->bindParam(':user_id', $user->id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			
			if($sth->rowCount >= 1){
				return true;
			}
			
			$this->errors[] = $this->lang['delete_already'];
			return false;
			
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error('Failed to execute query to delete a user.', ['exception' => $db_err]);
			}
			$this->errors[] = $this->lang['delete_unsuccessful'];
			return false;
		
		}
	
	}
	
	/**
	 * Checks for duplicate identity, returns false if the identity already exists, returns true if identity doesn't exist
	 *
	 * @param $identity string - depends on the options
	 * @return boolean
	 */
	public function identity_check($identity){
		
		$query = "SELECT id FROM {$this->options['table_users']} WHERE {$this->options['login_identity']} = :identity";
		$sth = $this->db->prepare($query);
		$sth->bindParam(':identity', $identity, PDO::PARAM_STR);
		
		try {
		
			//there basically should be nothing returned, if something is returned then identity check fails
			$sth->execute();
			if($sth->fetch()){
				$this->errors[] = $this->lang["account_creation_duplicate_{$this->options['login_identity']}"];
				return false;
			}
			return true;
			
		}catch(PDOException $db_err){

			if($this->logger){
				$this->logger->error('Failed to execute query to check duplicate login identities.', ['exception' => $db_err]);
			}
			$this->errors[] = $this->lang['account_creation_unsuccessful'];
			return false;
			
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
		
			//we don't need to check what the reg_activation is, give options to the end user
			if($this->options['email'] AND $user->email){
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
		if($user->activationCode == $activation_code){
			return $this->force_activate($user);
		}
		
		$this->errors[] = $this->lang['activate_unsuccessful'];
		return false;
	
	}
	
	protected function force_activate($user){
	
		$query = "UPDATE {$this->options['table_users']} SET active = 1, activationCode = NULL WHERE id = :id";
		$sth = $this->db->prepare($query);
		$sth->bindParam(':id', $user->id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			$user->active = 1;
			$user->activationCode = null;
			return true;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to activate user {$user->id}.", ['exception' => $db_err]);
			}
			$this->errors[] = $this->lang['activate_unsuccessful'];
			return false;
		
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
		$sth->bindParam(':activation_code', $activation_code, PDO::PARAM_STR);
		$sth->bindParam(':id', $user->id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			$user->active = 0;
			$user->activationCode = $activation_code;
			return $activation_code;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to deactivate user {$user->id}.", ['exception' => $db_err]);
			}
			$this->errors[] = $this->lang['deactivate_unsuccessful'];
			return false;
		
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
	 * Generates a forgotten code and forgotten time
	 *
	 * @param $user object
	 * @return boolean
	 */
	public function forgotten_password(UserAccount $user){
	
		$user->forgottenCode = $this->random->generate(40);
		$user->forgottenDate = date('Y-m-d H:i:s');
		
		$query = "UPDATE {$this->options['table_users']} SET passwordChange = 1, forgottenCode = :forgotten_code, forgottenDate = :forgotten_date WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindParam('forgotten_code', $user->forgottenCode PDO::PARAM_STR);
		$sth->bindParam('forgotten_date', $user->forgottenDate, PDO::PARAM_STR);
		$sth->bindParam('user_id', $user->id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			if($sth->rowCount < 1){
				//no one was updated
				$this->errors[] = $this->lang['forgot_unsuccessful'];
				return false;
			}
			
			//continue to send email
			return $this->emailer->send_forgot_password($user);
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to update user with forgotten code and date", ['exception' => $db_err]);
			}
			$this->errors[] = $this->lang['deactivate_unsuccessful'];
			return false;
		
		}
	
	}
	
	/**
	 * Checks if the forgotten code is valid and that it has been used within the time limit
	 *
	 * @param $user object
	 * @param $forgotten_code string
	 * @return boolean
	 */
	public function forgotten_check(UserAccount $user, $forgotten_code){
	
		//check if there is such thing as a forgottenCode and forgottenTime
		if(!empty($user->forgottenCode) AND $user->forgottenCode == $forgotten_code){
		
			$allowed_duration = $this->options['login_forgot_expiration'];
			
			if($allowed_duration != 0){
		
				$forgotten_time = strtotime($user->forgottenTime);
				//add the allowed duration the forgotten time
				$forgotten_time_duration = strtotime("+ $allowed_duration seconds", $forgotten_time);
				//compare with the current time
				$current_time = strtotime(date('Y-m-d H:i:s'));
				
				if($current_time > $forgotten_time_duration){
				
					//we have exceeded the time, so we need to clear the forgotten so that it defaults back to normal
					//or else there'd be no way of resolving this issue
					$this->forgotten_clear($user);
					$this->errors[] = $this->lang['forgot_check_unsuccessful'];
					return false;
				
				}
			
			}
			
			//at this point everything should be good to go
			return true;
		
		}

		//if the forgottenCode doesn't exist or the code doesn't match, then we just return false, no need to clear
		$this->errors[] = $this->lang['forgot_check_unsuccessful'];
		return false;
	
	}
	
	/**
	 * Finishes the forgotten cycle, clears the forgotten code and updates the user with the new password
	 *
	 * @param $user object
	 * @param $forgotten_code string
	 * @return boolean
	 */
	public function forgotten_complete(UserAccount $user, $new_password){
	
		//clear the forgotten first and update with new password
		if($this->forgotten_clear($user) AND $this->change_password($user, $new_password)){
			return true;
		}
		return false;
	
	}
	
	/**
	 * Clears the forgotten code and forgotten time when we have completed the cycle or if the time limit was exceeded
	 *
	 * @param $user object
	 * @return boolean
	 */
	public function forgotten_clear(UserAccount $user){
	
		$query = "UPDATE {$this->options['table_users']} SET passwordChange = 0, forgottenCode = NULL, forgottenTime = NULL WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindParam('user_id', $user->id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			if($sth->rowCount < 1){
				//no one was updated
				$this->errors[] = $this->lang['forgot_unsuccessful'];
				return false;
			}
			
			$user->forgottenCode = null;
			$user->forgottenTime = null;
			
			return true;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to clear the forgotten code and forgotten time.", ['exception' => $db_err]);
			}
			$this->errors[] = $this->lang['forgot_unsuccessful'];
			return false;
		
		}
	
	}
	
	/**
	 * Changes the password of the user. If the old password was provided, it will be checked against the user, otherwise the password change will be forced.
	 * Also passes the password through the complexity checks.
	 * Also sets turns off the password change flag
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
			$sth->bindParam('user_id', $user->id, PDO::PARAM_INT);
			try{
				$sth->execute();
				$row = $sth->fetch(PDO::FETCH_OBJ);
				if(!hash_password_verify($old_password, $row->password)){
					$this->errors[] = $this->lang['password_change_unsuccessful'];
					return false;
				}
			}catch(PDOException $db_err){
				if($this->logger){
					$this->logger->error("Failed to execute query to get the password hash from user {$user->id}.", ['exception' => $db_err]);
				}
				$this->errors[] = $this->lang['password_change_unsuccessful'];
				return false;
			}
		}
		
		//password complexity check on the new_password
		if(!$this->password_manager->complex_enough($new_password, $old_password, $user->{$this->options['identity']}){
			$this->errors += $this->password_manager->get_errors();
			return false;
		}
		
		//hash new password
		$new_password = $this->hash_password($new_password, $this->options['hash_method'], $this->options['hash_rounds']);
		
		//update with new password
		$query = "UPDATE {$this->options['table_users']} SET password = :new_password, passwordChange = 0 WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindParam('new_password', $new_password, PDO::PARAM_STR);
		$sth->bindParam('user_id', $user->id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			if($sth->rowCount < 1){
				$this->errors[] = $this->lang['password_change_unsuccessful'];
				return false;
			}
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to update password hash with user {$user->id}.", ['exception' => $db_err]);
			}
			$this->errors[] = $this->lang['password_change_unsuccessful'];
			return false;
		
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
	 * @param $users array of objects
	 * @return boolean
	 */
	public function force_password_change(array $users){
	
		foreach($users as $user){
			$in_sql[] = $user->id;
		}
		
		$in_sql = implode(',', $in_sql);
		
		$query = "UPDATE {$this->options['table_users']} SET passwordChange = 1 WHERE id IN ($in_sql)";
		$sth = $this->db->prepare($query);
		
		try{
		
			$sth->execute();
			//if they were already flagged, then the job has been done
			return true;
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to flag the password for change.", ['exception' => $db_err]);
			}
			$this->errors[] = $this->lang['password_flag'];
			return false;
		
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
		$sth->bindParam('user_id', $user_id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			$row = $sth->fetch(PDO::FETCH_OBJ);
			if(!$row){
				$this->errors[] = $this->lang('user_select_unsuccessful');
				return false;
			}
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to select user $user_id.", ['exception' => $db_err]);
			}
			$this->errors[] = $this->lang['user_select_unsuccessful'];
			return false;
		
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
		
		//some users may not exist, we'll return null for the ones that don't exist
		$list_of_ids = implode(',', $user_ids);
		$query = "SELECT * FROM {$this->options['table_users']} WHERE id IN ($list_of_ids)";
		$sth = $this->db->prepare();
		
		try{
		
			$sth->execute();
            $result = $sth->fetchAll(PDO::FETCH_OBJ);
			if(!$result){
				return null;
			}
			
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to select users of $list_of_ids.", ['exception' => $db_err]);
			}
			$this->errors[] = $this->lang['user_select_unsuccessful'];
			return false;
		
		}
		
		$output_users = array();
		
		foreach($result as $row){
			
			unset($row->password);
			$user = new UserAccount($row->id);
			$user->set_user_data($row);
			$this->role_manager->loadSubjectRoles($user);
			$output_users[$id] = $user;
		
		}
		
		return $output_users	
	
	}
	
	/**
	 * Gets an array of users based on an array of roles
	 *
	 * @param $roles array
	 * @return $users array | null
	 */
	public function get_users_by_role(array $roles){
	
		$role_names = implode(',' $roles);
		
		//double join
		$query = "
			SELECT asr.subject_id 
			FROM auth_subject_role AS asr 
			INNER JOIN auth_role AS ar ON asr.role_id = ar.role_id 
			WHERE ar.name IN ($role_names)
		";
		
		$sth = $this->db->prepare($query);
		
		try{
			
			$sth->execute();
			$result = $sth->fetchAll(PDO::FETCH_OBJ);
			if(!$result){
				//no users correspond to any of the roles
				$this->errors[] = $this->lang['user_role_select_empty'];
				return null;
			}
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to select subjects from auth subject role based on roles: $role_names", ['exception' => $db_err]);
			}
			$this->errors[] = $this->lang['user_role_select_unsuccessful'];
			return false;
		
		}
		
		$user_ids = array();
		
		foreach($result as $row){
			$user_ids[] = $row->subject_id;
		}
		
		return $this->get_users($user_ids);
	
	}
	
	/**
	 * Gets an array of users based on an array of permissions
	 *
	 * @param $permissions array
	 * @return $users array | null
	 */
	public function get_users_by_permission(array $permissions){
	
		$permission_names = implode(',', $permissions);
		
		//triple join
		$query = "
			SELECT asr.subject_id 
			FROM auth_subject_role AS asr 
			INNER JOIN auth_role_permissions AS arp ON asr.role_id = arp.role_id
			INNER JOIN auth_permissions AS ap ON arp.permission_id = ap.permission_id
			WHERE ap.name IN ($permission_names)
		";
		
		try{
			
			$sth->execute();
			$result = $sth->fetchAll(PDO::FETCH_OBJ);
			if(!$result){
				//no users correspond to any of the permissions
				$this->errors[] = $this->lang['user_permission_select_empty'];
				return null;
			}
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to select subjects from auth subject role based on permissions: $permission_names", ['exception' => $db_err]);
			}
			$this->errors[] = $this->lang['user_permission_select_unsuccessful'];
			return false;
		
		}
		
		$user_ids = array();
		
		foreach($result as $row){
			$user_ids[] = $row->subject_id;
		}
		
		return $this->get_users($user_ids);
	
	}
	
	/**
	 * Gets an array of role objects that contains permission objects from an array of role names
	 *
	 * @param $requested_roles array
	 * @return $roles array | null
	 */
	public function get_roles(array $requested_roles){
	
		$roles = array();
	
		foreach($requested_roles as $role_name){
			if($role = $this->role_manager->roleFetchByName($role_name)){
				$roles[$role_name] = $role;
			}
		}
		
		if(empty($roles)){
			return null;
		}
		
		//if you want the permissions, just go $roles['role_name']->getPermissions();
		return $roles;
	
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
			if(!role_object){
				return false;
			}
			
			//at this point role object has already been created or updated
			//if the perms have not been set, there's no need to update it
			if(isset($role_data['perms'] AND is_array($role_data['perms'])){
			
				//first delete all the old permissions (if they exist!)
				$old_permissions = $role_object->getPermissions();
				foreach($old_permissions as $permission_object){
					$this->role_manager->permissionDelete($permission_object);
				}
				
				//if the perms is not empty, we add/update the new roles
				//if it were empty, we would leave it with no permissions
				if(!empty($role_data['perms']){
				
					//all permissions will be recreated
					foreach($role_data['perms'] as $permission_name => $permission_desc){
					
						$permission_object = Permission::create($permission_name, $permission_desc);
						if(!$this->role_manager->permissionSave($permission_object)){
							$this->errors[] = $this->lang('permission_save_unsuccessful');
							return false;
						}
						if(!$role_object->addPermission($permission_object)){
							$this->errors[] = $this->lang('permission_assignment_unsuccessful');
							return false;
						}
						
					}
					
				}
				
				if(!$this->role_manager->roleSave($role_object)){
					$this->errors[] = $this->lang('role_save_unsuccessful');
					return false;
				}
				
			}
			
			$role_names[] = $role_name;
		
		}
		
		return $this->get_roles($role_names);
	
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
		if($role_object = $this->role_manager->roleFetchByName($role_name){
			//update the existing role (if the role_desc actually exists)
			$role_object->description = ($role_desc) ? $role_desc : $role_object->description;
		}else{
			//create the new role (if the role_desc is false, pass an empty role desc string)
			$role_desc = ($role_desc) ? $role_desc : '';
			$role_object = Role::create($role_name, $role_desc);
		}
		
		if(!$this->role_manager->roleSave($role_object)){
			$this->errors[] = $this->lang('role_save_unsuccessful');
			return false;
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
			
			$output_roles[$key] = $role;
			
		}
		
		return $output_roles;
	
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
	 * @param $role_permissions
	 * @return boolean
	 */
	public function delete_roles_permissions(array $roles_permissions){
	
		foreach($role_permissions as $key => $value){
		
			if(is_array($value)){
			
				//delete permissions as well
				if($role_object = $this->role_manager->roleFetchByName($key)){
				
					foreach($value as $permission){
					
						if(!$this->delete_permission($permission)){
							return false;
						}
					
					}
					
					if(!$this->role_manager->roleDelete($role_object)){
						$this->errors[] = $this->lang('role_delete_unsuccessful');
						return false;
					}
				
				}
			
			}else{
			
				//just delete the role
				if($role_object = $this->role_manager->roleFetchByName($value)){
				
					if(!$this->role_manager->roleDelete($role_object)){
						$this->errors[] = $this->lang('role_delete_unsuccessful');
						return false;
					}
				
				}
			
			}
		
		}
		
		return true;
	
	}
	
	/**
	 * Delete a single permission
	 *
	 * @param $permission_name string
	 * @return boolean
	 */
	public function delete_permission($permission_name){
	
		if($permission_object = $this->role_manager->permissionFetchByName($permission){
			if(!$this->role_manager->permissionDelete($permission_object)){
				$this->errors[] = $this->lang('permission_delete_unsuccessful');
				return false;
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
	
	//we need some functions that allow incremental updates of the role
	//basically export the $role object (which allows incremental updates.. etc)
	//then expose the roleSave in the rbac which would update the role or insert the role (but since they wouldn't have access to create the role, it would most likely update)
	//it's basically a process of using get_roles() -> modify role object -> role_save();
	public function save_roles(array $roles){
	
		foreach($roles as $role){
			if(is_object($role)){
				//if at any times the roleSave failed, we have to return false
				if(!$this->role_manager->roleSave($role)){
					$this->errors[] = $this->lang('role_save_unsuccessful');
					return false;
				}
			}
		}
		return true;
		
	}
	
	//takes a user id and role object, and adds it to the user and saves it, the role object should have a list of permissions
	public function register_roles(UserAccount $user, array $role_names){
		
		foreach($role_names as $role_name){
		
			$role = $this->role_manager->roleFetchByName($role_name);
			
			if(!$this->role_manager->roleAddSubject($role, $user)){
				$this->errors[] = $this->lang['role_assignment_unsuccessful'];
				return false;
			}
			
		}
		
		return $user;
	
	}
	
	public function get_errors(){
		if(!empty($this->errors)){
			return $this->errors;
		}else{
			return false;
		}
	}

}