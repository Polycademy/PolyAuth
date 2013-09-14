<?php

namespace PolyAuth\Accounts;

use Psr\Log\LoggerInterface;
use Psr\Log\LoggerAwareInterface;

use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\Storage\StorageInterface;

use PolyAuth\UserAccount;
use PolyAuth\Accounts\Rbac;

use PolyAuth\Security\PasswordComplexity;
use PolyAuth\Security\Random;
use PolyAuth\Security\Encryption;

use PolyAuth\Emailer;
use PolyAuth\Sessions\LoginAttempts;

use PolyAuth\Exceptions\ValidationExceptions\RegisterValidationException;
use PolyAuth\Exceptions\ValidationExceptions\PasswordValidationException;
use PolyAuth\Exceptions\ValidationExceptions\DatabaseValidationException;
use PolyAuth\Exceptions\UserExceptions\UserDuplicateException;
use PolyAuth\Exceptions\UserExceptions\UserNotFoundException;

class AccountsManager implements LoggerAwareInterface{

	protected $storage;
	protected $options;
	protected $lang;
	protected $logger;
	protected $rbac;
	protected $password_complexity;
	protected $random;
	protected $encryption;
	protected $emailer;
	protected $login_attempts;
	
	public function __construct(
		StorageInterface $storage, 
		Options $options, 
		Language $language, 
		LoggerInterface $logger = null, 
		Rbac $rbac = null, 
		PasswordComplexity $password_complexity = null, 
		Random $random = null, 
		Encryption $encryption = null,
		Emailer $emailer = null,
		LoginAttempts $login_attempts = null
	){
	
		$this->storage = $storage;
		$this->options = $options;
		$this->lang = $language;
		$this->logger = $logger;
		$this->rbac  = ($rbac) ? $rbac : new Rbac($storage, $language, $logger);
		$this->password_complexity = ($password_complexity) ? $password_complexity : new PasswordComplexity($options, $language);
		$this->random = ($random) ? $random : new Random;
		$this->encryption = ($encryption) ? $encryption : new Encryption();
		$this->emailer = ($emailer) ? $emailer : new Emailer($options, $language, $logger);
		$this->login_attempts = ($login_attempts) ? $login_attempts : new LoginAttempts($storage, $options, $logger);
		
	}
	
	/**
	 * Sets a logger instance on the object
	 *
	 * @param LoggerInterface $logger
	 * @return null
	 */
	public function setLogger(LoggerInterface $logger){
		$this->logger = $logger;
	}
	
	/**
	 * Register a new user. It adds some default data and role/permissions. It also handles the activation emails.
	 * Validation of the $data array is the end user's responsibility. We don't know what custom data fields the end user may want.
	 *
	 * @param $data array - $data parameter corresponds to user columns or properties. Make sure the identity and password and any other insertable properties are part of it.
	 * @param $force_active boolean - Used to force a registered active user regardless of reg activation options. Can be used to create admin accounts
	 * @return $registered_user object | false - This is a fully loaded user object containing its roles and user data.
	 */
	public function register(array $data, $force_active = false){
		
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
		if($this->duplicate_identity_check($data[$this->options['login_identity']])){
			throw new UserDuplicateException($this->lang["account_creation_duplicate_{$this->options['login_identity']}"]);
		}
		
		//check if password is complex enough
		if(!$this->password_complexity->complex_enough($data['password'])){
			throw new PasswordValidationException($this->password_complexity->get_error());
		}
		
		//constructing the payload now
		$ip = (!empty($_SERVER['REMOTE_ADDR'])) ? $_SERVER['REMOTE_ADDR'] : '127.0.0.1';
		$data['ipAddress'] = inet_pton($ip);
		$data['password'] = password_hash($data['password'], $this->options['hash_method'], ['cost' => $this->options['hash_rounds']]);
		
		if($force_active){
			$activated = 1;
		}else{
			$activated = ($this->options['reg_activation'] === false) ? 1 : 0;
		}
		
		$data += array(
		    'createdOn'	=> date('Y-m-d H:i:s'),
		    'lastLogin'	=> date('Y-m-d H:i:s'),
		    'active'	=> $activated,
		);
		
		//inserting activation code into the users table, whether it is manual or email
		if(!empty($this->options['reg_activation']) AND !$force_active){
			$data['activationCode'] = $this->random->generate(40); 
		}
		
		//we need to validate that the columns actually exist
		$columns = array_keys($data);
		if(!$this->storage->validate_columns($this->options['table_users'], $columns)){
			throw new DatabaseValidationException($this->lang['account_creation_invalid']);
		}
		
		$last_insert_id = $this->storage->register_user($data, $columns);
		
		//grab the user's data that we just inserted
		$registered_user = $this->get_user($last_insert_id);
		
		//now we've got to add the default roles and permissions
		$registered_user = $this->rbac->register_user_roles($registered_user, array($this->options['role_default']));
		
		//automatically send the activation email
		if(
			$this->options['reg_activation'] == 'email' 
			AND $this->options['email'] 
			AND $registered_user['email'] 
			AND !$force_active
		){
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

		if(!$this->storage->deregister_user($user['id'])){

			throw new UserNotFoundException($this->lang['account_delete_already']);
			return false;

		};

		return true;
	
	}
	
	/**
	 * Checks for duplicate identity, returns true if the identity exists, false if the identity already exist
	 *
	 * @param $identity string
	 * @return boolean - true if duplicate, false if no duplicate
	 */
	public function duplicate_identity_check($identity){
		
		return $this->storage->duplicate_identity_check($identity);
	
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
	
	/**
	 * Force activates an user account regardless of any conditions.
	 * @param  UserAccount $user
	 * @return Boolean
	 */
	protected function force_activate($user){
	
		if($this->storage->force_activate($user['id']){
			$user['active'] = 1;
			$user['activationCode'] = null;
			return true;
		};

		return false;
		
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

		if($this->storage->deactivate($user['id'], $activation_code)){
			$user['active'] = 0;
			$user['activationCode'] = $activation_code;
			return $activation_code;
		}

		return false;
	
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
		
		if($this->storage->forgotten_password($user['id'], $user['forgottenCode'], $user['forgottenDate'])){
			return $this->emailer->send_forgotten_password($user);
		}

		return false;
	
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

			$this->storage->password_change_flag($user['id']);
			$user['passwordChange'] = 1;
			
			return true;
		
		}
		
		//if the forgottenCode doesn't exist or the code doesn't match
		return false;
	
	}
	
	/**
	 * Finishes the forgotten cycle, clears the forgotten code and updates the user with the new password
	 * You would call this once the user passes the forgotten check, and enters a new password.
	 * If you do not call this, the user will not be allowed the login on the next login or autologin attempt.
	 * Furthermore if the password is not changed, the forgotten code will not be cleared.
	 * It also clears any login attempts for this user, so that if the user had failed attempts, then changed
	 * their password, then they should be allowed to login without the throttling hindering their way.
	 *
	 * @param $user object
	 * @param $new_password string
	 * @return boolean
	 */
	public function forgotten_complete(UserAccount $user, $new_password){
	
		//removes the change password flag, and then removes the forgotten codes
		if($this->change_password($user, $new_password)){
			$this->forgotten_clear($user);
			//clear any login attempts to allow bypass
			if(!empty($this->options['login_lockout'])){
				//we need to clear both the ipaddress or the identity simultaneously
				$this->login_attempts->clear($user[$this->options['login_identity']], true);
			}
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
	
		if($this->storage->forgotten_password_clear($user['id'])){
			$user['forgottenCode'] = null;
			$user['forgottenDate'] = null;
		}

		return true;
	
	}

	/**
	 * Registration for users that are authenticating from external providers.
	 * You do not need any user details, they can be filled in later.
	 * This means that we're registering a user with no username, password or email.
	 * @return object       The user object
	 */
	public function external_register(){

		$ip = (!empty($_SERVER['REMOTE_ADDR'])) ? $_SERVER['REMOTE_ADDR'] : '127.0.0.1';
		
		$data = array(
			'ipAddress'	=> inet_pton($ip),
		    'createdOn'	=> date('Y-m-d H:i:s'),
		    'lastLogin'	=> date('Y-m-d H:i:s'),
		    'active'	=> 1,
		);

		$last_insert_id = $this->storage->external_register($data);
		
		$registered_user = $this->get_user($last_insert_id);
		
		$registered_user = $this->rbac->register_user_roles($registered_user, array($this->options['role_default']));
		
		return $registered_user;

	}

	public function external_provider_check($external_identifier, $provider_name){

		$result = $this->storage->get_external_providers($external_identifier);

		//if false, we will create a new user account
		if(!$result){
			return false;
		}

		//we need to check if one of them contains the same provider this would mean that this provider is already registered with us and we would need to update the tokenObject
		foreach($result as $row){
			if($row->provider == $provider_name){
				return array(
					'user_id'		=> $row->userId,
					'provider_id'	=> $row->id,
				);
			}
		}

		//at this point the provider doesn't currently exist, but there are other providers that match the external_identifier therefore we would need add a new provider record
		return array('user_id' => $result[0]->userId);

	}

	public function register_external_provider(array $data){

		if(!empty($this->options['external_token_encryption'])){
			$data['tokenObject'] = $this->encryption->encrypt($data['tokenObject'], $this->options['external_token_encryption']);
		}

		return $this->storage->register_external_provider($data);

	}

	//removes external provider given a provider_id
	//or perhaps provider name with user id??
	//this would be used for unlinking provider accounts
	//or perhaps if we could detect revokes?
	public function deregister_external_provider(){

	}

	//this would be used for autologin, since when we login we would already have the token object.
	//we would get all the providers, given a user_id
	//then augment the providers in the OAuthStrategy
	public function get_external_providers_by_user(){

	}

	public function update_external_provider($provider_id, array $new_data){

		if(!empty($this->options['external_token_encryption'])){
			$new_data['tokenObject'] = $this->encryption->encrypt($new_data['tokenObject'], $this->options['external_token_encryption']);
		}

		return $this->storage->update_external_provider($provider_id, $new_data);

	}

	//also note to change any functions relating to deletion of users (such as deregister)
	//also change the user object in order to extract any external providers! 
	
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

			$check_password = $this->storage->get_password($user['id']);
			if(!password_verify($old_password, $check_password)){
				throw new PasswordValidationException($this->lang['password_change_unsuccessful']);
			}
			
		}
		
		//password complexity check on the new_password
		if(!$this->password_complexity->complex_enough($new_password, $old_password, $user[$this->options['login_identity']])){
			throw new PasswordValidationException($this->password_complexity->get_error());
		}
		
		//hash new password
		$new_password = password_hash($new_password, $this->options['hash_method'], ['cost' => $this->options['hash_rounds']]);
		
		//update with new password
		if(!$this->storage->update_password($user['id'], $new_password)){
			return false;
		}
		
		$user['passwordChange'] = 0;
		
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
		$max = (!empty($this->options['login_password_complexity']['max'])) ? $this->options['login_password_complexity']['max'] : 32;
		
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

		//if they were already flagged, then the job has been done
		$this->storage->multi_password_change_flag($user_ids);

		foreach($users as $user){
			if($user instanceof UserAccount){
				$user['passwordChange'] =  1;
			}
		}

		return true;
	
	}
	
	/**
	 * Gets the user according to their id. The user is an augmented object of UserAccount including all the user's data (minus the password) and with any current permissions loaded in.
	 *
	 * @param $user_id int
	 * @return $user object
	 */
	public function get_user($user_id){

		$row = $this->storage->get_user($user_id);
		if(!$row){
			throw new UserNotFoundException($this->lang['user_select_unsuccessful']);
		}
		
		//load in the data into the UserAccount
		unset($row->password);
		$user = new UserAccount($row->id);
		$user->set_user_data($row);
		
		//load in the roles and permissions of the user
		$user = $this->rbac->load_subject_roles($user);
		
		return $user;
		
	}
	
	/**
	 * Gets an array of users based on their user ids
	 *
	 * @param $user_ids array
	 * @return $users array | null - Array of (id => UserAccount)
	 */
	public function get_users(array $user_ids){

		$result = $this->storage->get_users($user_ids);
		if(!$result){
			throw new UserNotFoundException($this->lang['user_select_unsuccessful']);
		}
		
		$output_users = array();
		
		foreach($result as $row){
			
			unset($row->password);
			$user = new UserAccount($row->id);
			$user->set_user_data($row);
			$this->rbac->load_subject_roles($user);
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

		$result = $this->storage->get_users_by_role($roles);
		if(!$result){
			//no users correspond to any of the roles
			throw new UserNotFoundException($this->lang['user_role_select_empty']);
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
	
		$result = $this->storage->get_users_by_permission($permissions);
		if(!$result){
			//no users correspond to any of the permissions
			throw new UserNotFoundException($this->lang['user_permission_select_empty']);
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
		if(!$this->storage->validate_columns($this->options['table_users'], $columns)){
			throw new DatabaseValidationException($this->lang['account_update_invalid']);
		}

		if($this->storage->update_user($user_id, $user->get_user_data(), $columns)){
			//put the id back into the user
			$user['id'] = $user_id;
			return $user;
		}
	
	}
	
	/**
	 * Bans a user account. This will prevent logging in and reregistering.
	 * The record will still exist in the database, so you can keep a record of the user's information.
	 * This does not set cookies or IP based blocks as those are ineffective, you can do that if you wish.
	 * It will return false if the query did not update anything.
	 *
	 * @param $user object
	 * @return $user object | boolean
	 */
	public function ban_user(UserAccount $user){

		if($this->storage->ban_user($user['id'])){
			$user['banned'] = 1;
			return $user;
		}

		return false;
	
	}
	
	/**
	 * Unbans a user account.
	 *
	 * @param $user object
	 * @return $user object | boolean
	 */
	public function unban_user(UserAccount $user){

		if($this->storage->unban_user($user['id'])){
			$user['banned'] = 0;
			return $user;
		}

		return false;
	
	}

}