<?php 

namespace PolyAuth\Sessions;

use Psr\Log\LoggerInterface;
use Psr\Log\LoggerAwareInterface;

use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\Storage\StorageInterface;

use PolyAuth\AuthStrategies\AuthStrategyInterface;

use PolyAuth\UserAccount;
use PolyAuth\Accounts\AccountsManager;
use PolyAuth\Accounts\Rbac;

use PolyAuth\Cookies;
use PolyAuth\Sessions\SessionZone;
use PolyAuth\Sessions\LoginAttempts;

use PolyAuth\Exceptions\UserExceptions\UserPasswordChangeException;
use PolyAuth\Exceptions\UserExceptions\UserNotFoundException;
use PolyAuth\Exceptions\UserExceptions\UserBannedException;
use PolyAuth\Exceptions\UserExceptions\UserInactiveException;
use PolyAuth\Exceptions\ValidationExceptions\StrategyValidationException;
use PolyAuth\Exceptions\ValidationExceptions\PasswordValidationException;
use PolyAuth\Exceptions\ValidationExceptions\DatabaseValidationException;
use PolyAuth\Exceptions\ValidationExceptions\LoginValidationException;
use PolyAuth\Exceptions\ValidationExceptions\SessionValidationException;

class UserSessions implements LoggerAwareInterface{

	protected $strategies;
	protected $storage;
	protected $options;
	protected $lang;
	protected $logger;
	protected $encryption;
	protected $accounts_manager;
	protected $rbac;
	protected $session_zone;
	protected $cookies;
	protected $login_attempts;
	protected $user;

	public function __construct(
		$strategies, 
		StorageInterface $storage, 
		Options $options, 
		Language $language, 
		LoggerInterface $logger = null, 
		AccountsManager $accounts_manager = null, 
		Rbac $rbac = null,
		SessionZone $session_zone = null, 
		Cookies $cookies = null,
		LoginAttempts $login_attempts = null
	){

		//convert $strategies into an array
		if(!is_array($strategies)){
			$strategies = array($strategies);
		}

		foreach($strategies as $strategy){
			if(!$strategy instanceof AuthStrategyInterface){
				throw StrategyValidationException('Authentication strategies need to implement AuthStrategyInterface.');
			}
		}

		$this->strategies = $strategies;
		$this->storage = $storage;
		$this->options = $options;
		$this->lang = $language;
		$this->logger = $logger;
		$this->accounts_manager = ($accounts_manager) ? $accounts_manager : new AccountsManager($storage, $options, $language, $logger);
		$this->rbac = ($rbac) ? $rbac : new Rbac($storage, $language, $logger);
		$this->session_zone = ($session_zone) ? $session_zone : new SessionZone($options);
		$this->cookies = ($cookies) ? $cookies : new Cookies($options);
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
	 * Start the tracking sessions. You should only call this once. However multiple calls to this function
	 * is idempotent.
	 * It will:
	 * 		assign anonymous users an anonymous session, 
	 *   	attempt autologin, 
	 *    	detect inactive users, -> exception and logged out
	 *     	detect banned users, -> exception and logged out
	 *      detect whether passwords need to change, -> exception 
	 *      and expire long lived sessions. -> logged out
	 * Wrap this call in a try catch block and handle any exceptions.
	 * The exceptions stem from autologin conditions, such as banned.
	 */
	public function start(){

		//if the user property is filled, this means start has already been called
		//if it has been called, we don't want to do anything here as it can cause a conflict
		//or overwrite sessions
		if(!empty($this->user)){
			return;
		}

		//this starts the session to allow variables to be read from the session
		$this->session_zone->start_session();

			//if the user is not logged in, we're going to reset an anonymous session and attempt autologin
			if(!$this->authorized()){

				//beware that this means an anonymous session will never time out
				$this->set_default_session();
				
				if($this->options['login_autologin']){
					$this->autologin();
				}
			
			}else{
				
				$this->user = $this->accounts_manager->get_user($this->session_zone['user_id']);
			
			}


		//time out long lived logged in sessions
		if($this->options['session_expiration'] AND is_numeric($this->session_zone['timeout'])){
			$time_to_live = time() - $this->session_zone['timeout'];
			if($time_to_live > $this->options['session_expiration']){
				$this->logout();
			}
		}

		$this->session_zone->commit_session();
	
	}
	
	/**
	 * Autologin cycles through all of the authentication strategies to check if at least one of the autologins worked.
	 * As soon as one of them works, it breaks the loop, and then updates the last login, and sets the session parameters.
	 * The user_id gets set the passed back user id. The anonymous becomes false, and the timeout is refreshed.
	 * This checks for password change and banned status and will throw appropriate exceptions.
	 * It will assign the user account to the $this->user variable.
	 *
	 * @return boolean
	 */
	protected function autologin(){
		
		$user_id = $this->strategy->autologin();
		
		if($user_id){
		
			$this->user = $this->accounts_manager->get_user($user_id);
			$this->storage->update_last_login($this->user['id'], $this->get_ip());
			$this->session_zone->regenerate();
			$this->set_default_session($user_id, false);
			
			//final checks before we proceed (inactive or banned would logout the user)
			$this->check_inactive($this->user);
			$this->check_banned($this->user);
			$this->check_password_change($this->user);
			
			return true;
		
		}else{
		
			return false;
		
		}
	
	}

	/**
	 * Manually logs in the user, given a $data array of input parameters.
	 * The input parameter can be an array of ['identity'] (string) AND ['password'] (string) AND ['autologin'] (boolean)
	 * However it is also optional, if you are using Oauth or HTTP auth.
	 * In that case, it will automatically extract the necessary tokens.
	 * If you wish to bypass the login throttling, just pass in $force_login as true.
	 * You should use $force_login in conjunction with a captcha form to allow real users to bypass.
	 * After all login throttling is meant to be used against bots. Not real users.
	 * Beware of forgotten password or identity, when a user completes the cycle, they should still be able to login
	 *
	 * @param $data array optional
	 * @param $force_login boolean
	 * @return boolean
	 */
	public function login(array $data = null, $force_login = false){
		
		//the login hook will manipulate the passed in $data and return at least 'identity' and 'password'
		//in the case of Oauth, the identity and password may be created on the fly, as soon as the third party authenticates
		$data = $this->strategy->login_hook($data);
		
		if(!is_array($data) OR !isset($data['identity']) OR !isset($data['password'])){
			$this->login_failure($data, $this->lang['login_unsuccessful']);
		}
		
		if(!$force_login AND !empty($this->options['login_lockout'])){
			//is the current login attempt locked out?
			$lockout_time = $this->login_attempts->locked_out($data['identity']);
			//if the lockout_time is true, non-zero integer
			if($lockout_time){
				$this->login_failure($data, sprintf($this->lang['login_lockout'], $lockout_time));
			}
		}

		$row = $this->storage->get_login_check($data['identity']);

		if($row){

			if(password_verify($data['password'], $row->password)){
			
				//identity is valid, and password has been verified
				$user_id = $row->id;
				
			}else{
			
				//this is only attempt that is considered a real failed login attempt
				//the third parameter is true in order to implement login throttling
				$this->login_failure($data, $this->lang['login_password'], true);
			
			}

		}else{

			$this->login_failure($data, $this->lang['login_identity']);

		}
		
		$this->user = $this->accounts_manager->get_user($user_id);
		if(!empty($this->options['login_lockout'])){
			$this->login_attempts->clear($this->user[$this->options['login_identity']]);
		}
		$this->storage->update_last_login($this->user['id'], $this->get_ip());
		
		$this->session_zone->regenerate();
		$this->set_default_session($user_id, false);
		
		$this->check_inactive($this->user);
		$this->check_banned($this->user);
		$this->check_password_change($this->user);
		
		//if it has passed everything, we're going to call set_autologin to setup persistent login if autologin is boolean true
		if(!empty($data['autologin']) AND $this->options['login_autologin']){
			$this->strategy->set_autologin($user_id);
		}
		
		return true;
	
	}

	public function external_login($identity){

		$row = $this->storage->get_login_check($identity);
		$user_id = $row->id;
		
		$this->user = $this->accounts_manager->get_user($user_id);

		if(!empty($this->options['login_lockout'])){
			$this->login_attempts->clear($this->user[$this->options['login_identity']]);
		}
		$this->storage->update_last_login($this->user['id'], $this->get_ip());
		
		$this->session_zone->regenerate();
		$this->set_default_session($user_id, false);
		
		$this->check_inactive($this->user);
		$this->check_banned($this->user);
		
		return true;
	
	}
	
	/**
	 * Login failure should be called when the login did not succeed. This throws the LoginValidationException.
	 * However it also increments the login attempts and calls the logout hook.
	 * You can pass the third parameter to prevent it from incrementing the login attempts.
	 * The third parameter should be true when the attempt is a real login attempt.
	 * The only attempt that should be throttled is ones where the attempt
	 * was one with a real identity but the wrong password. Other attempts will not be considered.
	 *
	 * @param $data anything
	 * @param $message string
	 * @param $throttle boolean
	 * @throw Exception LoginValidationException
	 */
	protected function login_failure($data, $message, $throttle = false){
	
		$exception = new LoginValidationException($message);
		
		//if the identity does not exist, there's no point throttling, even on ip addresses
		//this would be the equivalent of an attacker trying to login with no username/email
		//or it could just be a user that forgot to enter the username
		//at any case, it's not a threat
		if(!empty($data['identity']) AND $throttle AND !empty($this->options['login_lockout'])){
			$this->login_attempts->increment($data['identity']);
		}
		
		//everytime the user fails to login, we log him out completely, this could have ramifications if users login after they are already logged in
		$this->logout();
		
		throw $exception;
	
	}
	
	/**
	 * Logout, this will destroy all the previous session data and recreate an anonymous session.
	 * It is possible to call this without calling $this->start().
	 * It will also delete the session cookie and autologin cookie.
	 * It will clear the $this->user variable
	 */
	public function logout(){
		
		//perform any custom authentication functions
		$this->strategy->logout_hook();
		
		//delete the php session cookie and autologin cookie
		$this->cookies->delete_cookie($this->session_zone->get_name());
		$this->cookies->delete_cookie('autologin');
		
		//this calls session_destroy() and session_unset()
		$this->session_zone->destroy();
		//clears the current user
		$this->user = null;
		
		//start a new session anonymous session
		$this->set_default_session();
	
	}
	
	/**
	 * Checks if the user is logged in and possesses all the passed in parameters.
	 * The parameters operate on all or nothing except $identities and $id. $identities and $id operates like "has to be at least one of them".
	 * This first checks if the session exists, and if not checks if the user exists in this script's memory.
	 * 
	 * @param $permissions array of permission names | string | false
	 * @param $roles array of role names | string | false
	 * @param $identities array of user identities | string | false (this must match your login_identity option)
	 * @param $ids array of user ids | integer | false
	 * @return boolean
	 */
	public function authorized($permissions = false, $roles = false, $identities = false, $ids = false){
	
		$this->session_zone->start_session();
		
		$permissions = ($permissions) ? (array) $permissions : false;
		$roles = ($roles) ? (array) $roles : false;
		$identities = ($identities) ? (array) $identities : false;
		$ids = ($ids) ? (array) $ids : false;

		//if the session and $this->user don't exist, then the user is not logged in
		//if one of them exists, then there's a chance that the session data got lost in a single instance of the script
		//also compensates for if the user id is actually a zero
		if(empty($this->session_zone['user_id']) AND $this->session_zone['user_id'] !== 0){
			if(!$this->user instanceof UserAccount OR empty($this->user['id'])){
				return false;
			}else{
				$user_id = $this->user['id'];
			}
		}else{
			$user_id = $this->session_zone['user_id'];
		}

		//we finished reading from the session, commit it!
		$this->session_zone->commit_session();
		
		//check if the user id actually exists (this may be redundant, but better safe than sorry)
		$row = $this->storage->get_user($user_id);

		//does the id exist?
		if(!$row){
			return false;
		}
		
		//id check
		if($ids AND !in_array($user_id, $ids)){
			return false;
		}

		//identity check
		if($identities AND !in_array($row->{$this->options['login_identity']}, $identities)){
			return false;
		}
		
		//reset the user variable if it does not exist, this is possible if the developer not use $this->start()
		if(!$this->user instanceof UserAccount OR empty($this->user['id'])){
			$this->user = $this->accounts_manager->get_user($user_id);
		}
		
		if($permissions){
		
			//check if the user has all the permissions
			foreach($permissions as $permission_name){
				if(!$this->user->has_permission($permission_name)){
					return false;
				}
			}
		
		}
		
		if($roles){
		
			//we need to acquire role objects first because has_role only accepts objects, not strings
			$role_objects = $this->rbac->get_roles($roles);

			foreach($role_objects as $role_object){

				if(!$this->user->has_role($role_object)){
					return false;
				}
			}
		
		}
		
		return true;
	
	}
	
	/**
	 * Gets the currently logged in user's user account
	 * It calls accounts manager rather than just returning the user here because
	 * the user here is not as up to date as the one from the database.
	 * @return object|null gives back null if anonymous, otherwise an UserAccount object
	 */
	public function get_user(){
	
		//if the user is not filled, this means it's an anonymous user (thus a "null" user)
		if(empty($this->user)){
			return null;
		}

		return $this->accounts_manager->get_user($this->user['id']);
	
	}
	
	/**
	 * Gets the current session manager if you want granular control.
	 * @return $this->session_zone object
	 */
	public function get_session_zone(){
		
		return $this->session_zone;
	
	}

	/**
	 * Gets all the properties that are in the session
	 * @return mixed
	 */
	public function get_properties(){

		$this->session_zone->start_session();
		$value = $this->session_zone->get_all();
		$this->session_zone->commit_session();
		return $value;

	}

	/**
	 * Clears all the properties except the reserved ones
	 */
	public function clear_properties(){

		$this->session_zone->start_session();
		$this->session_zone->clear_all(array('user_id', 'anonymous', 'timeout'));
		$this->session_zone->commit_session();

	}

	/**
	 * Gets a session property. Flash data is deleted after it is read once.
	 * @param  string  $key		identifier of the session data
	 * @param  boolean $flash	whether it's a flash data or not
	 * @return mixed			session data
	 */
	public function get_property($key, $flash = false){

		$this->session_zone->start_session();

		if($flash){
			$value = $this->session_zone->get_flash($key);
		}else{
			$value = $this->session_zone[$key];
		}

		$this->session_zone->commit_session();

		return $value;

	}
	
	/**
	 * Updates/inserts the session with custom properties.
	 * You cannot use reserved keys such as 'user_id', 'anonymous' or 'timeout'
	 * You cannot use custom session data unless you are using cookie based authentication.
	 * Otherwise each request is unique and stateless.
	 *
	 * @param boolean $flash sets a read-once value
	 */
	public function set_property($key, $value, $flash = false){
		
		if($key == 'user_id' OR $key == 'anonymous' OR $key == 'timeout'){
			throw new SessionValidationException($this->lang['session_invalid_key']);
		}

		$this->session_zone->start_session();

		if($flash){
			$this->session_zone->set_flash($key, $value);
		}else{
			$this->session_zone[$key] = $value;
		}
		
		$this->session_zone->commit_session();
	
	}
	
	/**
	 * Delete custom properties on the session.
	 * You cannot use reserved keys such as 'user_id', 'anonymous' or 'timeout'
	 */
	public function delete_property($key, $flash = false){
	
		if($key == 'user_id' OR $key == 'anonymous' OR $key == 'timeout'){
			throw new SessionValidationException($this->lang['session_invalid_key']);
		}
		
		$this->session_zone->start_session();
		
		if($flash){
			$this->session_zone->get_flash($key);
		}else{
			unset($this->session_zone[$key]);
		}
		
		$this->session_zone->commit_session();
	
	}

	/**
	 * Does the session have a particular property? Useful mainly for flash values so you don't lose it.
	 * @param  string  $key   Name of the value
	 * @return boolean
	 */
	public function has_flash_property($key){

		$this->session_zone->start_session();

		$value = $this->session_zone->has_flash($key);

		$this->session_zone->commit_session();

		return $value;

	}
	
	/**
	 * Sets up an anonymous or non-anonymous session.
	 * If no parameters are set it will set a anonymous session.
	 *
	 * @param $user_id integer | false
	 * @param $anonymous boolean
	 */
	protected function set_default_session($user_id = false, $anonymous = true){
	
		$this->session_zone->start_session();
		$this->session_zone['user_id'] = $user_id;
		$this->session_zone['anonymous'] = $anonymous;
		$this->session_zone['timeout'] = time();
		$this->session_zone->commit_session();
	
	}
	
	/**
	 * Checks if a user is inactive. This will log the user out if so before throwing an exception.
	 *
	 * @param $user UserAccount
	 * @throw Exception UserInactiveException
	 */
	protected function check_inactive(UserAccount $user){
	
		if($user['active'] == 0){

			$this->login_failure(false, $this->lang['user_inactive']);

		}
	
	}
	
	/**
	 * Checks if a user is banned. This will log the user out if so before throwing an exception.
	 *
	 * @param $user UserAccount
	 * @throw Exception UserBannedException
	 */
	protected function check_banned(UserAccount $user){
	
		if($user['banned'] == 1){
			$this->login_failure(false, $this->lang['user_banned']);
		}
	
	}
	
	/**
	 * Checks if a user needs to change his current password.
	 *
	 * @param $user UserAccount
	 * @throw Exception PasswordChangeException
	 */
	protected function check_password_change(UserAccount $user){
		
		if($user['passwordChange'] == 1){
			throw new UserPasswordChangeException($this->lang['password_change_required']);
		}
		
	}

	/**
	 * Helper function to get the ip and format it correctly for insertion.
	 *
	 * @return $ip_address binary | string
	 */
	protected function get_ip() {
	
		$ip_address = (!empty($_SERVER['REMOTE_ADDR'])) ? $_SERVER['REMOTE_ADDR'] : '127.0.0.1';
		return inet_pton($ip_address);
		
	}
	
}