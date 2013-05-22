<?php 

namespace PolyAuth\Sessions;

use PDO;
use PDOException;
use Psr\Log\LoggerInterface;

use Aura\Session\Manager as SessionManager;
use Aura\Session\SegmentFactory;
use Aura\Session\CsrfTokenFactory;
use Aura\Session\Randval;
use Aura\Session\Phpfunc;

use PolyAuth\Options;
use PolyAuth\Language;

//for making sure auth strategies are real strategies
use PolyAuth\AuthStrategies\AuthStrategyInterface;

//for manipulating the user
use PolyAuth\UserAccount;
use PolyAuth\Accounts\AccountsManager;

//for manipulating cookies
use PolyAuth\Cookies;

//various exceptions
use PolyAuth\Exceptions\UserExceptions\UserPasswordChangeException;
use PolyAuth\Exceptions\UserExceptions\UserNotFoundException;
use PolyAuth\Exceptions\UserExceptions\UserBannedException;
use PolyAuth\Exceptions\UserExceptions\UserInactiveException;
use PolyAuth\Exceptions\ValidationExceptions\PasswordValidationException;
use PolyAuth\Exceptions\ValidationExceptions\DatabaseValidationException;
use PolyAuth\Exceptions\ValidationExceptions\LoginValidationException;
use PolyAuth\Exceptions\ValidationExceptions\SessionValidationException;

class UserSessionsManager{

	protected $strategy;
	protected $db;
	protected $options;
	protected $lang;
	protected $logger;
	protected $encryption;
	protected $accounts_manager;
	protected $session_manager;
	protected $session_segment;
	protected $cookies;
	protected $user;

	public function __construct(
		AuthStrategyInterface $strategy,
		PDO $db, 
		Options $options, 
		Language $language, 
		LoggerInterface $logger = null,
		AccountsManager $accounts_manager = null,
		SessionManager $session_manager = null,
		Cookies $cookies = null,
	){
		
		$this->strategy = $strategy;
		$this->db = $db;
		$this->options = $options;
		$this->lang = $language;
		$this->logger = $logger;
		$this->accounts_manager = ($accounts_manager) ? $accounts_manager : new AccountsManager($db, $options, $language, $logger);
		if($session_manager){
			$this->session_manager = $session_manager;
		}else{
			$this->session_manager = new SessionManager(
				new SegmentFactory,
				new CsrfTokenFactory(
					new Randval(
						new Phpfunc
					)
				),
				$_COOKIE
			);
		}
		$this->cookies = ($cookies) ? $cookies : new Cookies($options);
		
		//resolving session locking problems and other HTTP header problems
		ob_start();
		register_shutdown_function(self::finish);
		
		//establishing namespaced segment (this will be our session data
		$this->session_segment = $this->session_manager->newSegment('PolyAuth\UserSession');
	
	}
	
	/**
	 * Start the tracking sessions.
	 * It will assign anonymous users an anonymous session, attempt autologin, detect banned users, detect whether passwords need to change, and expire long lived sessions.
	 * Wrap this call in a try catch block and handle any exceptions.
	 */
	public function start(){
		
		//starting the session if it hasn't been started yet
		if(!$this->session_manager->isStarted()){
			$this->session_manager->start();
		}
		
		//if the user is not logged in, we're going to reset an anonymous session and attempt autologin
		if(!$this->authenticated()){
		
			//beware that this means an anonymous session will never time out
			$this->set_default_session();
			
			if($this->options['login_autologin']){
				$this->autologin();
			}
		
		}else{
		
			$this->user = $this->accounts_manager->get_user($this->session_segment->user_id);
		
		}
		
		//time out long lived logged in sessions
		if($this->options['session_expiration'] !== 0 AND is_int($this->session_segment->timeout)){
			$time_to_live = time() - $this->session_segment->timeout;
			if($time_to_live > $this->options['session_expiration']){
				$this->logout();
			}
		}
	
	}
	
	/**
	 * Finish will intercept the cookies in the headers before they are sent out.
	 * It will make sure that only one SID cookie is sent.
	 * It will also preserve any cookie headers prior to this library being used.
	 */
	protected function finish(){
	
		if(SID){
			$headers =  array_unique(headers_list());   
			$cookie_strings = array();
			foreach($headers as $header){
				if(preg_match('/^Set-Cookie: (.+)/', $header, $matches)){
					$cookie_strings[] = $matches[1];
				}
			}
			header_remove('Set-Cookie');
			foreach($cookie_strings as $cookie){
				header('Set-Cookie: ' . $cookie, false);
			}
		}
		ob_flush();
		
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
			$this->update_last_login($this->user);
			$this->regenerate_session();
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
	 *
	 * @param $data array optional
	 * @return boolean
	 */
	public function login(array $data = null){
	
		if(!$this->session_manager->isStarted()){
			$this->session_manager->start();
		}
		
		//these are based on the current session or ip
		$this->is_locked_out();
		$this->check_login_attempts_exceeded();
		$this->increment_login_attempts();
		
		//the login hook will manipulate the passed in $data and return at least 'identity' and 'password'
		//in the case of Oauth, the identity and password may be created on the fly, as soon as the third party authenticates
		$data = $this->strategy->login_hook($data);
		
		if(!is_array($data) OR (!isset($data['identity']) OR !isset($data['password']))){
			throw new LoginValidationException($this->lang['login_unsuccessful']);
		}
		
		$query = "SELECT id, password FROM {$this->options['table_users']} WHERE {$this->options['login_identity']} = :identity";
		$sth = $this->db->prepare($query);
		$sth->bindValue('identity', $data['identity'], PDO::PARAM_STR);
		
		try{
		
			$sth->execute();
			if($row = $sth->fetch(PDO::FETCH_OBJ)){
			
				if(password_verify($data['password'], $row->password)){
				
					//identity is valid, and password has been verified
					$user_id = $row->id;
					
				}else{
				
					throw new LoginValidationException($this->lang['login_password']);
				
				}
				
			}else{
			
				throw new LoginValidationException($this->lang['login_identity']);
				
			}
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to login.", ['exception' => $db_err]);
			}
			throw $db_err;
		
		}
		
		$this->user = $this->accounts_manager->get_user($user_id);
		$this->clear_login_attempts($this->user);
		$this->update_last_login($this->user);
		
		$this->regenerate_session();
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
	
	/**
	 * Logout, this will destroy all the previous session data and recreate an anonymous session.
	 * It is possible to call this without calling $this->start().
	 * It will also delete the session cookie and autologin cookie.
	 * It will clear the $this->user variable
	 */
	public function logout(){
		
		if(!$this->session_manager->isStarted()){
			$this->session_manager->start();
		}
		
		//perform any custom authentication functions
		$this->strategy->logout_hook();
		
		//delete the php session cookie and autologin cookie
		$this->cookies->delete_cookie($this->session_manager->getName());
		$this->cookies->delete_cookie('autologin');
		
		//this calls session_destroy() and session_unset()
		$this->session_manager->destroy();
		//clears the current user
		$this->user = null;
		
		//start a new session
		$this->session_manager->start();
		//clear the segment
		$this->session_segment->clear();
		//setup the the anonymous session
		$this->set_default_session();
	
	}
	
	/**
	 * Checks if the user is logged in and possesses all the passed in parameters.
	 * The parameters operate on all or nothing except $identities. $identities operates like "has to be at least one of them".
	 * This first checks if the session exists, and if not checks if the user exists in this script's memory.
	 * 
	 * @param $permissions array of permission names | null
	 * @param $roles array of role names | null
	 * @param $identities array of user identities | null (this must match your login_identity option)
	 * @return boolean
	 */
	public function authenticated(array $permissions = null, array $roles = null, array $identities = null){
	
		if(!$this->session_manager->isStarted()){
			$this->session_manager->start();
		}
		
		//if the session and $this->user don't exist, then the user is not logged in
		//if one of them exists, then there's a chance that the session is logged in does exist!
		if(empty($this->session_segment->user_id) AND $this->session_segment->user_id !== 0){
			if(!$this->user instanceof UserAccount OR empty($this->user['id'])){
				return false;
			}else{
				$user_id = $this->user['id'];
			}
		}else{
			$user_id = $this->session_segment->user_id;
		}
		
		//check if the user id actually exists (this may be redundant, but better safe than sorry)
		$query = "SELECT id, {$this->options['login_identity']} FROM {$this->options['table_users']} WHERE id = :user_id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('user_id', $user_id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			$row = $sth->fetch(PDO::FETCH_OBJ);
			
			//does the id exist?
			if(!$row){
				return false;
			}
			
			//identity check
			if($identities AND !in_array($row->identity, $identities)){
				return false;
			}
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to check if the user identity exists.", ['exception' => $db_err]);
			}
			throw $db_err;
		
		}
		
		//reset the user variable if it does not exist, this is possible if the developer not use $this->start()
		if(!$this->user instanceof UserAccount OR empty($this->user['id'])){
			$this->user = $this->accounts_manager->get_user($user_id);
		}
		
		if($permissions){
		
			//check if the user has all the permissions
			foreach($permissions as $permission_name){
				if(!$this->user->has_permission($permission_name){
					return false;
				}
			}
		
		}
		
		if($roles){
		
			//check if the user has all the roles
			foreach($roles as $role_name){
				if(!$this->user->has_role($role_name){
					return false;
				}
			}
		
		}
		
		return true;
	
	}
	
	/**
	 * Gets the currently logged in user's user account
	 * The reason why it calls accounts manager rather than just returning the user here, is that the user here does not reflect any changes made the user in the accounts manager.
	 * Which would make $this->user quite stale.
	 */
	public function get_user(){
	
		return $this->accounts_manager->get_user($this->user['id']);
	
	}
	
	/**
	 * Gets the current user's session segment.
	 * The session segment will be read only. Use update_session to add extra properties to the session.
	 *
	 * @return $this->session_segment object
	 */
	public function get_session(){
	
		if(!$this->session_manager->isStarted()){
			$this->session_manager->start();
		}
		
		$this->session_manager->commit();
		
		//this will not be writable!
		return $this->session_segment;
	
	}
	
	/**
	 * Updates the session with custom properties.
	 * You cannot use reserved keys such as 'user_id', 'anonymous' or 'timeout'
	 *
	 * @return $this->session_segment object
	 */
	public function update_session_property($key, $value){
		
		if($key == 'user_id' OR $key == 'anonymous' OR $key == 'timeout'){
			throw new SessionValidationException($this->lang['session_invalid_key']);
		}
		
		if(!$this->session_manager->isStarted()){
			$this->session_manager->start();
		}
		
		$this->session_segment->{$key} = $value;
		
		$this->session_manager->commit();
		
		return $this->session_segment;
	
	}
	
	/**
	 * Delete custom properties on the session.
	 * You cannot use reserved keys such as 'user_id', 'anonymous' or 'timeout'
	 *
	 * @return $this->session_segment object
	 */
	public function delete_session_property($key){
	
		if($key == 'user_id' OR $key == 'anonymous' OR $key == 'timeout'){
			throw new SessionValidationException($this->lang['session_invalid_key']);
		}
		
		if(!$this->session_manager->isStarted()){
			$this->session_manager->start();
		}
		
		unset($this->session_segment->{$key});
		
		$this->session_manager->commit();
		
		return $this->session_segment;
	
	}
	
	/**
	 * Regenerate the user's session id. Can be used without calling $this->start()
	 * Use this when:
	 * 1. the role or permissions of the current user was changed programmatically.
	 * 2. the user updates their profile
	 * 3. the user logs in or logs out (to prevent session fixation) -> (done automatically)
	 */
	public function regenerate_session(){
	
		if(!$this->session_manager->isStarted()){
			$this->session_manager->start();
		}
		
		$this->session_manager->regenerateId();
		$this->session_manager->commit();
	
	}
	
	/**
	 * Sets up an anonymous or non-anonymous session.
	 * If no parameters are set it will set a anonymous session.
	 *
	 * @param $user_id integer | false
	 * @param $anonymous boolean
	 */
	protected function set_default_session($user_id = false, $anonymous = true){
	
		if(!$this->session_manager->isStarted()){
			$this->session_manager->start();
		}
	
		$this->session_segment->user_id = false;
		$this->session_segment->anonymous = true;
		$this->session_segment->timeout = time();
		
		//this calls session_write_close(), it will close the session lock
		$this->session_manager->commit();
	
	}
	
	/**
	 * Checks if a user is inactive. This will log the user out if so before throwing an exception.
	 *
	 * @param $user UserAccount
	 * @throw Exception UserInactiveException
	 */
	protected check_inactive(UserAccount $user){
	
		if($user['active'] === 0){
			$this->logout();
			throw new UserInactiveException($this->lang['user_inactive']);
		}
	
	}
	
	/**
	 * Checks if a user is banned. This will log the user out if so before throwing an exception.
	 *
	 * @param $user UserAccount
	 * @throw Exception UserBannedException
	 */
	protected function check_banned(UserAccount $user){
	
		if($user['banned'] === 1){
			$this->logout();
			throw new UserBannedException($this->lang['user_banned']);
		}
	
	}
	
	/**
	 * Checks if a user needs to change his current password.
	 *
	 * @param $user UserAccount
	 * @throw Exception PasswordChangeException
	 */
	protected function check_password_change(UserAccount $user){
		
		if($user['passwordChange'] === 1){
			throw new UserPasswordChangeException($this->lang['password_change_required']);
		}
		
	}
	
	/**
	 * Checks if the current session is locked out due to attempts exceeding
	 */
	protected function is_locked_out(){
	
	}
	
	/**
	 * Increment the number of login attempts, this could work via sessions, ip or username
	 * Sessions are probably the least useful, but the other two can result in DOS or inconvenience
	 */
	protected function increment_login_attempts(){
	
	}
	
	/**
	 * Check if the attempts have exceeded, if so set up a lock out time
	 */
	protected function check_login_attempts_exceeded(){
	
	}
	
	/**
	 * Clear all the login attempts on successful login
	 */
	public function clear_login_attempts(UserAccount $user){
	
	}
	
	/**
	 * Update the last login time
	 */
	public function update_last_login(UserAccount $user){
	
	}
	
}