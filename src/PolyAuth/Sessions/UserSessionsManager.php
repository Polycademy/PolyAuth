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

//for caching
use PolyAuth\Caching\CacheInterface;

//various exceptions
use PolyAuth\Exceptions\UserExceptions\UserPasswordChangeException;
use PolyAuth\Exceptions\UserExceptions\UserNotFoundException;
use PolyAuth\Exceptions\UserExceptions\UserBannedException;
use PolyAuth\Exceptions\ValidationExceptions\PasswordValidationException;
use PolyAuth\Exceptions\ValidationExceptions\DatabaseValidationException;

class UserSessionsManager{

	protected $strategies;
	protected $db;
	protected $options;
	protected $lang;
	protected $cache;
	protected $logger;
	protected $encryption;
	protected $accounts_manager;
	protected $session_manager;
	protected $session_segment;
	protected $cookies;
	protected $user;

	public function __construct(
		array $strategies,
		PDO $db, 
		Options $options, 
		Language $language, 
		CacheInterface $cache = null
		LoggerInterface $logger = null,
		AccountsManager $accounts_manager = null,
		SessionManager $session_manager = null,
		Cookies $cookies = null,
	){
		
		foreach($strategies as $strategy){
			if(!$strategy instanceof AuthStrategyInterface){
				throw new \InvalidArgumentException('Strategies must implement the AuthStrategyInterface');
			}
		}
		
		$this->strategies = $strategies;
		$this->db = $db;
		$this->options = $options;
		$this->lang = $language;
		$this->cache = $cache;
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
		
		//resolving session locking problems
		ob_start();
		register_shutdown_function(self::finish);
		
		//establishing namespaced segment (this will be our session data
		$this->session_segment = $this->session_manager->newSegment('PolyAuth\UserSession');
	
	}
	
	/**
	 * Start the tracking sessions. It will assign anonymous users an anonymous session, attempt autologin, detect whether passwords need to change, and expire long lived sessions.
	 * Wrap this call in a try catch block and redirect to change password page.
	 * Then redirect to password change page and then call AccountsManager::forgotten_complete()
	 *
	 * @throw Exception PasswordChangeException
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
		
		//this calls session_write_close(), it will close the session lock
		//it reduces the probability of concurrent ajax requests hanging
		$this->session_manager->commit();
	
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
	
		if(!$this->session_manager->isStarted()){
			$this->session_manager->start();
		}
		
		$user_id = false;
		//cycle through the auth strategies and check that at least one of them works
		foreach($this->auth_strategies as $strategy){
			if($user_id = $strategy->autologin()){
				//as soon as one of them works, break it
				break;
			}
		}
		
		//do note that if you are using OAuth or OpenId, this user_id may be created on the fly and immediately registered due to third party login
		if($user_id){
		
			$this->user = $this->accounts_manager->get_user($user_id);
			$this->update_last_login($this->user);
			$this->regenerate_session();
			$this->set_default_session($user_id, false);
			
			//final checks before we proceed (banned would logout the user)
			$this->check_banned($this->user);
			$this->check_password_change($this->user);
			
			return true;
		
		}else{
		
			return false;
		
		}
	
	}
	
	//THIS IS ALWAYS A MANUAL login (don't call this until you have the Oauth token)
	//in the case of Oauth, first do the redirect stuff (probably using $this->social_login()), on the redirect page, $this->exchange token, then call $this->login();
	public function login(array $data = null){
	
		if(!$this->session_manager->isStarted()){
			$this->session_manager->start();
		}
	
	
		//$data can be ['identity'] => 'username OR email',
		//['password'] => 'password' //<- optional
		
		//MANUAL first
		//then in the order of strategies (it will try each one of them until one of them works)
		//call the login_hook to return the $data and any morphs
		//then use the $data's identity and password to login
		//if in the case of Oauth, the $data would be null, then we'd pass null in, but the login_hook, so extract the OAuth token
		//then use the Oauth token to authenticate against the API and extract valuable data, fill the data with whatever and pass back
		//We would check the data's identity and password to match, if we detect ['oauth'] true, then these are registered or inserted...
	
		//automatically logout first, then login
		//if it detects that passwordChange is required (it will throw an exception)
		//if it detects that there is forgottenCode and stuff, it will run $accounts_manager->forgotten_clear
		
		//if this fails at any time, we'll do the whole login throttling.
		
		
		//also regenerate user session (refresh the ID), but use the "same" session to store the user variable
		//CREATE A SESSION! with the new user
		
		//set the session segment timeout to time()
		
		$this->user = $this->accounts_manager->get_user($user_id);
		$this->update_last_login($user);
		$this->regenerate_session();
		$this->set_default_session($user_id, false);
		$this->check_banned($user);
		$this->check_password_change($user);
		
	
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
		//close the handle
		$this->session_manager->commit();
	
	}
	
	//this will accept 3 optional parameters, if none are set, it simply checks if the person is logged in
	//if any are set, it's all or nothing, it will make sure that they are all true
	//to detect if one is logged in, one need to see if the UserAccount variable exists (can't rely on just sessions, possible sessionless)
	public function authenticated(array $permissions = null, array $roles = null, array $users = null){
	
		//$this->user (represents the currently logged in user). This obviously kept in "memory". Perhaps it's better to use PHP sessions?
		//OR you can use the Aura Sessions, which will be constructed for any particular user.
		//it's better to use the session data which would be an encoded version of the UserAccount
		//in fact we only need to check if session data exists (but serialisation and unserialisation works)
		
		//actually don't use sessions for this, this is because sessions relies on a cookies
		//instead simply check if $this->user is filled
		//$this->user will be filled, everytime the person auto logs in, and manually logs in.
		//For HTTP strategy, each request logs in. They constantly logs in.
		//For cookie strategy, autologin will fill it, but otherwise if they don't autologin..?
		
		//No this should use sessions to test whether someone is logged in.
		//If the client doesn't use cookies, sessions can be appended via the URL (most likely API usage)
		//If the client doesn't respect the URL session id, or that is switched off, it doesn't matter, because they will constantly login
		//on each request
		//Even with OAuth, it'd be the same
		
		//YOU HAVE TO BE WARY OF SESSION CONSIDERATIONS, FOR clients that dont' accept cookies
		//you can't use your own sessions to know if someone is authenticated or not
		//you'll have to authenticate each time, that is autologin needs to run, or login needs to run
		//if they run through, then the user IS authenticated
		//perhaps another hook is required...?
		//the problem is if, even if I autologin, because this obviously returned false due to lack of sessions, then subsequent requests to "authenticated" would fail, as there's nothing anchoring the user to be authenticated.
		//two solutions: use a $this->user memory variable that only exists for the script's session and assign it when autologgedin or loggedin and destroy on log out
		//or a hook on each authentication strategy that asks if the user is logged in or not
		//im choosing the first option, the latter results in too much code for the end user
		//this will first check the sessions, then it will check the $this->user variable
	
	}
	
	/**
	 * Gets the current user's session segment.
	 * The segment can be used to store extra data, remove data, unset or clear data.
	 */
	public function get_session(){
	
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
	
	}
	
	/**
	 * Sets up an anonymous or non-anonymous session.
	 * If no parameters are set it will set a anonymous session.
	 *
	 * @param $user_id integer | false
	 * @param $anonymous boolean
	 */
	protected function set_default_session($user_id = false, $anonymous = true){
	
		$this->session_segment->user_id = false;
		$this->session_segment->anonymous = true;
		$this->session_segment->timeout = time();
	
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
	
	//LOGIN ATTEMPTS STUFF
	
	public function update_last_login(UserAccount $user){
	
	}
	
	public function is_max_login_attempts_exceeded(){
	
	}
	
	public function get_last_attempt_time(){
	
	}
	
	public function get_attempts_num(){
	
	}
	
	public function is_time_locked_out(){
	
	}
	
	public function clear_login_attempts(){
	
	}
	
}