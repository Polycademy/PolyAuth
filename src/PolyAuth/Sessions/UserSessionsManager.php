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

//for encrypting session data
use PolyAuth\Security\Encryption;

//for manipulating the user
use PolyAuth\UserAccount;
use PolyAuth\Accounts\AccountsManager;

//for cookie management
// use PolyAuth\Cookies;

//various exceptions
use PolyAuth\Exceptions\PasswordChangeException;
use PolyAuth\Exceptions\PasswordValidationException;
use PolyAuth\Exceptions\DatabaseValidationException;
use PolyAuth\Exceptions\UserNotFoundException;

//this class handles all the login and logout functionality
class UserSessionsManager{

	protected $strategies;
	protected $db;
	protected $options;
	protected $lang;
	protected $logger;
	protected $encryption;
	protected $accounts_manager;
	protected $session_manager;
	// protected $cookies;

	public function __construct(
		array $strategies,
		PDO $db, 
		Options $options, 
		Language $language, 
		LoggerInterface $logger = null,
		Encryption $encryption = null,
		// Cookies $cookies = null,
		AccountsManager $accounts_manager = null,
		SessionManager $session_manager = null
	){
	
		//output buffering is for SID bug https://bugs.php.net/bug.php?id=38104
		ob_start();
		register_shutdown_function(self::end);
		
		//this shouldn't happen should it!?
		foreach($strategies as $strategy){
			if(!$strategy instanceof AuthStrategyInterface){
				throw new \InvalidArgumentException('Strategies must implement the AuthStrategyInterface');
			}
		}
		
		$this->strategies = $strategies;
		$this->options = $options;
		$this->lang = $language;
		
		$this->db = $db;
		$this->logger = $logger;
		
		$this->encryption = ($encryption) ? $encryption : new Encryption;
		// $this->cookies = ($cookies) ? $cookies : new Cookies($options);
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
		
		//setting up cookie parameters for the session manager (which uses PHP sessions)
		//note that if you're using this for an API, and using HTTP authentication, sessions may be ignored by the client
		//the client will simply have to login in each time, based on RESTful style
		//this will still work, but you can't rely on a shopping cart in such a situation!
		$this->session_manager->setCookieParams(array(
			'lifetime'	=> $this->options['cookie_lifetime'],
			'path'		=> $this->options['cookie_path'],
			'domain'	=> $this->options['cookie_domain'],
			'secure'	=> $this->options['cookie_secure'],
			'httponly'	=> $this->options['cookie_httponly'],
		));
	
	}
	
	protected function end(){
		//extract the cookie headers, and replace it with one single SID header
		
		ob_get_clean();
	}
	
	/**
	 * Call this to begin tracking sessions, login details (cookies/HTTP tokens) and autologin.
	 * This will throw an exception called PasswordChangeException if it detects that the user needs to change password
	 * You would wrap this call in a try catch block and redirect to change password page.
	 * You should then redirect to acquiring the new password, and then call forgotten_complete in AccountsManager
	 */
	public function start(){
	
		//multiple possibilities:
		
		//FIRST: ANONYMOUS NO SESSION USER
			//Can go into SECOND (via just normal assignment)
			//Can go into THIRD (via autologin)
		//SECOND: ANONYMOUS SESSION USER
			//not possible for this to autologin... because the session has already been assigned
		//THIRD: LOGGED IN USER
			//IF password needs change, throw exception (don't logout, since you need know who the "person" is
	
	
		//this will be used for all sessions
		$segment = $this->session_manager->newSegment('PolyAuth-UserSession');
	
		//check if the person is not logged in, and that autologin was set to true
		if($this->options['login_autologin'] AND !$this->authenticated()){
			//this will make authenticated true if it worked, it will also create a session for the logged in user
			$this->autologin();
		}
		
		if($this->authenticated){
		
			//this means the session is "logged in"
			
			if($this->needs_to_change_password()){
				throw new PasswordChangeException($this->lang['password_change_required']);
			}
			
			//create a logged in session...
		
		}else{
		
			//this either the session is anonymous, or there are no sessions at all
			
			//if there are no sessions at all, we shall create an anonymous session
			if(!$this->session_manager->isAvailable){
			
				//assign anonymous an anonymous session
				$segment->anonymous = true;
				$segment->timeout = time();
			
			}
			
		
		}
		
		//time out long lived sessions (to log people if someone left their browser hanging on public computers)
		if(isset($segment->timeout) AND $this->options['session_expiration'] !== 0){
		
			$time_to_live = time() - $segment->timeout;
			if($time_to_live > $this->options['session_expiration']){
			
				//destroys the current session
				$params = $this->session_manager->getCookieParams();
				setcookie(
					$this->session_manager->getName(), 
					'', 
					time() - 86500, 
					$params["path"], 
					$params["domain"], 
					$params["secure"], 
					$params["httponly"]
				);
				$this->session_manager->destroy();
				
				//creates a new one anonymous session (lazy loading)
				$segment->anonymous = true;
				$segment->timeout = time();
			
			}
		
		}
		
		//this calls session_write_close(), it will close the ability to update the sessions
		//it reduces the probability of concurrent ajax requests hanging due to any session writes
		$this->session_manager->commit();
	
	}
	
	/**
	 * Checks if the user needs to change his current password.
	 *
	 * @return boolean
	 */
	public function needs_to_change_password(){
	
		//will return a UserAccount!
		$user = $this->get_user_session();
		
		if($user['passwordChange'] === 1){
			return true;
		}else{
			return false;
		}
	
	}
	
	/**
	 *
	 *
	 */
	protected function autologin(){
	
		//requires identity and autoCode
		//will call $this->login, once the details are set
		//actually why not just the id and autoCode? (also autoCode should be encrypted!), the autoCode is equivalent to a password
		//encrypted autoCode and id of the user (not username)
		//one single encrypted autologin cookie -> serialized array. Store the identity and autoCode. But we need be able to specify which strategy to use...?
		
		//if autologin failed, then do not go to login, or else it may increment login attempts
		
		//CREATE A NEW SESSION with the new user session
	
	}
	

	
	//THIS IS ALWAYS A MANUAL login (don't call this until you have the Oauth token)
	//in the case of Oauth, first do the redirect stuff (probably using $this->social_login()), on the redirect page, $this->exchange token, then call $this->login();
	public function login(array $data = null){
	
		//login will destroy the old session, and create a new one (can't use regenerate ID), because the session itself is gone!
		$this->session_manager->start(); //this will reopen the session, however we're going to get some errors
	
	
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
	
	}
	
	public function logout(){
	
		//call regenerate user session
		//create a new anonymous session
	
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
	
	//saves a new user for this session
	public function save_user_session(UserAccount $user){
	
		$user = $this->encryption->encrypt($user, $this->options['security_key']);
		
		//continue to save this encrypted $user into the session now...

	
	}
	
	//get current client session data
	//this is the server side session, not the cookie data...
	//use this to store temporary information about the user, such as shopping carts... etc
	//three places to modify user data
	//$user for serverside to database ORM
	//user session (tmp) or database session depending on interface (this stuff is a serialised version of $user, but can have other things in it, this doesn't need to map to the database)
	public function get_user_session(UserAccount $user){
	
		//this can work for anonymous sessions too!
		
	
	}
	
	//modify client session data
	//use this for shopping carts or temporary user data
	//this will not save the data to the database!
	//it is not for updating the user's account
	public function update_user_session(){
	
		//decrypt session
		//modify/update it as an array
		//encrypt it again
	
	}
	
	/**
	 * Regenerate the user's session. Destroys current session, and creates one again with different ID.
	 * Use this when:
	 * 1. the role or permissions of the current user was changed programmatically.
	 * 2. the user updates their profile
	 * 3. the user logs in or logs out (to prevent session fixation) -> (done automatically)
	 */
	public function regenerate_user_session(){
	
		//this needs to cater to AJAX, it has the problem of concurrent requests...
		//actually this may not be a problem, this is only called on log in or log out, autologin only happens if the session has expired
		
		//delete the old session
	
		$this->session_manager->regenerateId();
		$_SESSION = array();
	
	}
	
}