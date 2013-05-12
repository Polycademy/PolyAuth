<?php 

namespace PolyAuth\Sessions;

//for database
use PDO;
use PDOException;

//for logger
use Psr\Log\LoggerInterface;

//for options
use PolyAuth\Options;

//for languages
use PolyAuth\Language;

//for sessions
use PolyAuth\CookieManager;
use Aura\Session\Manager as SessionManager;
use Aura\Session\SegmentFactory;
use Aura\Session\CsrfTokenFactory;

//for handling accounts
use PolyAuth\UserAccount;
use PolyAuth\Accounts\AccountsManager;

//this class handles all the login and logout functionality
class LoginLogout{

	protected $auth_strategies;
	protected $db;
	protected $options;
	protected $lang;
	protected $logger;
	protected $session_manager;
	protected $accounts_manager;
	
	protected $user; //this is used to represent the user account for the RBAC, it is only initialised when a person logs in, it is not be used for any other purposes, always must represent the currently logged in user

	public function __construct(
		array $auth_strategies,
		PDO $db, 
		Options $options, 
		Language $language, 
		LoggerInterface $logger = null,
		AccountsManager $accounts_manager = null,
		CookieManager $cookie_manager = null,
		SessionManager $session_manager = null
	){
	
		$this->auth_strategies = $auth_strategies;
		$this->options = $options;
		$this->lang = $language;
		
		$this->db = $db;
		$this->logger = $logger;
		$this->cookie_manager = ($cookie_manager) ? $cookie_manager : new CookieManager(
			$this->options['cookie_domain'],
			$this->options['cookie_path'],
			$this->options['cookie_prefix'],
			$this->options['cookie_secure'],
			$this->options['cookie_httponly']
		);
		$this->session_manager = ($session_manager) ? $session_manager : new SessionManager(new SegmentFactory, new CsrfTokenFactory);
		$this->accounts_manager = ($accounts_manager) ? $accounts_manager : new AccountsManager($db, $options, $language, $logger);
		
		if($this->options['session_autostart']{
			$this->start();
		}
	
	}
	
	//remember to ask to change passwords if it detects a forgottenCode and forgottenTime and call the necessary method in accounts manager
	public function start(){
	
		//only two checks are necessary (whether they are logged in/authenticated, and whether autologin is switched on)
		//then it will proceed to go through the strategies
		//immediately logs the person in if they have identity, rememberCode and are not currently logged in
		if(!$this->authenticated() && $this->cookie_manager->get_cookie('identity') && $this->cookie_manager->get_cookie('rememberCode')){
			$this->autologin();
		}
		
		//... continue
		
		//if the person is logged in, we're going to check for forgottenCode and forgottenTime (actually can't do that)
		
	
	}
	
	//autologin strategy depends on what the auth strategy is
	//if it was HTTP, look into headers (or OAuth)
	//if it was cookies, look in to cookies
	protected function autologin(){
	
	}
	
	//THIS IS ALWAYS A MANUAL login
	public function login(){
	
		//automatically logout first, then login
	
	}
	
	public function logout(){
	
	}
	
	//this will accept 3 optional parameters, if none are set, it simply checks if the person is logged in
	//if any are set, it's all or nothing, it will make sure that they are all true
	//to detect if one is logged in, one need to see if the UserAccount variable exists (can't rely on just sessions, possible sessionless)
	public function authenticated(array $permissions = null, array $roles = null, array $users = null){
	
		//$this->user (represents the currently logged in user). This obviously kept in "memory". Perhaps it's better to use PHP sessions?
		//OR you can use the Aura Sessions, which will be constructed for any particular user.
		//it's better to use the session data which would be an encoded version of the UserAccount
		//in fact we only need to check if session data exists (but serialisation and unserialisation works)
	
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
	
	//use this function to determine if the user needs to change password?
	public function needs_to_change_password(){
	
	}
	
	//this is for cookie data and session storage
	//please note that the cookie data should not contain all of the user's data (only the necessary ones)
	//such as autologin key and current session (so they don't have to constantly login)
	//of course such would only exist if there were cookies
	//in the situation without cookies, this would only be used for the session storage on the server
	//to track the user on the client, we would have to use HTTP tokens (or in PHPBB, token strings)
	//also allow the ability to add flash data to that session
	//the cookie is only there to track who the user is (a session id), this will lead to data on the database being associated with it (that's it..), yea screw you RoyFielding!
	public function encrypt_session($data, $key){
	
		$data = serialize($data);
		return base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5($key), $data, MCRYPT_MODE_CBC, md5(md5($key))));

	}
	
	public function decrypt_session($data, $key){
	
		$data = rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5($key), base64_decode($data), MCRYPT_MODE_CBC, md5(md5($key))), "\0");
		return unserialize($data);
	
	}

}