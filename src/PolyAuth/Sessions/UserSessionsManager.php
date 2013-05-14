<?php 

namespace PolyAuth\Sessions;

use PDO;
use PDOException;
use Psr\Log\LoggerInterface;

use Aura\Session\Manager as SessionManager;
use Aura\Session\SegmentFactory;
use Aura\Session\CsrfTokenFactory;

use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\UserAccount;
use PolyAuth\Accounts\AccountsManager;

//this class handles all the login and logout functionality
class UserSessionsManager{

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
		$this->cookie_manager = ($cookie_manager) ? $cookie_manager : new CookieManager($options);
		$this->session_manager = ($session_manager) ? $session_manager : new SessionManager(new SegmentFactory, new CsrfTokenFactory);
		$this->accounts_manager = ($accounts_manager) ? $accounts_manager : new AccountsManager($db, $options, $language, $logger);
	
	}
	
	//basically $loginlogout = new LoginLogout; try{ $loginlogout->start(); }catch(PasswordChangeException){ -> redirect to change password page }
	
	//remember to ask to change passwords if it detects passwordChange flag and call the necessary method in accounts manager (forgotten_complete), if the passwords needed to change, then don't just change the password, also call the forgotten_complete to reset the forgotten code and password Change
	
	
	
	
	/**
	 * Call this to begin tracking sessions, login details (cookies/HTTP tokens) and autologin.
	 * This will throw an exception called PasswordChangeException if it detects that the user needs to change password
	 * You would wrap this call in a try catch block and redirect to change password page.
	 * The functionality of this depends on the authentication strategies.
	 *
	 * @return boolean
	 */
	public function start(){
	
		if($this->options['login_autologin'] AND !$this->authenticated()){
			$this->autologin();
		}
		
		//now the person may not be logged in or may have autologin off
		//if the person is logged in, detect whether passwordChange is necessary
		//if so, throw an exception, the API should pass back an error
		//if it's an SPA, your SPA should detect an error code from your server, then your SPA would demand a change in passwords
	
	}
	
	//autologin strategy depends on what the auth strategy is
	//if it was HTTP, look into headers (or OAuth)
	//if it was cookies, look in to cookies
	protected function autologin(){
	
		//requires identity and autoCode
		//will call $this->login, once the details are set
		//actually why not just the id and autoCode? (also autoCode should be encrypted!), the autoCode is equivalent to a password
		//encrypted autoCode and id of the user (not username)
		//one single encrypted autologin cookie -> serialized array. Store the identity and autoCode. But we need be able to specify which strategy to use...?
		
		//if autologin failed, then do not go to login, or else it may increment login attempts
	
	}
	
	//THIS IS ALWAYS A MANUAL login (don't call this until you have the Oauth token)
	//in the case of Oauth, first do the redirect stuff (probably using $this->social_login()), on the redirect page, $this->exchange token, then call $this->login();
	public function login(array $data = null){
	
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