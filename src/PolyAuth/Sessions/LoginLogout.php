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
use PolyAuth\Sessions\CookieManager;
use Aura\Session\Manager as SessionManager;
use Aura\Session\SegmentFactory;
use Aura\Session\CsrfTokenFactory;

//for RBAC (to authenticate against access)
use PolyAuth\Accounts\AccountsManager;
use PolyAuth\UserAccount;
use RBAC\Permission;
use RBAC\Role\Role;
use RBAC\Manager\RoleManager;

//this class handles all the login and logout functionality
class LoginLogout{

	protected $db;
	protected $options;
	protected $lang;
	protected $logger;
	protected $session_manager;
	protected $accounts_manager;
	protected $role_manager;
	
	protected $user; //this is used to represent the user account for the RBAC, it is only initialised when a person logs in, it is not be used for any other purposes, always must represent the currently logged in user
	
	protected $errors = array();

	public function __construct(PDO $db, Options $options, Language $language, SessionInterface $session_handler = null, LoggerInterface $logger = null){
	
		$this->options = $options;
		$this->lang = $language;
		
		$this->db = $db;
		$this->logger = $logger;
		$this->cookie_manager = new CookieManager(
			$this->options['cookie_domain'],
			$this->options['cookie_path'],
			$this->options['cookie_prefix'],
			$this->options['cookie_secure'],
			$this->options['cookie_httponly']
		);
		$this->session_manager = new SessionManager(new SegmentFactory, new CsrfTokenFactory);
		$this->accounts_manager = new AccountsManager($db, $options, $language, $logger); //to mainly use the password hash verify
		$this->role_manager  = new RoleManager($db, $logger);
		
		$this->startyourengines();
	
	}
	
	//remember to ask to change passwords if it detects a forgottenCode and forgottenTime and call the necessary method in accounts manager
	protected function startyourengines(){
	
		//immediately logs the person in if they have identity, rememberCode and are not currently logged in
		if(!$this->logged_in() && $this->cookie_manager->get_cookie('identity') && $this->cookie_manager->get_cookie('rememberCode')){
			$this->login_remembered_user();
		}
		
		//... continue
		
	
	}
	
	public function login(){
	
	}
	
	public function login_remembered_user(){
	
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
	
	public function logged_in(){
	
	}
	
	public function logout(){
	
	}
	
	public function encrypt_session($data, $key){

		return base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, md5($key), $data, MCRYPT_MODE_CBC, md5(md5($key))));

	}
	
	public function decrypt_session($data, $key){
	
		return rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, md5($key), base64_decode($data), MCRYPT_MODE_CBC, md5(md5($key))), "\0");
	
	}
	
	public function get_errors(){
		if(!empty($this->errors)){
			return $this->errors;
		}else{
			return false;
		}
	}

}