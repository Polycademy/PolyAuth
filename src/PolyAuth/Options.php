<?php

namespace PolyAuth;

use PolyAuth\Sessions\EncryptedSessionHandler;

//standard options object to be passed in
class Options implements \ArrayAccess{

	public $options = array(
		//table options, see that the migration to be reflected. (RBAC options are not negotiable)
		'table_users'						=> 'user_accounts',
		'table_login_attempts'				=> 'login_attempts',
		//password options
		'hash_method'						=> PASSWORD_DEFAULT, //PASSWORD_DEFAULT || PASSWORD_BCRYPT
		'hash_rounds'						=> 10,
		//session options
		'session_handler'					=> new EncryptedSessionHandler('abc4345ncu'), //SessionHandlerInterface or null
		'session_expiration'				=> 43200, //expiration of a single session (set to 0 for infinite)
		//cookie options
		'cookie_domain'						=> '',
		'cookie_path'						=> '/',
		'cookie_prefix'						=> 'polyauth',
		'cookie_secure'						=> false,
		'cookie_httponly'					=> false,
		'cookie_lifetime'					=> 0, //for when the browser is closed (how long should the cookies be remembered for) (0 means the cookie dies as soon as the browser closes)
		//email options (email data should be passed in as a string, end user manages their own stuff)
		'email'								=> false, //make this true to use the emails by PHPMailer, otherwise false if you want to roll your own email solution, watch out for email activation
		'email_smtp'						=> false,
		'email_host'						=> '',
		'email_auth'						=> false,
		'email_username'					=> '',
		'email_password'					=> '',
		'email_smtp_secure'					=> '', //tls or ssl or false
		'email_from'						=> 'enquiry@polycademy.com',
		'email_from_name'					=> 'Polycademy',
		'email_replyto'						=> false, //can be an email or false
		'email_replyto_name'				=> '',
		'email_cc'							=> false,
		'email_bcc'							=> false,
		'email_html'						=> true, //will determine it was text or html based email
		'email_activation_template'			=> 'Activation code: {{activation_code}} User id: {{user_id}}. Here is an example link http://example.com/?activation_code={{activation_code}}&user_id={{user_id}}',
		'email_forgotten_identity_template'	=> 'Identity: {{identity}} User id {{user_id}}.',
		'email_forgotten_password_template'	=> 'Temporary login: {{forgotten_code}} Identity: {{identity}} User id {{user_id}}.',
		//rbac options (initial roles from the migration, also who's the default role, and root access role?)
		'role_default'						=> 'members',
		//login options (this is the field used to login with, plus login attempts)
		'login_identity'					=> 'username', //can be email or username
		'login_password_complexity'			=> array(
			'min'			=> 8, //('' or false or 8)
			'max'			=> 32,
			'lowercase'		=> false,
			'uppercase'		=> false,
			'number'		=> false,
			'specialchar'	=> false,
			'diffpass'		=> false, //number of characters different from old password ('' or false or 3)
			'diffidentity'	=> false,
			'unique'		=> false, //number of unique characters ('' or false or 4) ('' defaults to 4)
		), //can be an array or empty array
		'login_autologin'					=> true, //allowing remember me or not
		'login_expiration'					=> 86500, // autologin expiration (seconds). Set to zero for no expiration
		'login_expiration_extend'			=> true, //allowing whether autologin extends the login_expiration
		'login_attempts'					=> 0, //if 0, then it is disabled
		'login_lockout'						=> 0, //lockout time in seconds
		'login_forgot_expiration'			=> 0, //how long before the temporary password expires in seconds!
		'login_realm'						=> 'Protected by PolyAuth Realm', //only relevant to HTTP auth
		//registration options
		'reg_activation'					=> false, //can be email, manual, or false
		//cache options
		'cache_directory'					=> '', //this is only relevant to the FileSystemCache
		'cache_ttl'							=> 3600, //maximum time an item can live in memory, this is only relevant to APCCache
	);
	
	public function __construct(array $options = null){
		
		if($options){
			$this->set_options($options);
		}
		
		//this should only run once at startup (should create this as a singleton)
		$this->set_session_handler($this->options['session_handler']);
		$this->set_cookie_settings();
		
	}
	
	public function set_options(array $options){
		$this->options = array_merge($this->options, $options);
	}
	
	protected function set_session_handler(\SessionHandlerInterface $session_handler = null){
	
		if($session_handler === null){
			return;
		}
		
		session_set_save_handler($handler, true);		
	
	}
	
	protected function set_cookie_settings(){
	
		$session_name = ini_get('session.name');
		$session_name = $this->options['cookie_prefix'] . $session_name;
		ini_set('session.name', $session_name);
		
		session_set_cookie_params(
			$this->options['cookie_lifetime'],
			$this->options['cookie_path'],
			$this->options['cookie_domain'],
			$this->options['cookie_secure'],
			$this->options['cookie_httponly']
		);
	
	}
	
	public function offsetSet($offset, $value) {
		if (is_null($offset)) {
			$this->options[] = $value;
		} else {
			$this->options[$offset] = $value;
		}
	}
	
	public function offsetExists($offset) {
		return isset($this->options[$offset]);
	}
	
	public function offsetUnset($offset) {
		unset($this->options[$offset]);
	}
	
	public function offsetGet($offset) {
		return isset($this->options[$offset]) ? $this->options[$offset] : null;
	}

}