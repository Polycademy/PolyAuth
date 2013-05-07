<?php

namespace PolyAuth;

use PolyAuth\Sessions\SessionInterface;

//standard options object to be passed in
class Options implements \ArrayAccess{

	public $options = array();
	
	public function __construct(array $options = false){
		
		$this->options = array(
			//table options, see that the migration to be reflected. (RBAC options are not negotiable)
			'table_users'						=> 'user_accounts',
			'table_login_attempts'				=> 'login_attempts',
			//security options
			'hash_fallback'						=> false, //set whether to use bcrypt fallback (if you're behind 5.3.7 in PHP version, this will not seamlessly upgrade, if you switch PHP versions, make sure to rehash your passwords manually)
			'hash_method'						=> PASSWORD_DEFAULT,	//can be PASSWORD_DEFAULT or PASSWORD_BCRYPT
			'hash_rounds'						=> 10,
			//session options
			'session_encrypt'					=> true, //should the session data be encrypted? (only for the cookie)
			'session_key'						=> 'hiddenpassword', //session encryption key, any number of characters and depends on session_encrypt
			'session_handler'					=> null, //object that implements the SessionInterface
			//cookie options
			'cookie_domain'						=> '',
			'cookie_path'						=> '/',
			'cookie_prefix'						=> '',
			'cookie_secure'						=> false,
			'cookie_httponly'					=> false,
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
			'email_type'						=> 'html', //can be text or html
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
			'login_persistent'					=> true, //allowing remember me or not
			'login_expiration'					=> 86500, // How long to remember the user (seconds). Set to zero for no expiration
			'login_expiration_extend'			=> true, //allowing whether autologin extends the login_expiration
			'login_attempts'					=> 0, //if 0, then it is disabled
			'login_lockout'						=> 0, //lockout time in seconds
			'login_forgot_expiration'			=> 0, //how long before the temporary password expires in seconds!
			//registration options
			'reg_activation'					=> false, //can be email, manual, or false
		);
		
		if($options){
			$this->set_options($options);
		}
		
		//this should only run once at startup
		$this->set_session_handler($this->options['session_handler']);
		
	}
	
	public function set_options(array $options){
		$this->options = array_merge($this->options, $options);
	}
	
	protected function set_session_handler(SessionInterface $session_handler = null){
	
		if($session_handler === null){
			return;
		}
		
		//second parameter is to register the shutdown function
		//make sure this runs before sessions are started
		session_set_save_handler($session_handler, true);
	
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