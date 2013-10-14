<?php

namespace PolyAuth;

//standard options object to be passed in
class Options implements \ArrayAccess{

	//session_expiration => expiration of a particular user or anonymous sesion (remembering staying on the page)
	//cookie_lifetime => expiration of the session cookie (remembering across pages)
	//login_expiration => expiration of the autologin cookie

	public $options = array(
		//table options, see that the migration to be reflected. (RBAC options are not negotiable)
		'table_users'						=> 'user_accounts',
		'table_login_attempts'				=> 'login_attempts',
		'table_external_providers'			=> 'external_providers',
		//password options
		'hash_method'						=> PASSWORD_DEFAULT, //PASSWORD_DEFAULT || PASSWORD_BCRYPT
		'hash_rounds'						=> 10,
		//session options (used for internal session handling)
		'session_save_path'					=> '', //for filesystem persistence, leave empty for default session save path
		'session_expiration'				=> 43200, //expiration of a single session (set to null for infinite)
		'session_gc_probability'			=> '1', //probability of running the session garbage collection (percentage change to one decimal place)
		//cookie options
		'cookie_domain'						=> '',
		'cookie_path'						=> '/',
		'cookie_prefix'						=> 'polyauth_',
		'cookie_secure'						=> false,
		'cookie_httponly'					=> true,
		'cookie_lifetime'					=> 0, //for when the browser is closed (how long should the session cookies should be remembered for) (0 means the cookie dies as soon as the browser closes)
		//email options (email data should be passed in as a string, end user manages their own stuff)
		'email'								=> false, //make this true to use the emails by PHPMailer, otherwise false if you want to roll your own email solution, watch out for email activation
		'email_smtp'						=> false,
		'email_host'						=> '',
		'email_port'						=> '',
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
		'role_default'						=> 'member',
		//login options (this is the field used to login with, plus login attempts)
		'login_identity'					=> 'email', //can be email or username, if you are using third party sign in, it's recommended to be 'email'
		'login_password_complexity'			=> array( //this should allow spaced names...?
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
		'login_lockout'						=> array('ipaddress', 'identity'), //lockout tracking, can use both or one of them or false
		'login_lockout_cap'					=> 172800, //cap on the lockout time in seconds (0 means no cap) 48 hrs
		'login_forgot_expiration'			=> 0, //how long before the temporary password expires in seconds!
		'login_realm'						=> 'Protected by PolyAuth Realm', //only relevant to HTTP auth
		//registration options
		'reg_activation'					=> false, //can be email, manual, or false (if doing manual, the activationCode is still generated, but you will need to send the email yourself)
		//oauth1/2 consumption options
		'external_federation'				=> true, //to auto federate across providers (duplicate providers will always merge regardless)
		'external_providers'				=> array( //can be false or empty array, below is an example of OAuth2 + OAuth1
			// 'github'		=> array(
			// 	'key'				=> '',
			// 	'secret'			=> '',
			// 	'scope'				=> array(), //if scopes change, it will require everybody to relogin
			// 	'callback_url'		=> '', //if it is not set (or empty), it will be auto set to the current url in which the code is called, this will be overwritten if passed in directly during login
			// 	'identifier'		=> array(
			// 		'api' 		=> 'user/email',
			// 		'key'		=> 'email',
			// 		'type'		=> 'email',
			// 	), //key to url (expected JSON, but can also be done with other information too...)
			// ),
			// 'twitter'		=> array(
			// 	'key'				=> '',
			// 	'secret'			=> '',
			// 	'scope'				=> false, //OAUTH1 does not have scopes, make sure to be false
			// 	'callback_url'		=> '', //note that we'll add in a custom "provider" query parameter, so that is reserved!
			// 	'identifier'		=> array(
			// 		'api'	=> 'blah',
			// 		'key'	=> 'id', //this is the json key
			// 		'type'	=> 'id', //this the type prefix, all identifiers that are to be federated need the same type, if you have different types, they not will be federated even if you ask it to, in order to prevent confusion between the same values
			// 	), //twitter id is better than their name handle
			// ),
		),
		'external_token_encryption'			=> false, //if this is false, we will not encrypt the token data, otherwise provide a random key, only set this once, if you change this option, you'll need to manually encrypt/decrypt all the database tokens
	);
	
	public function __construct(array $options = null){
		
		if($options){
			$this->set_options($options);
		}
		
	}
	
	public function set_options(array $options){
		$this->options = array_merge($this->options, $options);
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