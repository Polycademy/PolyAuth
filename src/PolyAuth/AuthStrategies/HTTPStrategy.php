<?php

namespace PolyAuth\AuthStrategies;

use Psr\Log\LoggerInterface;
use PolyAuth\Options;

/**
 * To use HTTP strategy, you need to make sure to capture any LoginValidationException, UserInactiveException or UserBannedException, and send the HTTP authentication 401 and WWW-Authenticate challenge to the client.
 * PolyAuth won't do this by default, because it doesn't know how you might want the username/password challenge to be displayed or when/where you want them.
 * Furthermore logout doesn't work with HTTP authentication. You can however resend the challenge, however this semantically means that the client's credentials are incorrect.
 */
class HTTPStrategy implements AuthStrategyInterface{

	protected $storage;
	protected $options;
	protected $logger;
	protected $realm;
	
	public function __construct(
		StorageInterface $storage, 
		Options $options, 
		LoggerInterface $logger = null,
		$realm = false
	){
		
		$this->storage = $storage;
		$this->options = $options;
		$this->logger = $logger;
		$this->realm = ($realm) ? $realm : $options['login_realm'];
		
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
	 * Checks for the HTTP Authorization header for identity and password.
	 * This does not send HTTP 401 challenge, it's meant to be non-intrusive.
	 * The end user will need to send that manually if they wish for a page to be authenticated.
	 *
	 * @return $user_id int | boolean
	 */
	public function autologin(){
	
		//check if the identity or password is passed in as HTTP
		if(!empty($_SERVER['PHP_AUTH_USER'])){
		
			$identity = $_SERVER['PHP_AUTH_USER'];
			$password = $_SERVER['PHP_AUTH_PW'];

			$row = $this->storage->get_login_check($identity);

			if($row AND password_verify($password, $row->password)){
				return $row->id;
			}
		
		}
		
		return false;
	
	}
	
	/**
	 * HTTP authentication is stateless, there are no autologin cookies. Autologin depends on the browser saving the credentials.
	 *
	 * @param $user_id int
	 * @return null
	 */
	public function set_autologin($user_id){
	
		return;
	
	}
	
	/**
	 * Login hook for HTTP authentication.
	 * This does not send HTTP 401 challenge, the end user will need to catch the login exceptions and show the HTTP 401 and WWW-Authenticate Header themselves.
	 *
	 * @param $data array | boolean
	 */
	public function login_hook($data){
	
		if(!empty($_SERVER['PHP_AUTH_USER'])){
		
			$data['identity'] = $_SERVER['PHP_AUTH_USER'];
			$data['password'] = $_SERVER['PHP_AUTH_PW'];
			
			return $data;
		
		}
		
		return false;
	
	}
	
	/**
	 * HTTP basic authentication does not have a proper logout functionality. This may clear the authentication cache or it may not.
	 * Also doing this on pages that do not require authentication will result in a prompt for username and password.
	 *
	 * @return null
	 */
	public function logout_hook(){
		
		$this->send_challenge($this->realm);
		return;
	
	}
	
	/**
	 * Sends an HTTP basic auth challenge. You can use this to manually send the challenge if authentication didn't work, or if it was needed.
	 * This is activated from HTTPStrategy, the UserSessionsManager does not use this function.
	 * Also sends an optional message.
	 *
	 * @param $realm string
	 * @param $message string
	 */
	public function send_challenge($realm, $message = false){
	
		header('WWW-Authenticate: Basic realm="' . $realm . '"');
		header('HTTP/1.0 401 Unauthorized');
		
		if($message){
			exit($message);
		}
	
	}

}