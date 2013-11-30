<?php

namespace PolyAuth\Authentication\AuthStrategies;

use PolyAuth\Storage\StorageInterface;
use PolyAuth\Sessions\SessionManager;
use PolyAuth\Security\Random;

use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\Accounts\AccountsManager;
use PolyAuth\UserAccount;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;

class CookieStrategy extends AbstractStrategy implements StrategyInterface{

	protected $storage;
	protected $lang;
	protected $session_manager;
	protected $cookie_options;
	protected $request;
	protected $response;
	protected $accounts_manager;
	protected $random;
	
	public function __construct(
		StorageInterface $storage, 
		Options $options,
		Language $language, 
		SessionManager $session_manager, 
		array $cookie_options = array(), 
		Request $request = null, 
		Response $response = null, 
		AccountsManager $accounts_manager = null, 
		Random $random = null
	){
		
		$this->storage = $storage;
		$this->lang = $language;
		$this->session_manager = $session_manager;
		$this->request = ($request) ? $request : $this->get_request();
		$this->response = ($response) ? $response : new Response;
		$this->accounts_manager = ($accounts_manager) ? $accounts_manager : new AccountsManager($storage, $options, $language);
		$this->random = ($random) ? $random : new Random;

		//default cookie options
		$this->cookie_options = array_merge(
			array(
				'autologin'						=> true, //allowing remember me or not
				'autologin_expiration'			=> 86400, // autologin expiration (seconds). Set to zero for no expiration (well for as long as possible)
				'autologin_expiration_extend'	=> true, //allowing whether autologin extends the autologin_expiration
				'cookie_path'					=> '/',
				'cookie_domain'					=> null,
				'cookie_secure'					=> false,
				'cookie_httponly'				=> true,
			),
			$cookie_options
		);

		//client session expiration should equal the server session expiration
		$this->cookie_options['session_expiration'] = intval($this->session_manager->get_session_expiration()); //session expiration can literally be zero for a session cookie!

	}

	/**
	 * Detects if CookieStrategy is relevant to the current request.
	 * Tests for the existence of a session cookie or an autologin cookie.
	 * @return Boolean
	 */
	public function detect_relevance(){

		$session_cookie = $this->request->cookies->has('session');
		$autologin_cookie = $this->request->cookies->has('autologin');

		if($session_cookie OR $autologin_cookie){
			return true;
		}

		return false;

	}

	/**
	 * Starts the session tracking for Cookie strategy.
	 * It first gets the session cookie. If the cookie exists, it attempts to 
	 * start the session with the session cookie's session id. If it doesn't exist 
	 * it will start a new anonymous session. This is all handled by the SessionManager.
	 * After the session is started, it will reset the session cookie with the new/old 
	 * session id, and reset the expiration of the cookie. The expiration of the server 
	 * session is also reset in the SessionManager. This means the session lifetime
	 * can be refreshed each time the user accesses the system.
	 * @return Void
	 */
	public function start_session(){

		$session_cookie = $this->request->cookies->get('session');

		if($session_cookie){
			$session_id = $this->session_manager->start($session_cookie);
		}else{
			$session_id = $this->session_manager->start();
		}

		if($this->cookie_options['session_expiration']){
			$expiration = time() + $this->cookie_options['session_expiration'];
		}else{
			$expiration = 0;
		}

		//this resets the session cookie regardless of it being a new or old session, this refreshes the session cookie's lifetime
		$this->response->headers->setCookie(new Cookie(
			'session',
			$session_id,
			$expiration, 
			$this->cookie_options['cookie_path'], 
			$this->cookie_options['cookie_domain'], 
			$this->cookie_options['cookie_secure'], 
			$this->cookie_options['cookie_httponly']
		));

	}

	/**
	 * Autologin Cookie Strategy, this checks whether the autologin cookie exists, and checks if the 
	 * cookie's credentials are valid. If it is valid, it will return a new user id. It may also extend the  
	 * autologin expiration time. If it is invalid, it will clear the autologin details in the database, 
	 * and also delete the autologin cookie.
	 * @return Integer | Boolean
	 */
	public function autologin(){

		if(!$this->cookie_options['autologin']){
			return false;
		}
	
		$autologin = $this->request->cookies->get('autologin');
		
		if($autologin){
		
			$autologin = unserialize($autologin);
			$id = $autologin['id'];
			$autocode = $autologin['autoCode'];
			//current time minus duration less/equal autoDate
			$valid_date = date('Y-m-d H:i:s', time() - $this->cookie_options['autologin_expiration']);

			//also check if autologin has expired on the server
			$row = $this->storage->check_autologin($id, $autocode, $valid_date);

			if($row){
				
				//extend the user's autologin if it is switched on
				if($this->cookie_options['autologin_expiration_extend']){
					$this->set_autologin($id);
				}

				//refresh the session
				$this->regenerate_cookie_session();

				return $this->accounts_manager->get_user($row->id);
				
			}else{
			
				//clear the autoCode in the DB, since it failed
				$this->clear_autologin($id);
				return false;
				
			}
		
		}

		return false;
	
	}
	
	/**
	 * Set the autologin cookie, autologin code and autologin date for the specified user id.
	 * Can also be used to reset the autologin cookie.
	 *
	 * @param $id integer
	 * @return boolean
	 */
	public function set_autologin($id){
	
		$autocode = $this->random->generate(20);

		if($this->storage->set_autologin($id, $autocode)){

			$autologin = serialize(array(
				'id'		=> $id,
				'autoCode'	=> $autocode,
			));

			//cookie's expiration duration, if the autologin_expiration is 0, then it's set to a 2 year duration
			$expiration = ($this->cookie_options['autologin_expiration'] !== 0) ? $this->cookie_options['autologin_expiration'] : (60*60*24*365*2);
			
			//set the new autologin cookie!
			$this->response->headers->setCookie(new Cookie(
				'autologin', 
				$autologin, 
				time() + $expiration, 
				$this->cookie_options['cookie_path'], 
				$this->cookie_options['cookie_domain'], 
				$this->cookie_options['cookie_secure'], 
				$this->cookie_options['cookie_httponly']
			));

			return true;

		}else{

			return false;

		}
	
	}
	
	/**
	 * Clears the autologin cookie, autologin code and autologin date for the specified user id.
	 *
	 * @param $id integer
	 * @return boolean
	 */
	public function clear_autologin($id){
	
		//clear the cookie to prevent multiple attempts
		$this->response->headers->clearCookie('autologin');
		return $this->storage->clear_autologin($id);
	
	}

	public function login(array $data, $external = false){

		//if identity doesn't exist or that (password doesn't exist while external is false)
		//if external is true, password doesn't need to be set
		if(!isset($data['identity']) OR (!isset($data['password']) AND !$external)){

			return array(
				'identity'	=> $data['identity'],
				'message'	=> $this->lang['login_unsuccessful'],
				'throttle'	=> false
			);

		}

		$row = $this->storage->get_login_check($data['identity']);

		if($row){

			//if external, we don't run the password verify
			if(!$external AND !password_verify($data['password'], $row->password)){

				//because the password failed, we are going to throttle the login attempt
				return array(
					'identity'	=> $data['identity'],
					'message'	=> $this->lang['login_password'],
					'throttle'	=> true
				);
			
			}

			//if it was external, then there is no password
			$user_id = $row->id;

		}else{

			return array(
				'identity'	=> $data['identity'],
				'message'	=> $this->lang['login_identity'],
				'throttle'	=> false
			);

		}

		if(!empty($data['autologin']) AND $this->cookie_options['autologin']){
			$this->set_autologin($user_id);
		}

		$this->regenerate_cookie_session();

		$user = $this->accounts_manager->get_user($user_id);

		return $user;
		
	}
	
	public function logout(){
	
		//delete the php session cookie and autologin cookie
		$this->response->headers->clearCookie('session');

		//if autologin was passed in via the request, we're going to clear it from the response and server
		//otherwise just clear it from the response
		$autologin = $this->request->cookies->get('autologin');
		if($autologin){
			$id = unserialize($autologin)['id'];
			$this->clear_autologin($id);
		}else{
			$this->response->headers->clearCookie('autologin');
		}

		//clears the server session information
		$this->session_manager->finish();
	
	}

	public function challenge(){

		$this->response->setStatusCode(401, 'Unauthorized');

	}

	/**
	 * Regenerates the session id on the server and on the cookies. This is only ever
	 * used inside the CookieStrategy. Other strategies do not need to regenerate 
	 * session ids. To help prevent session fixation. This is called on logging in through
	 * either normal login or autologin.
	 * @return Void
	 */
	protected function regenerate_cookie_session(){

		$new_session_id = $this->session_manager->regenerate();

		if($this->cookie_options['session_expiration']){
			$expiration = time() + $cookie_options['session_expiration'];
		}else{
			$expiration = 0;
		}

		$this->response->headers->setCookie(new Cookie(
			'session',
			$new_session_id,
			$expiration, 
			$this->cookie_options['cookie_path'], 
			$this->cookie_options['cookie_domain'], 
			$this->cookie_options['cookie_secure'], 
			$this->cookie_options['cookie_httponly']
		));

	}

}