<?php

namespace PolyAuth\Authentication\AuthStrategies;

use PolyAuth\Storage\StorageInterface;
use PolyAuth\Sessions\SessionManager;
use PolyAuth\Security\Random;
use PolyAuth\Exceptions\SessionExceptions\SessionExpireException;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;

class CookieStrategy extends AbstractStrategy implements StrategyInterface{

	protected $storage;
	protected $session_manager;
	protected $cookie_options;
	protected $request;
	protected $response;
	protected $random;
	
	public function __construct(
		StorageInterface $storage, 
		SessionManager $session_manager, 
		array $cookie_options = array(), 
		Request $request = null, 
		Response $response = null, 
		Random $random = null
	){
		
		$this->storage = $storage;
		$this->session_manager = $session_manager;
		$this->request = ($request) ? $request : $this->get_request();
		$this->response = ($response) ? $response : new Response;
		$this->random = ($random) ? $random : new Random;

		//default cookie options
		$this->cookie_options = array_merge(
			array(
				'autologin'						=> true, //allowing remember me or not
				'autologin_expiration'			=> 86400, // autologin expiration (seconds). Set to zero for no expiration (well for as long as possible)
				'autologin_expiration_extend'	=> true //allowing whether autologin extends the autologin_expiration
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

		$session_cookie = $this->request->cookies->get('session');
		$autologin_cookie = $this->request->cookies->get('autologin');

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

		if($this->cookies_options['session_expiration']){
			$expiration = time() + $cookie_options['session_expiration'];
		}else{
			$expiration = 0;
		}

		//this resets the session cookie regardless of it being a new or old session, this refreshes the session cookie's lifetime
		$this->response->header->setCookie(new Cookie(
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
	 * cookie's credentials are valid. If it is valid, it will return the user id. It may also extend the  
	 * autologin expiration time. If it is invalid, it will clear the autologin details in the database, 
	 * and also delete the autologin cookie.
	 * @return Integer | Boolean $user_Id
	 */
	public function autologin(){
	
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
				return $row->id;
				
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
			$this->response->header->setCookie(new Cookie(
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
		$this->response->header->clearCookie('autologin');
		return $this->storage->clear_autologin($id);
	
	}
	
	/**
	 * Login hook, this will manipulate the $data array passed in and return it.
	 * The cookie strategy won't do anything in this case. It's a simple stub.
	 *
	 * @param $data array
	 * @return $data array
	 */
	public function login($data){
		
		//we need to do some actually logging in here... this is because different auth strategies have different routines for logging in
		//

		return $data;


		//THE STRATEGY's LOGIN function returns either boolean OR the UserAccount object
		//It should also decide whether to set the autologin
		//It should alkso decide whether to do a regeneration of the session! (only done on CookieStrategy!)
		
	}
	
	/**
	 * Logout hook, will perform any necessary custom actions when logging out.
	 * The cookie strategy won't do anything in this case.
	 *
	 * @return null
	 */
	public function logout(){

		//this will be called if there any failures in logging in, you need to make sure to delete all the potential stuff
		//like an access token or autocode
	
		//delete the php session cookie and autologin cookie
		$this->response->header->clearCookie('session');

		//if autologin was passed in via the request, we're going to clear it from the response and server
		//otherwise just clear it from the response
		$autologin = $this->request->cookies->get('autologin');
		if($autologin){
			$id = unserialize($autologin)['id'];
			$this->clear_autologin($id);
		}else{
			$this->response->header->clearCookie('autologin');
		}

		return;
	
	}

	public function get_response(){

		//this cookie strategy will most likely just output COOKIES!
		//As in the cookie header...
		//As in using $response->header->setCookie or ->clearCookie
		
		
		//this dynamically adds a strategy array property to the response object (hopefully not overwriting anything)
		//end developers can quickly check what the response object contains, and decide what to do with it
		//there are 3 options:
		//->send() or sendHeaders() or sendContent()
		//extract the response's object properties and build a response yourself
		//continue using the response object throughout the application, and augment it until you're ready to 
		//to output to it to the client in your controllers
		//one option is to check the strategy array, and if it's just headers, one can add whatever headers they want
		//to add, and write sendHeaders(), and then just continue doing their work, until sending content
		//in fact you can just call header() after calling sendHeaders() and that would overwrite any headers we set
		//as long as no content has been echoed, it's fine!
		//however for OAuth provider, often there will be content as well, the end developer would have to decide how
		//and when to output these, we recommend of course to do it immediately after you call $authenticator->start()
		$this->response->strategy = array(
			'type'		=> 'cookie',
			'headers'	=> true,
			'content'	=> false,
			'redirect'	=> false
		);

		return $this->response->prepare($this->request);

	}

}