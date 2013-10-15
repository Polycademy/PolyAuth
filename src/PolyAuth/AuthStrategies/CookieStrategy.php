<?php

namespace PolyAuth\AuthStrategies;

use PolyAuth\Storage\StorageInterface;
use PolyAuth\Options;
use PolyAuth\Sessions\SessionManager;
use PolyAuth\Cookies;
use PolyAuth\Security\Random;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Cookie;

class CookieStrategy extends AbstractStrategy implements StrategyInterface{

	protected $storage;
	protected $options;
	protected $session_manager;
	protected $request;
	protected $response;
	protected $random;
	
	public function __construct(
		StorageInterface $storage, 
		Options $options, 
		SessionManager $session_manager, 
		Request $request = null, 
		Response $response = null, 
		Random $random = null, 
	){
		
		$this->storage = $storage;
		$this->options = $options;
		$this->session_manager = $session_manager;
		$this->request = ($request) ? $request : $this->get_request();
		$this->response = ($response) ? $response : new Response;
		$this->random = ($random) ? $random : new Random;
		
	}

	//The authenticator first asks if the session is available before attempting an autologin.
	//To do this, we have to have a start function in this class.
	//The start function will check if the client connection has the relevant session id and transport.
	//If they do, it will attempt to start a session with that session id.
	//If they don't it will attempt to start a session without any session id.
	//A session will get started.
	//The authorised function can now interrogate the session data to see if a user exists and is not anonymous.
	//If they are anonymous. (This can happen if the session id was invalid/expired or session was started normally).

	public function detect_relevance(){

		$session_cookie = $this->cookies->get_cookie('session');
		$autologin_cookie = $this->cookies->get_cookie('autologin');

		//CookieStrategy would be relevant if there was a session or autologin cookie
		if($session_cookie OR $autologin_cookie){
			return true;
		}

		return false;

	}

	public function start_session(){

		$session_cookie = $this->cookies->get_cookie('session');

		if($session_cookie){

			//get the ID
			$this->session_manager->start($session_cookie);

		}else{

			//start a new session
			$this->session_manager->start();

		}

	}

	//autologin is different for different strategies
	//In Cookie Strategy
	//Autologin is a persistent session cookie, so it's more persistent than the session cookie, 
	//and this is stored not in the session manager, but in the UserAccounts table
	//In OAuthProvision
	//Starting a session would indicate a use of the "access token". This will come in via the
	//the transport (Header Authorization) and/or query parameter
	//Autologin would be the request for an access token using an "auth code" or "refresh token". This always comes in via a post request. According to section 6 (http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-6), there can be additional client authentication at the same time.
	//This would then send back the access token for the client to use.
	//Login hook would be used in order to process the client credentials and resource owner credentials (determined based on options). Or just resource owner credentials. 3 legged would lead to auth code. 2 legged would lead to access token (skip auth code). Can't decide automatically, use manual options to decide.
	//In OAuth consumption (authorisation code grant) as a decorator
	//Starting a session would not change, that's dependent on the actual strategy
	//Autologin would be enhanced by checking for an "auth code". This "auth code" will however be a third party 
	//auth code, this is a request for a third party access token. The server would receive this auth code
	//and send a request to the third party to get an access token. This is saved against not the session but 
	//the user account. (this checking of the auth code, does need to be separated from auth code intended for this server)
	//So there are 2 types of auth codes. One sent to OAuthProvider, and one intended for OAuthConsume. How to differentiate?
	//Auth codes that come in for OAuthConsumer comes in as redirect. They are in the query parameters along with other redirection parameters.
	//Just check the redirection parameters, and you have the correct auth code. The auth code that comes in for OAuthProvider would come in as a
	//post request (as in here: http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-4.1.3), and of course this is a request for access token.
	//
	//TO RECAP:
	//OAuthConsume autologin enhancing: Look got auth code and redirection parameters in the query parameters.
	//OAuthProvision autologin enhancing: Look into the post request
	//
	//Login hook would not change, because the user would still login using their particular strategy.

	/**
	 * Autologin Cookie Strategy, this checks whether the autologin cookie exists, and checks if the cookie's credentials are valid.
	 * If it is valid, it will return the user id. It may also extend the autologin expiration time.
	 * If it is invalid, it will clear the autologin details in the database, and also delete the autologin cookie.
	 * If the user id didn't exist, it doesn't really matter, since the update will still pass.
	 *
	 * @return $user_id int | boolean
	 */
	public function autologin(){
	
		//should return an array
		$autologin = $this->cookies->get_cookie('autologin');
		
		if($autologin){
		
			$autologin = unserialize($autologin);
			$id = $autologin['id'];
			$autocode = $autologin['autoCode'];
			//current time minus duration less/equal autoDate
			$valid_date = date('Y-m-d H:i:s', time() - $this->options['login_expiration']);

			//also check for expiration
			$row = $this->storage->check_autologin($id, $autocode, $valid_date);

			if($row){
				
				//extend the user's autologin if it is switched on
				if($this->options['login_expiration_extend']){
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
			$expiration = ($this->options['login_expiration'] !== 0) ? $this->options['login_expiration'] : (60*60*24*365*2);
			$this->cookies->set_cookie('autologin', $autologin, $expiration);
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
		$this->cookies->delete_cookie('autologin');
		return $this->storage->clear_autologin($id);
	
	}
	
	/**
	 * Login hook, this will manipulate the $data array passed in and return it.
	 * The cookie strategy won't do anything in this case. It's a simple stub.
	 *
	 * @param $data array
	 * @return $data array
	 */
	public function login_hook($data){
		
		return $data;
		
	}
	
	/**
	 * Logout hook, will perform any necessary custom actions when logging out.
	 * The cookie strategy won't do anything in this case.
	 *
	 * @return null
	 */
	public function logout_hook(){
	
		//delete the php session cookie and autologin cookie
		$this->cookies->delete_cookie('session');
		$this->cookies->delete_cookie('autologin');
		return;
	
	}

	public function get_response(){

		//this cookie strategy will most likely just output COOKIES!
		//As in the cookie header...
		//As in using $response->header->setCookie or ->clearCookie

	}

}