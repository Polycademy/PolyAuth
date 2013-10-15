<?php

namespace PolyAuth\Authentication\AuthStrategies;

use Symfony\Component\HttpFoundation\Request;

abstract class AbstractStrategy{

	/**
	 * Returns the session manager which can be used as an array to manipulate the session data.
	 * @return ArrayObject
	 */
	public function get_session(){

		return $this->session_manager;

	}

	/**
	 * Establishes a Symfony request object. This augments the request object with the Authorization 
	 * header since it's not available by default.
	 * @return Object
	 */
	public function get_request(){

		$headers = getallheaders();

		$request = Request::createFromGlobals();
		if(isset($headers['Authorization'])){
			$request->headers->set('Authorization', $headers['Authorization']);
		}

		return $request;

	}

	/**
	 * This will return an HTTPFoundation response object which contains what PolyAuth wants to 
	 * return to the client. However the end developer can further modify the response object,
	 * or reconstruct it differently.
	 */
	abstract public get_response();

	/**
	 * Start_session will find the relevant session id/token and the transport method, and start
	 * the session tracking
	 */
	abstract public function start_session();

	/**
	 * Autologin method. Use this to determine how to log the user in automatically.
	 * Therefore it will need to extract identity and password in appropriate places, such as cookies or HTTP headers.
	 */
	abstract public function autologin();
	
	/**
	 * This should setup a persistent autologin method to go with the autologin function. It can be a stub.
	 */
	abstract public function set_autologin($user_id);
	
	/**
	 * Login hook is called just before the manual login. This modifies the $data variable must return the $data variable.
	 * Modify the $data variable to fill it with ['identity'] AND ['password'].
	 * Certain strategies may use login hook to create the random account on the fly such as Oauth or OpenId.
	 * PolyAuth will create any corresponding server session data.
	 */
	abstract public function login($data);
	
	/**
	 * Destroy any client session data. PolyAuth will destroy the corresponding server session data.
	 */
	abstract public function logout();

}