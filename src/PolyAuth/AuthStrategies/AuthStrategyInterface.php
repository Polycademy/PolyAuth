<?php

namespace PolyAuth\AuthStrategies;

interface AuthStrategyInterface{

	/**
	 * Autologin method. Use this to determine how to log the user in automatically.
	 * Therefore it will need to extract identity and password in appropriate places, such as cookies or HTTP headers.
	 */
	public function autologin();
	
	/**
	 * Login hook is called just before the manual login. This modifies the $data variable must return the $data variable.
	 * For example for OAuth2, you would extract the token to call the API, and use the API to extract the user identity data.
	 * Modify the $data variable to fill the 'identity', 'password' = random and 'oauth' = true.
	 * If the identity cannot be retrieved, generate a random unique identity for the user.
	 * Create the cookie, if it's the cookie strategy.
	 * PolyAuth will create any corresponding server session data.
	 */
	public function login_hook($data);
	
	/**
	 * Destroy any client session data. PolyAuth will destroy the corresponding server session data.
	 */
	public function logout_hook();

}