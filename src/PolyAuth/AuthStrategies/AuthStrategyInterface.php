<?php

namespace PolyAuth\AuthStrategies;

use Psr\Log\LoggerInterface;
use Psr\Log\LoggerAwareInterface;

interface AuthStrategyInterface extends LoggerAwareInterface{

	/**
	 * Autologin method. Use this to determine how to log the user in automatically.
	 * Therefore it will need to extract identity and password in appropriate places, such as cookies or HTTP headers.
	 */
	public function autologin();
	
	/**
	 * This should setup a persistent autologin method to go with the autologin function. It can be a stub.
	 */
	public function set_autologin($user_id);
	
	/**
	 * Login hook is called just before the manual login. This modifies the $data variable must return the $data variable.
	 * Modify the $data variable to fill it with ['identity'] AND ['password'].
	 * Certain strategies may use login hook to create the random account on the fly such as Oauth or OpenId.
	 * PolyAuth will create any corresponding server session data.
	 */
	public function login_hook($data);
	
	/**
	 * Destroy any client session data. PolyAuth will destroy the corresponding server session data.
	 */
	public function logout_hook();
	
	/**
	 * Sets a logger instance on the object
	 */
	public function setLogger(LoggerInterface $logger);

}