<?php

namespace PolyAuth\Security;

use PolyAuth\Options;
use PolyAuth\Storage\StorageInterface;
use Symfony\Component\HttpFoundation\Request;
use PolyAuth\Security\IpTransformer;

class LoginAttempts{

	protected $storage;
	protected $options;
	protected $request;
	protected $ip_transformer;

	public function __construct(
		StorageInterface $storage, 
		Options $options,
		Request $request = null,
		IpTransformer $ip_transformer = null
	){
	
		$this->storage = $storage;
		$this->options = $options;
		$this->request = ($request) ? $request : Request::createFromGlobals();
		$this->ip_transformer = ($ip_transformer) ? $ip_transformer : new IpTransformer;

	}
	
	/**
	 * Checks if the current login attempt is locked according to an exponential timeout.
	 * There is cap on the length of the timeout however. The timeout could grow to infinity without the cap.
	 * This returns how many seconds the session is locked out from attempting a login.
	 *
	 * @param $identity string
	 * @return false | int
	 */
	public function locked_out($identity){

		$lockout_options = $this->options['login_lockout'];
		
		if(
			!empty($identity) 
			AND is_array($lockout_options)
			AND (
				in_array('ipaddress', $lockout_options) 
				OR 
				in_array('identity', $lockout_options)
			)
		){

			$row = $this->storage->locked_out(
				$identity, 
				$this->ip_transformer->insert($this->request->getClientIp())
			);

			if(!$row){
				return false;
			}

			$number_of_attempts = $row->attemptNum;
			$last_attempt = $row->lastAttempt;
			
			//y = 1.8^(n-1) where n is number of attempts, resulting in exponential timeouts, to prevent brute force attacks
			$lockout_duration = round(pow(1.8, $number_of_attempts - 1));
			
			//capping the lockout time
			if($this->options['login_lockout_cap']){
				$lockout_duration = min($lockout_duration, $this->options['login_lockout_cap']);
			}
			
			//adding the lockout time to the last attempt will create the overall timeout
			$timeout = strtotime($last_attempt) + $lockout_duration;
			
			//if the current time is less than the timeout, then attempt is locked out
			if(time() < $timeout){
				//return the difference in seconds
				return (integer) $timeout - time();
			}
			
		}
		
		return false;
	
	}
	
	/**
	 * Increment the number of login attempts.
	 * This will track both the ip address and the identity used to login.
	 * It will only increment for the current session's ip.
	 *
	 * @param $identity string
	 * @return true
	 */
	public function increment($identity){

		return $this->storage->increment_login_attempt(
			$identity, 
			$this->ip_transformer->insert($this->request->getClientIp())
		);
	
	}
	
	/**
	 * Clear all the login attempts on a successful login for a particular identity.
	 * Clears only where the identity and the current session's ip match.
	 * The $either_or allows people to force this function to clear ipaddress or identity simultaneously.
	 * This will be used when the forgotten cycle completes, because we want to allow the session to bypass
	 * ipaddress checks and identity checks.
	 * Normally it would check ipaddress AND identity
	 * 
	 * @param $identity string
	 * @param $either_or boolean
	 * @return true | false
	 */
	public function clear($identity, $either_or = false){
	
		$lockout_options = $this->options['login_lockout'];
		
		if(
			!empty($identity) 
			AND is_array($lockout_options)
			AND (
				in_array('ipaddress', $lockout_options) 
				OR 
				in_array('identity', $lockout_options)
			)
		){

			return $this->storage->clear_login_attempts(
				$identity, 
				$this->ip_transformer->insert($this->request->getClientIp()), 
				$either_or
			);
			
		}
		
		return false;
	
	}

}