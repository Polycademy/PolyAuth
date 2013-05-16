<?php

namespace PolyAuth\AuthStrategies;

use PolyAuth\Options;
use PolyAuth\Cookies;

class CookieStrategy implements AuthStrategyInterface{

	protected $cookies;
	
	public function __construct(Cookies $cookies = null, Encryption $encryption = null){
		
		$this->cookies = ($cookies) ? $cookies : new Cookies(new Options);
		
	}

	public function autologin(){
	
		//should create a session
		//cookies need options to be setup...
	
	}
	
	//this just returns the $data because the cookie based authentication doesn't do anything at this point
	//but also assigns the cookies
	public function login_hook($data){
		//assign $data to cookies (using encryption)
		
		//the thing to assign should just be the session id, and also any extra data to store
		//does the session id need to be encrypted?
		
		//should create a session
		
		
		
		return $data;
	}
	
	public function logout_hook(){
	
	}

}