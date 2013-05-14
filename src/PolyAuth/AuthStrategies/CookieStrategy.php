<?php

namespace PolyAuth\AuthStrategies;

use PolyAuth\AuthStrategies\AuthStrategyInterface;
use PolyAuth\CookieManager;

class CookieStrategy implements AuthStrategyInterface{

	public function autologin(){
	
	}
	
	//this just returns the $data because the cookie based authentication doesn't do anything at this point
	public function login_hook($data){
		return $data;
	}
	
	public function logged_in(){
	
	}

}