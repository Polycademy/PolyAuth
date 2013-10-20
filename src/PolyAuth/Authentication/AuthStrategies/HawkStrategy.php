<?php

namespace PolyAuth\Authentication\AuthStrategies;

use PolyAuth\Storage\StorageInterface;
use PolyAuth\Sessions\SessionManager;

use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\Accounts\AccountsManager;
use PolyAuth\UserAccount;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class HawkStrategy extends AbstractStrategy implements StrategyInterface{

	public function __construct(){

	}

	public function start_session(){

		$this->session_manager->start();

	}

	public function autologin(){

	}

	public function login($data, $external = false){

		return false;

	}

	public function logout(){

		$this->session_manager->finish();

	}

	//FOR THIS CASE
	//AccountsManager -> should create a random password...?
	//Yes, random passwords are good of sub accounts.
	//Imagine registering on an account, then we create another account associated with that user account.
	//Or you could enforce a high password complexity for the API.


	public function challenge(){

		$this->response->setStatusCode(401, 'Unauthorized');
		$this->response->headers->set('WWW-Authenticate', 'Hawk');

	}


}