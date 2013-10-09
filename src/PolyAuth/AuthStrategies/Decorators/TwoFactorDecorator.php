<?php

namespace PolyAuth\AuthStrategies\Decorators;

class TwoFactorDecorator extends DecoratorAbstract{

	public function __construct($strategy){
		$this->strategy = $strategy;
	}

	//any strategy can be decorated to make sure that there's a second factor of authentication
	//specifically login/autologin
	//well actually autologin cannot be 2 factored, it's automatically logging in!
	//There can't be a 2 factor!
	//Only the login function will be wrapped!

}