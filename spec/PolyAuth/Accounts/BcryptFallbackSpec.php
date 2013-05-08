<?php

namespace spec\PolyAuth\Accounts;

use PhpSpec\ObjectBehavior;

class BcryptFallbackSpec extends ObjectBehavior{

	function it_is_initializable(){
		$this->shouldHaveType('PolyAuth\Accounts\BcryptFallback');
	}
	
	function it_should_hash_and_verify_passwords(){
	
		$password_hash = $this->hash('password');
		$this->verify('incorrectpassword', $password_hash)->shouldReturn(false);
		$this->verify('password', $password_hash)->shouldReturn(true);
	
	}
	
}