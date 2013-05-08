<?php

namespace spec\PolyAuth\Accounts;

use PhpSpec\ObjectBehavior;

class RandomSpec extends ObjectBehavior{

	function it_is_initializable(){
	
		$this->shouldHaveType('PolyAuth\Accounts\Random');
		
	}
	
	function it_should_generate_random_alpha_numeric_token(){
	
		$this->generate(32)->shouldHaveLength(32);
		//at least one capital alpha, lowercase alpha and number in any order while negating any special characters
		$this->generate(32)->shouldMatch('/^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])[A-Za-z0-9]+$/');
		$this->generate(2)->shouldReturn(false);
	
	}
	
	function it_should_generate_random_alpha_numeric_special_token(){
		
		//and also one or more characters that is neither alpha nor numeric
		$this->generate(32, true)->shouldMatch('/^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[^A-Za-z0-9]).+$/');
		$this->generate(3, true)->shouldReturn(false);
		
	}
	
	public function getMatchers(){
	
		return [
			'haveLength' => function($subject, $condition) {
				return (strlen($subject) == $condition);
			},
		];
		
	}
	
}
