<?php

namespace spec\PolyAuth;

use PhpSpec\ObjectBehavior;

class OptionsSpec extends ObjectBehavior{

	function it_is_initializable(){
		$this->shouldHaveType('PolyAuth\Options');
	}
	
	function it_should_manipulate_options_array(){
	
		$this->set_options(array(
			'login_expiration'	=> 100,
		));
		
		$this['login_expiration']->shouldReturn(100);
		
		$this[0] = 'Blah blah';
		
		$this[0]->shouldReturn('Blah blah');
	
	}
	
}
