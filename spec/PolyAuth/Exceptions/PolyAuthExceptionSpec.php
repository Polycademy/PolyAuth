<?php

namespace spec\PolyAuth\Exceptions;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class PolyAuthExceptionSpec extends ObjectBehavior{
	
	function it_is_initializable(){
		$this->shouldHaveType('PolyAuth\Exceptions\PolyAuthException');
	}
	
	function it_should_append_errors_and_return_them(){
	
		$this->append_error('blah blah blah');
		$this->append_error('lol lol lol');
		$this->get_errors()->shouldReturn(['blah blah blah', 'lol lol lol']);
	
	}
	
}