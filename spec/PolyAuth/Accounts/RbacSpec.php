<?php

namespace spec\PolyAuth\Accounts;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class RbacSpec extends ObjectBehavior{

	function let(){
	
	}

	function it_is_initializable(){
	
		$this->shouldHaveType('PolyAuth\Accounts\Rbac');
		
	}
	
	function it_implements_logger_interface(){
	
		$this->shouldImplement('Psr\Log\LoggerAwareInterface');
	
	}
	
}
