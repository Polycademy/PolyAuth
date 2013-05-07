<?php

namespace spec\PolyAuth;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class EmailerSpec extends ObjectBehavior{
	function it_is_initializable()
	{
	$this->shouldHaveType('PolyAuth\Emailer');
	}
}
