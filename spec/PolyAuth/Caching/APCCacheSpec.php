<?php

namespace spec\PolyAuth\Caching;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class APCCacheSpec extends ObjectBehavior{

	function it_is_initializable(){
		$this->shouldHaveType('PolyAuth\Caching\APCCache');
	}
	
}