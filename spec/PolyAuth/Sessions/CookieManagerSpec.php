<?php

namespace spec\PolyAuth\Sessions;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class CookieManagerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('PolyAuth\Sessions\CookieManager');
		
		//use overwrite function to overwrite PHP's cookie functions to return true!
    }
}
