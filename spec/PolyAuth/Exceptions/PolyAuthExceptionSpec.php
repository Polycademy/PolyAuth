<?php

namespace spec\PolyAuth\Exceptions;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class PolyAuthExceptionSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('PolyAuth\Exceptions\PolyAuthException');
    }
}
