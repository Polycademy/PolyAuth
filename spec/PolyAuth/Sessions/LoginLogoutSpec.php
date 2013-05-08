<?php

namespace spec\PolyAuth\Sessions;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class LoginLogoutSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('PolyAuth\Sessions\LoginLogout');
    }
}
