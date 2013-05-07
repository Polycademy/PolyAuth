<?php

namespace spec\PolyAuth;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class UserAccountSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('PolyAuth\UserAccount');
    }
}
