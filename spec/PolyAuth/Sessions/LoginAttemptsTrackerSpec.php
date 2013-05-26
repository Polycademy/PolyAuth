<?php

namespace spec\PolyAuth\Sessions;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class LoginAttemptsTrackerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('PolyAuth\Sessions\LoginAttemptsTracker');
    }
}
