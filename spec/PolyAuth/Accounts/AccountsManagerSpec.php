<?php

namespace spec\PolyAuth\Accounts;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class AccountsManagerSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('PolyAuth\Accounts\AccountsManager');
    }
}
