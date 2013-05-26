<?php

namespace spec\PolyAuth\Security;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

class EncryptionSpec extends ObjectBehavior
{
    function it_is_initializable()
    {
        $this->shouldHaveType('PolyAuth\Security\Encryption');
    }
}
