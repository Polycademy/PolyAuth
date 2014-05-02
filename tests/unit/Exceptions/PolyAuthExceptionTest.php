<?php

namespace PolyAuth\Exceptions;

use Codeception\Testcase\Test;
use Codeception\Util\Debug;
use PolyAuth\Exceptions\PolyAuthException;

class PolyAuthExceptionTest extends Test {

    protected $codeGuy;

    public function testNormalExceptionOperation () {

        $this->setExpectedException(
            'PolyAuth\Exceptions\PolyAuthException', 'Test Message', 1234
        );

        throw new PolyAuthException ('Test Message', 1234);

    }

    public function testExceptionsCanContainPayloads () {

        $payload = new \stdClass;
        $payload->random = 'random value';

        $exception = new PolyAuthException(['This is the message', $payload]);

        $this->assertEquals($payload, $exception->getPayload());

    }

    public function testExceptionsOutputtedAsAStringContainsPayloadIfPayloadExists () {

        $payload = ['blah'];
        $encodedPayload = json_encode($payload);

        $exception = new PolyAuthException(['This is the message', $payload]);
        $exceptionString = (string) $exception;
        
        $this->assertContains($encodedPayload, $exceptionString);

    }

}