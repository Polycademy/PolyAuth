<?php

namespace PolyAuth\Sessions;

use Codeception\Util\Stub;

class SessionManagerTest extends \Codeception\TestCase\Test
{
   /**
    * @var \CodeGuy
    */
    protected $codeGuy;

    protected $session_manager;

    protected function _before()
    {

        //$dbh = $this->getModule('Db')->dbh;
        $options = new \PolyAuth\Options;
        $language = new \PolyAuth\Language;
        $this->session_manager = new \PolyAuth\Sessions\SessionManager($options, $language);

    }

    protected function _after()
    {
    }

    // tests
    public function testMe()
    {

    }

}