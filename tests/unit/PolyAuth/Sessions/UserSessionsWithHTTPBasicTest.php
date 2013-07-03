<?php

namespace PolyAuth\Sessions;

use Codeception\Util\Stub;

class UserSessionsWithHTTPBasicTest extends \Codeception\TestCase\Test
{
   /**
    * @var \CodeGuy
    */
    protected $codeGuy;

    protected $user_sessions;

    protected function _before(){

        $db = $this->getModule('Db');
        $dbh = $db->driver->getDbh();
        $options = new \PolyAuth\Options;
        $language = new \PolyAuth\Language;
        $strategy = new \PolyAuth\AuthStrategies\HTTPStrategy($dbh, $options);
        $this->user_sessions = new \PolyAuth\Sessions\UserSessions($strategy, $dbh, $options, $language);

    }

    protected function _after(){

        $this->user_sessions->logout();

    }

    public function testLogin(){

        $this->user_sessions->start();

        $_SERVER['PHP_AUTH_USER'] = 'administrator';
        $_SERVER['PHP_AUTH_PW'] = 'password';
        $this->user_sessions->login();

        //we have a live one!
        $session_properties = $this->user_sessions->get_properties();
        $this->assertEquals(1, $session_properties['user_id']);
        $this->assertEquals(false, $session_properties['anonymous']);
        $this->assertInternalType('integer', $session_properties['timeout']);

        //the user is now loaded!
        $current_user = $this->user_sessions->get_user();
        $this->assertInstanceOf('PolyAuth\UserAccount', $current_user);
        $this->assertEquals('administrator', $current_user['username']);

        //some authority!
        $this->assertTrue($this->user_sessions->authorized());
        $this->assertTrue($this->user_sessions->authorized('admin_read', 'admin', 'administrator'));

    }

}