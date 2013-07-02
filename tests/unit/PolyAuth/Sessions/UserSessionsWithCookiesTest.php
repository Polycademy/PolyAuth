<?php

namespace PolyAuth\Sessions;

use Codeception\Util\Stub;
use Codeception\Util\Fixtures;

class UserSessionsWithCookiesTest extends \Codeception\TestCase\Test
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
        $strategy = new \PolyAuth\AuthStrategies\CookieStrategy($dbh, $options);
        $this->user_sessions = new \PolyAuth\Sessions\UserSessions($strategy, $dbh, $options, $language);

        //WE NEED TO MOCK THE SESSION ZONE, so that it works!
        //setup mysql instance for travis!
        //use --defer-flush in the meantime

    }

    public function testConstructionAndImplementation(){

        $this->assertInstanceOf('PolyAuth\Sessions\UserSessions', $this->user_sessions);
        $this->assertInstanceOf('Psr\Log\LoggerAwareInterface', $this->user_sessions);

    }

    public function testSessionTracking(){

        $this->user_sessions->start();

        //default session properties
        $session_properties = $this->user_sessions->get_properties();
        $this->assertEquals(false, $session_properties['user_id']);
        $this->assertEquals(true, $session_properties['anonymous']);
        $this->assertInternalType('integer', $session_properties['timeout']);

        //should be an anonymous user
        $this->assertFalse($this->user_sessions->authorized());

    }

    public function testLogin(){

        $this->user_sessions->start();

        $this->user_sessions->login(array(
            'identity'  => 'administrator',
            'password'  => 'password',
        ));

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