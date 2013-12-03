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

    }

    protected function _after(){

        $this->user_sessions->logout();

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

    public function testLoginThrottlingAndForceLogin(){

        for($i = 0; $i < 10; $i++){
            try{
                $this->user_sessions->login(array(
                    'identity'  => 'administrator',
                    'password'  => 'password2',
                ));
            }catch(\Exception $e) {}
        }

        try{

            $this->user_sessions->login(array(
                'identity'  => 'administrator',
                'password'  => 'password2',
            ));

        }catch(\PolyAuth\Exceptions\PolyAuthException $e) {

            //this is an intentionally 1 second, 
            //the throttling won't increase the lockout time, 
            //if the attempts are made within the timeout itself
            //this is to prevent brute force attacks, 
            //so that the user is forced to wait
            $this->assertEquals('Temporarily locked out for 1 seconds.', $e->getMessage());

            //assuming captcha passed, we can force the login now
            $this->assertTrue($this->user_sessions->login(array(
                'identity'  => 'administrator',
                'password'  => 'password',
            ), true));

            return;

        }

        $this->fail('
            A login validation exception should be thrown with a 
            corresponding lockout time when multiple login attempts 
            are made.
        ');

    }

    public function testSessionPropertiesCanBeModified(){

        $this->user_sessions->start();

        $this->user_sessions->set_property('test', 'value');
        $this->user_sessions->set_property('flashtest', 'flashvalue', true);

        $this->assertEquals('value', $this->user_sessions->get_property('test'));
        $this->assertEquals('flashvalue', $this->user_sessions->get_property('flashtest', true));

        $this->user_sessions->delete_property('test');
        $this->assertEquals(null, $this->user_sessions->get_property('test'));

        $this->user_sessions->clear_properties();
        $this->assertEquals(null, $this->user_sessions->get_property('flashtest', true));

        $this->user_sessions->set_property('flashtest', 'flashvalue', true);
        $this->assertTrue($this->user_sessions->has_flash_property('flashtest'));

    }

    public function testSessionPropertiesAreCarriedOverAfterLoggingIn(){

        $this->user_sessions->start();

        $this->user_sessions->set_property('test', 'value');
        $this->user_sessions->set_property('flashtest', 'flashvalue', true);

        $this->user_sessions->login(array(
            'identity'  => 'administrator',
            'password'  => 'password',
        ));

        $this->assertEquals('value', $this->user_sessions->get_property('test'));
        $this->assertEquals('flashvalue', $this->user_sessions->get_property('flashtest', true));

    }

}