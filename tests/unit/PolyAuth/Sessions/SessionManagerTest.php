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

    protected function _before(){

        $options = new \PolyAuth\Options;
        $language = new \PolyAuth\Language;
        $this->session_manager = new \PolyAuth\Sessions\SessionManager($options, $language);

    }

    protected function _after(){
    }

    public function testStartingASessionReturnsNewSessionId(){

        $new_session_id = $this->session_manager->start();
        $this->assertInternalType('string', $new_session_id);
        $this->assertEquals($new_session_id, $this->session_manager->get_session_id());

    }

    public function testStartingAnExpiredSessionThrowsException(){

        $this->setExpectedException('PolyAuth\Exceptions\PolyAuthException');
        $this->session_manager->start('fgfdg&*#$&*HFHND(*F(');

    }

    public function testRestartingASessionShouldReturnTrue(){

        $this->session_manager->start();
        $output = $this->session_manager->start('blah blah blah');
        $this->assertTrue($output);

    }

    public function testANewSessionDataShouldBeEmptyArray(){

        $this->session_manager->start();
        $data = $this->session_manager->get_all();
        $this->assertEmpty($data);

    }

    public function testSessionDataCanBeAppendedAsAnArray(){

        $this->session_manager->start();
        $this->session_manager['key1'] = 'blahcrazy';
        $this->session_manager['key2'] = 'blah';
        $data = $this->session_manager->get_all();
        $this->assertArrayHasKey('key1', $data);
        $this->assertArrayHasKey('key2', $data);
        $this->assertContains('blah', $data);
        $this->assertTrue(isset($this->session_manager['key2']));
        $this->assertEquals('blahcrazy', $this->session_manager['key1']);

    }

    public function testSessionDataCanBeDeletedAsAnArray(){

        $this->session_manager->start();
        $this->session_manager['key1'] = 'blah';
        unset($this->session_manager['key1']);
        $data = $this->session_manager->get_all();
        $this->assertArrayNotHasKey('key2', $data);

    }

    public function testSessionDataCanBeCleared(){

        $this->session_manager->start();
        $this->session_manager['key1'] = 'blahcrazy';
        $this->session_manager['key2'] = 'blah';
        $this->session_manager->clear_all();
        $data = $this->session_manager->get_all();
        $this->assertEmpty($data);

    }

    public function testSessionDataCanBeClearedExceptCertainKeys(){

        $this->session_manager->start();
        $this->session_manager['key1'] = 'blahcrazy';
        $this->session_manager['key2'] = 'blah';
        $this->session_manager->clear_all(array(
            'key1'
        ));
        $data = $this->session_manager->get_all();
        $this->assertArrayHasKey('key1', $data);
        $this->assertArrayNotHasKey('key2', $data);

    }

    public function testSessionCanBeDestroyed(){

        $this->session_manager->start();
        $this->session_manager['key1'] = 'blahcrazy';
        $old_session_id = $this->session_manager->finish();
        $this->setExpectedException('PolyAuth\Exceptions\PolyAuthException');
        $this->session_manager->start($old_session_id);

    }

    public function testSessionCanBeRegeneratedWithANewSessionIdButPersistSessionData(){

        $original_session_id = $this->session_manager->start();
        $this->session_manager['key1'] = 'blahcrazy';
        $this->session_manager['key2'] = 'blah';
        $new_session_id = $this->session_manager->regenerate();
        $this->assertNotEquals($original_session_id, $new_session_id);
        $data = $this->session_manager->get_all();
        $this->assertArrayHasKey('key1', $data);
        $this->assertArrayHasKey('key2', $data);

        //the original session should not have persisted!
        $this->session_manager->finish();
        $this->setExpectedException('PolyAuth\Exceptions\PolyAuthException');
        $this->session_manager->start($original_session_id);

    }

}