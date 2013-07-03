<?php

namespace PolyAuth\Accounts;

use Codeception\Util\Stub;

class AccountsManagerTest extends \Codeception\TestCase\Test
{
   /**
    * @var \CodeGuy
    */
    protected $codeGuy;

    protected $accounts_manager;

    protected function _before(){

        $db = $this->getModule('Db');
        $dbh = $db->driver->getDbh();
        $options = new \PolyAuth\Options;
        $language = new \PolyAuth\Language;
        $this->accounts_manager = new \PolyAuth\Accounts\AccountsManager($dbh, $options, $language);

    }

    public function testRegistration(){

        $registered_user = $this->accounts_manager->register(array(
            'username'  => 'CMCDragonkai',
            'password'  => 'blahblah1234',
            'email'     => 'enquiry@polycademy.com',
        ));

        $this->codeGuy->seeInDatabase('user_accounts', array('username' => 'CMCDragonkai'));

        //returned registered user should equal the user retrived from the database
        $user_id = $this->codeGuy->grabFromDatabase('user_accounts', 'id', array('username' => 'CMCDragonkai'));
        $this->assertEquals($registered_user, $this->accounts_manager->get_user($user_id));

        //check duplicate identity

    }

    public function testDeregistration(){

    }

    public function testActivation(){

    }

    public function testForgottenPassword(){

    }

    public function testForgottenIdentity(){

    }

    public function testChangePassword(){

    }

    public function testUserAccountManipulation(){

    }

}