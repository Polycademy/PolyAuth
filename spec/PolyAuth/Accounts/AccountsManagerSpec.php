<?php

namespace spec\PolyAuth\Accounts;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

use PDO;
use PDOException;
use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\Accounts\PasswordComplexity;
use PolyAuth\Accounts\Random;
use PolyAuth\UserAccount;
use RBAC\Permission;
use RBAC\Role\Role;
use RBAC\Manager\RoleManager;
use PolyAuth\Emailer;

class AccountsManagerSpec extends ObjectBehavior{
	function it_is_initializable(){
		$this->shouldHaveType('PolyAuth\Accounts\AccountsManager');
	}
}