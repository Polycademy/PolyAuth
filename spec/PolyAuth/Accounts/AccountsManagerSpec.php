<?php

namespace spec\PolyAuth\Accounts;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Prophecy\Prophet;

use PDO;
use PDOException;
use PDOStatement;

use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\Accounts\PasswordComplexity;
use PolyAuth\Accounts\Random;
use PolyAuth\UserAccount;
use RBAC\Permission;
use RBAC\Role\Role;
use RBAC\Role\RoleSet;
use RBAC\Manager\RoleManager;
use PolyAuth\Emailer;

class AccountsManagerSpec extends ObjectBehavior{

	public $prophet;
	public $options;

	function let(
		PDO $db, 
		PDOStatement $sth, 
		Options $options, 
		Language $language, 
		RoleManager $role_manager,
		Role $role,
		RoleSet $role_set,
		Permission $permission
	){
	
		//MANUAL MOCKING
		$prophet = new Prophet;
		$this->prophet = $prophet;
		
		//LANGUAGE MOCKS
		
		$language_array = $language->lang;
		$language->offsetGet(Argument::any())->will(function($args) use ($language_array){
			$key = $args[0];
			return $language_array[$key];
		});
		
		//OPTIONS MOCKS
		
		$option_array = $options->options;
		$options->offsetGet(Argument::any())->will(function($args) use ($option_array){
			$key = $args[0];
			return $option_array[$key];
		});
		$this->options = $options;
	
		//PDO MOCKS
		
		$sth->bindParam(Argument::cetera())->willReturn(true);
		$sth->bindValue(Argument::cetera())->willReturn(true);
		$sth->execute(Argument::any())->willReturn(true);
		$sth->fetch()->willReturn(false);
		
		$db->prepare(Argument::any())->willReturn($sth);
		$db->lastInsertId()->willReturn(1);
		$db->getAttribute(PDO::ATTR_DRIVER_NAME)->willReturn('mysql');
		
		//ROLE MANAGER MOCKS
		
		$permission->permission_id = 1;
		$permission->name = 'Permission Name';
		$permission->description = 'A dummy permission';
		
		$role->role_id = 1;
		$role->name = $options->options['role_default'];
		$role->description = 'A dummy role';
		$role->hasPermission(Argument::type('RBAC\Permission'))->willReturn(true);
		$role->getPermissions()->willReturn(array($permission));
		
		$dummy_list_of_roles = array();
		
		$role_set = $prophet->prophesize('RBAC\Role\RoleSet');
		$role_set->addRole(Argument::type('RBAC\Role\Role'))->will(function($args){
			$dummy_list_of_roles[] = $args[0];
			return true;
		});
		$role_set->has_permission('Permission Name')->willReturn(true);
		$role_set_object = $role_set->reveal();
		
		//assigns a role set object to the UserAccount object
		$role_manager->loadSubjectRoles(Argument::type('PolyAuth\UserAccount'))->will(function($args) use ($role_set_object){
			$args[0]->loadRoleSet($role_set_object);
		});
		
		$role_manager->roleFetchByName($options->options['role_default'])->willReturn($role);
		
		//adds a role to the role set of the role object
		$role_manager->roleAddSubject(Argument::cetera())->will(function($args){
			$role = $args[0];
			$user = $args[1];
			$role_set = $user->getRoleSet();
			$role_set->addRole($role);
			$user->loadRoleSet($role_set);
			return true;
		});
		
		//CONSTRUCT!
		
		$this->beConstructedWith($db, $options, $language, null, $role_manager);
	
	}

	function it_is_initializable(){
	
		$this->shouldHaveType('PolyAuth\Accounts\AccountsManager');
		
	}
	
	function it_checks_for_duplicate_identity_when_registering(PDOStatement $sth){
	
		//for the identity checker, this means it found a result row of that identity
		$sth->fetch()->willReturn(true);
		
		$input_data = array(
			'username'			=> 'CMCDragonkai',
			'password'			=> 'P@szw0rd',
			'email'				=> 'example@example.com',
			'extraRandomField'	=> 'Hoopla!',
		);
	
		$this->register($input_data)->shouldReturn(false);
	
	}
	
	function it_checks_for_password_complexity_when_registering(){
	
		$input_data = array(
			'username'			=> 'CMCDragonkai',
			'password'			=> 'a', //<- this is too low for the minimum which is  by default 8
			'email'				=> 'example@example.com',
			'extraRandomField'	=> 'Hoopla!',
		);
	
		$this->register($input_data)->shouldReturn(false);
	
	}
	
	function it_should_register_new_users_with_appropriate_permissions(PDOStatement $sth, RoleManager $role_manager, Role $role){
		
		//no need to have "all" the fields, but the necessary ones
		$user_object = new \stdClass;
		$user_object->id = 1;
		$user_object->username = 'CMCDragonkai';
		$user_object->password = 'P@szw0rd';
		$user_object->email = 'example@example.com';
		$user_object->extraRandomField = 'Hoopla!';
		
		//for the get_user query to return a database object
		$sth->fetch(PDO::FETCH_OBJ)->willReturn($user_object);
	
		$input_data = array(
			'username'			=> 'CMCDragonkai',
			'password'			=> 'P@szw0rd',
			'email'				=> 'example@example.com',
			'extraRandomField'	=> 'Hoopla!',
		);
		
		$user_account = $this->register($input_data);
		
		$user_account->shouldBeAnInstanceOf('PolyAuth\UserAccount');
		
		//with no password
		$user_account->get_user_data()->shouldReturn(array(
			'id'				=> 1,
			'username'			=> 'CMCDragonkai',
			'email'				=> 'example@example.com',
			'extraRandomField'	=> 'Hoopla!',
		));
		
		$user_account->has_permission('Permission Name')->shouldReturn(true);
	
	}
	
	function it_should_activate_users(){
	
		//I always use PDO::FETCH_OBJ, so no need to worry.
		//but sometimes there's none
		// $sth->fetch()->will(function($args) use (){
		
		// });
		
		// $sth->fetch(PDO::FETCH_OBJ)->will(function($args) use (){
		
		// });
		
		// $sth->fetchAll(PDO::FETCH_OBJ)->will(function($args) use (){
		
		// });
		
		// $sth->rowCount()->will(function($args) use (){
		
		// });
		
		// $sth->lastInsertId()->will(function($args) use (){
		
		// });
	
	}
	
	function it_should_be_able_to_complete_the_forgotten_cycle(){
	
	}
	
	function it_should_be_able_to_get_users(){
	
	}
	
	function it_should_manipulate_roles_and_permissions(){
	
	}
	
}