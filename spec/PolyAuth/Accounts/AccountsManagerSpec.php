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
	public $user;

	function let(
		PDO $db, 
		PDOStatement $sth, 
		Options $options, 
		Language $language, 
		RoleManager $role_manager,
		Role $role,
		RoleSet $role_set,
		Permission $permission,
		UserAccount $user
	){
	
		//MANUAL MOCKING
		$prophet = new Prophet;
		$this->prophet = $prophet;
		
		//LANGUAGE MOCKS
		$language_array = $language->lang;
		$language_object = $prophet->prophesize('PolyAuth\Language');
		$language_object->offsetGet(Argument::any())->will(function($args) use (&$language_array){
			$key = $args[0];
			return $language_array[$key];
		});
		$language_object->offsetSet(Argument::cetera())->will(function($args) use (&$language_array){
			if(is_null($args[0])){
				$language_array[] = $args[1];
			} else {
				$language_array[$args[0]] = $args[1];
			}
		});
		$language_object = $language_object->reveal();
		
		//OPTIONS MOCKS
		$options = $options->options;
		$options_object = $prophet->prophesize('PolyAuth\Options');
		$options_object->offsetGet(Argument::any())->will(function($args) use (&$options){
			$key = $args[0];
			return $options[$key];
		});
		$options_object->offsetSet(Argument::cetera())->will(function($args) use (&$options){
			if(is_null($args[0])){
				$options[] = $args[1];
			} else {
				$options[$args[0]] = $args[1];
			}
		});
		$options_object = $options_object->reveal();
	
		//PDO MOCKS
		$sth->bindParam(Argument::cetera())->willReturn(true);
		$sth->bindValue(Argument::cetera())->willReturn(true);
		$sth->execute(Argument::any())->willReturn(true);
		$sth->fetch()->willReturn(false);
		
		$db->prepare(Argument::any())->willReturn($sth);
		$db->lastInsertId()->willReturn(1);
		$db->getAttribute(PDO::ATTR_DRIVER_NAME)->willReturn('mysql');
		
		//USER MOCKS
		$user_data = array(
			'id'				=> 1,
			'username'			=> 'CMCDragonkai',
			'email'				=> 'example@example.com',
			'activationCode'	=> 'abcd1234',
			'forgottenCode'		=> '1234567',
			'active'			=> 0,
		);
		$user = $prophet->prophesize('PolyAuth\UserAccount');
		$user->offsetGet(Argument::any())->will(function($args) use (&$user_data){
			$key = $args[0];
			return $user_data[$key];
		});
		$user->offsetSet(Argument::cetera())->will(function($args) use (&$user_data){
			if(is_null($args[0])){
				$user_data[] = $args[1];
			} else {
				$user_data[$args[0]] = $args[1];
			}
		});
		$user->offsetExists(Argument::any())->will(function($args) use (&$user_data){
			return isset($user_data[$args[0]]);
		});
		$user = $user->reveal();
		$this->user = $user;
		
		//ROLE MANAGER MOCKS
		$permission->permission_id = 1;
		$permission->name = 'Permission Name';
		$permission->description = 'A dummy permission';
		
		$role->role_id = 1;
		$role->name = 'members';
		$role->description = 'A dummy role';
		$role->hasPermission(Argument::type('RBAC\Permission'))->willReturn(true);
		$role->getPermissions()->willReturn(array($permission));
		$role->addPermission(Argument::any())->willReturn(true);
		
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
		
		$role_manager->roleFetchByName('members')->willReturn($role);
		$role_manager->roleFetch()->willReturn(array($role));
		$role_manager->roleSave(Argument::any())->willReturn(true);
		$role_manager->permissionFetch()->willReturn(array($permission));
		
		//adds a role to the role set of the role object
		$role_manager->roleAddSubject(Argument::cetera())->will(function($args){
			$role = $args[0];
			$user = $args[1];
			$role_set = $user->getRoleSet();
			$role_set->addRole($role);
			$user->loadRoleSet($role_set);
			return true;
		});
		
		//FIXTURES
		$options_object['login_forgot_expiration'] = 1000;
		
		//CONSTRUCT!
		$this->beConstructedWith($db, $options_object, $language_object, null, $role_manager);
	
	}

	function it_is_initializable(UserAccount $user){
	
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
	
	function it_should_register_new_users_with_appropriate_permissions(PDOStatement $sth){
		
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
		
		$this->activate($this->user)->shouldReturn(true);
		
	}
	
	function it_should_not_activate_users_on_incorrect_activation_code(){
	
		$this->activate($this->user, 'nottheactivationcode')->shouldReturn(false);
		
	}
	
	function it_should_activate_users_on_correct_activation_code(){
	
		$this->activate($this->user, 'abcd1234')->shouldReturn(true);
		
	}
	
	function it_should_deactivate_users_and_return_activation_code(){
	
		$this->user['active'] = 1;
		$this->user['activationCode'] = '';
		$this->deactivate($this->user)->shouldBeString();
	
	}
	
	function it_should_be_able_to_complete_the_forgotten_cycle(PDOStatement $sth){
	
		$sth->rowCount()->willReturn(1);
		
		//assume login_forgot_expiration was for 1000 seconds (from fixtures)
	
		//let's assume that the forgotten emails were sent out
		$this->user['forgottenCode'] = 'abcd1234';
		
		//assume that the user placed the request 900 seconds ago
		$this->user['forgottenTime'] = date('Y-m-d H:i:s', strtotime('- 900 seconds', strtotime(date('Y-m-d H:i:s'))));
		
		$this->forgotten_check($this->user, 'abcd1234')->shouldReturn(true);
		
		$this->forgotten_check($this->user, 'notthecorrectforgottencode')->shouldReturn(false);
		
		//exceeding the time should return false
		$this->user['forgottenTime'] = date('Y-m-d H:i:s', strtotime('- 3000 seconds', strtotime(date('Y-m-d H:i:s'))));
		$this->forgotten_check($this->user, 'abcd1234')->shouldReturn(false);
	
	}
	
	function it_should_manipulate_passwords(PDOStatement $sth){
	
		$sth->rowCount()->willReturn(1);
	
		$this->change_password($this->user, 'blah1234')->shouldReturn(true);
		
		$this->change_password($this->user, 's')->shouldReturn(false);
		
		$this->change_password($this->user, rand(40, 40))->shouldReturn(false);
		
		$this->reset_password($this->user)->shouldBeString();
		
		$this->force_password_change(array($this->user))->shouldReturn(true);
	
	}
	
	function it_should_be_able_to_get_a_user(PDOStatement $sth){
	
		//no need to have "all" the fields, but the necessary ones
		$user_object = new \stdClass;
		$user_object->id = 1;
		$user_object->username = 'CMCDragonkai';
		$user_object->password = 'P@szw0rd';
		$user_object->email = 'example@example.com';
		$user_object->extraRandomField = 'Hoopla!';
		
		//for the get_user query to return a database object
		$sth->fetch(PDO::FETCH_OBJ)->willReturn($user_object);
		
		$user_account = $this->get_user(1);
		
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
	
	function it_should_be_able_to_get_an_array_of_users(PDOStatement $sth){
	
		//no need to have "all" the fields, but the necessary ones
		$user_object = new \stdClass;
		$user_object->id = 1;
		$user_object->username = 'CMCDragonkai';
		$user_object->password = 'P@szw0rd';
		$user_object->email = 'example@example.com';
		$user_object->extraRandomField = 'Hoopla!';
		
		$user_object2 = new \stdClass;
		$user_object2->id = 2;
		$user_object2->username = 'CMCDragonkai';
		$user_object2->password = 'P@szw0rd';
		$user_object2->email = 'example@example.com';
		$user_object2->extraRandomField = 'Hoopla!';
		
		$sth->fetchAll(PDO::FETCH_OBJ)->willReturn(array(
			$user_object,
			$user_object2,
		));
		
		$this->get_users(array(1, 2))->shouldBeArray();
		$this->get_users(array(1, 2))->shouldHaveCount(2);
		
		$users = $this->get_users(array(1, 2));
		
		//based on their ids
		$users[0]->shouldBeAnInstanceOf('PolyAuth\UserAccount');
		$users[1]->shouldBeAnInstanceOf('PolyAuth\UserAccount');
		
		$users[0]->has_permission('Permission Name')->shouldReturn(true);
	
	}
	
	function it_should_get_users_by_roles(PDOStatement $sth){
	
		$role_object = new \stdClass;
		$role_object->subject_id = 1;
		
		$user_object = new \stdClass;
		$user_object->id = 1;
		$user_object->username = 'CMCDragonkai';
		$user_object->password = 'P@szw0rd';
		$user_object->email = 'example@example.com';
		$user_object->extraRandomField = 'Hoopla!';
		
		// $sth->fetchAll(PDO::FETCH_OBJ)->willReturn(array($role_object));
		$sth->fetchAll(PDO::FETCH_OBJ)->will(function() use ($role_object, $user_object){
			$this->fetchAll(PDO::FETCH_OBJ)->willReturn(array($user_object));
			return array($role_object);
		});
		
		$users = $this->get_users_by_role(array('random_role_name'));
		
		$users->shouldBeArray();
		$users->shouldHaveCount(1);
		$users[0]->shouldBeAnInstanceOf('PolyAuth\UserAccount');
	
	}
	
	function it_should_get_users_by_permissions(PDOStatement $sth){
	
		$permission_object = new \stdClass;
		$permission_object->subject_id = 1;
		
		$user_object = new \stdClass;
		$user_object->id = 1;
		$user_object->username = 'CMCDragonkai';
		$user_object->password = 'P@szw0rd';
		$user_object->email = 'example@example.com';
		$user_object->extraRandomField = 'Hoopla!';
		
		// $sth->fetchAll(PDO::FETCH_OBJ)->willReturn(array($role_object));
		$sth->fetchAll(PDO::FETCH_OBJ)->will(function() use ($permission_object, $user_object){
			$this->fetchAll(PDO::FETCH_OBJ)->willReturn(array($user_object));
			return array($permission_object);
		});
		
		$users = $this->get_users_by_permission(array('random_permission_name'));
		
		$users->shouldBeArray();
		$users->shouldHaveCount(1);
		$users[0]->shouldBeAnInstanceOf('PolyAuth\UserAccount');
	
	}
	
	function it_should_get_roles_and_permissions(PDOStatement $sth, Permission $permission){
	
		$sth->fetchAll(PDO::FETCH_OBJ)->willReturn(array($permission));
		
		//default role
		$roles = $this->get_roles(array('members'));
		$roles->shouldBeArray();
		$roles->shouldHaveCount(1);
		$permissions = $roles[0]->getPermissions();
		$permissions->shouldBeArray();
		$permissions[0]->shouldBeAnInstanceOf('RBAC\Permission');
		
		//all the roles
		$roles = $this->get_roles();
		$roles->shouldBeArray();
		$roles->shouldHaveCount(1);
		
		$permissions = $this->get_permissions(array('Permission Name'));
		$permissions->shouldBeArray();
		$permissions->shouldHaveCount(1);
		$permissions[0]->shouldBeAnInstanceOf('RBAC\Permission');
		$permissions = $this->get_permissions();
		$permissions->shouldBeArray();
		$permissions->shouldHaveCount(1);
		$permissions[0]->shouldBeAnInstanceOf('RBAC\Permission');
	
	}
	
	function it_should_register_roles_and_permissions(RoleManager $role_manager, Role $role){
		
		$role_manager->roleFetchByName('members')->will(function() use ($role){
			$this->roleFetchByName('members')->willReturn($role);
			return false;
		});
		
		$role_manager->permissionDelete(Argument::any())->willReturn(true);
		$role_manager->permissionSave(Argument::any())->will(function($args){
			//add a permission id to the permission object
			$args[0]->permission_id = 1;
			return true;
		});
	
		$this->register_role('members', 'This is the role description')->shouldBeAnInstanceOf('RBAC\Role\Role');
		
		$roles = $this->register_roles(array(
			'members'	=> 'role description',
		));
		
		$roles->shouldBeArray();
		
		$roles = $this->register_roles(array(
			'members',
			'members',
		));
		
		$roles->shouldBeArray();
		
		$roles = $this->register_roles_permissions(array(
			'members'	=> array(
				'desc'	=> 'This is an awesome role',
				'perms'	=> array(
					'Permission Name'	=> 'This is a dummy permission',
				),
			),
		));
		
		$roles->shouldBeArray();
		$roles[0]->shouldBeAnInstanceOf('RBAC\Role\Role');
	
	}
	
	function it_should_delete_roles_and_permissions(){
	
	}
	
}