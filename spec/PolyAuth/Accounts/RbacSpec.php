<?php

namespace spec\PolyAuth\Accounts;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;
use Prophecy\Prophet;

use PDO;
use PDOStatement;
use PolyAuth\Language;

use RBAC\Permission;
use RBAC\Role\Role;
use RBAC\Role\RoleSet;
use RBAC\Manager\RoleManager;

class RbacSpec extends ObjectBehavior{

	public $prophet;

	function let(
		PDO $db,
		PDOStatement $sth, 
		Language $language_object,
		Permission $permission,
		Role $role,
		RoleSet $role_set,
		RoleManager $role_manager
	){
	
		//setting up the prophet
		$this->prophet = new Prophet;
		
		$mocks = array();
		$mocks += $this->setup_db_mocks($db, $sth);
		$mocks += $this->setup_language_mocks($language_object);
		$mocks += $this->setup_logger_mocks();
		$mocks += $this->setup_role_manager_mocks($permission, $role, $role_set, $role_manager);
		
		$this->beConstructedWith(
			$mocks['db'],
			$mocks['language'], 
			$mocks['logger'], 
			$mocks['role_manager']
		);
	
	}
	
	function setup_db_mocks(PDO $db, PDOStatement $sth){
	
		//STH
		$sth->bindParam(Argument::cetera())->willReturn(true);
		$sth->bindValue(Argument::cetera())->willReturn(true);
		$sth->execute(Argument::any())->willReturn(true);
		$sth->fetch()->willReturn(true);
		
		//PDO
		$db->prepare(Argument::any())->willReturn($sth);
		
		return [
			'db'	=> $db, 
		];
	
	}
	
	function setup_language_mocks(Language $language_object){
	
		//LANGUAGE
		$language = $this->prophet->prophesize('PolyAuth\Language');
		$language_array = $language_object->lang;
		$language->offsetGet(Argument::any())->will(function($args) use (&$language_array){
			$key = $args[0];
			return $language_array[$key];
		});
		$language->offsetSet(Argument::cetera())->will(function($args) use (&$language_array){
			if(is_null($args[0])){
				$language_array[] = $args[1];
			} else {
				$language_array[$args[0]] = $args[1];
			}
		});
		$language = $language->reveal();
		
		return [
			'language'	=> $language,
		];
	
	}
	
	function setup_logger_mocks(){
	
		$logger = $this->prophet->prophesize();
		$logger->willExtend('stdClass');
		$logger->willImplement('Psr\Log\LoggerInterface');
		$logger->error(Argument::type('string'), Argument::type('array'))->willReturn(true);
		$logger = $logger->reveal();
		return [
			'logger'	=> $logger,
		];
	
	}
	
	function setup_role_manager_mocks(Permission $permission, Role $role, RoleSet $role_set, RoleManager $role_manager){
	
		$permission->permission_id = 1;
		$permission->name = 'Permission Name';
		$permission->description = 'A dummy permission';
		
		$role->role_id = 1;
		$role->name = 'members';
		$role->description = 'A dummy role';
		$role->hasPermission(Argument::type('RBAC\Permission'))->willReturn(true);
		$role->getPermissions()->willReturn(array($permission));
		$role->addPermission(Argument::any())->willReturn(true);
		
		$role_set->addRole(Argument::type('RBAC\Role\Role'))->willReturn(true);
		$role_set->has_permission('Permission Name')->willReturn(true);
		
		$role_manager->roleFetchByName('members')->willReturn($role);
		$role_manager->roleFetch()->willReturn(array($role));
		$role_manager->roleSave(Argument::any())->willReturn(true);
		$role_manager->permissionFetch()->willReturn(array($permission));
		
		//assigns a role set object to the UserAccount object
		$role_manager->loadSubjectRoles(Argument::type('PolyAuth\UserAccount'))->will(
			function($args) use ($role_set){
				$user = $args[0];
				$user->loadRoleSet($role_set);
				return $user;
			}
		);
		
		//adds a role to the role set of the role object
		$role_manager->roleAddSubject(Argument::cetera())->will(function($args){
			$role = $args[0];
			$user = $args[1];
			$role_set = $user->getRoleSet();
			$role_set->addRole($role);
			$user->loadRoleSet($role_set);
			return $user;
		});
		
		return [
			'role_manager'	=> $role_manager,
		];
	
	}

	function it_is_initializable(){
	
		$this->shouldHaveType('PolyAuth\Accounts\Rbac');
		
	}
	
	function it_implements_logger_interface(){
	
		$this->shouldImplement('Psr\Log\LoggerAwareInterface');
	
	}
	
	function it_should_get_roles_and_permissions(PDOStatement $sth, Permission $permission){
	
		$sth->fetchAll(PDO::FETCH_CLASS, '\RBAC\Permission')->willReturn(array($permission));
		
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
	
	function it_should_delete_roles_and_permissions(PDOStatement $sth, Permission $permission, RoleManager $role_manager){
		
		$sth->fetchAll(PDO::FETCH_CLASS, '\RBAC\Permission')->willReturn(array($permission));
		
		$role_manager->permissionDelete(Argument::any())->willReturn(true);
		$role_manager->roleDelete(Argument::any())->willReturn(true);
	
		$this->delete_permission('Permission Name')->shouldReturn(true);
		
		$this->delete_permissions(array('Permission Name'))->shouldReturn(true);
		
		$this->delete_roles_permissions(array(
			'members'	=> array(
				'Permission Name',
			),
		))->shouldReturn(true);
	
	}
	
}