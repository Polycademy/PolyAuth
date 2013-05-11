<?php

namespace spec\PolyAuth;

use PhpSpec\ObjectBehavior;

use RBAC\Role\Role;
use RBAC\Role\RoleSet;
use RBAC\Permission;

class UserAccountSpec extends ObjectBehavior{

	function let(RoleSet $role_set, Role $role, Permission $permission){
	
		//fixtures
		$subject_id = 1;
		$permission->permission_id = 1;
		$permission->name = 'admin_view';
		$permission->description = 'Admin View Permission';
		
		//collaborator stubbing/mocking
		$permission->__toString()->willReturn($permission->name);
		$role_set->getRoles()->willReturn(array($role));
		$role_set->getPermissions()->willReturn(array($permission));
		$role_set->has_permission($permission)->willReturn(true);
		
		$this->beConstructedWith($subject_id, $role_set);
		
	}

	function it_is_initializable_and_can_be_accessed_as_an_array(){
	
		$this->shouldHaveType('PolyAuth\UserAccount');
		$this->shouldImplement('\ArrayAccess');
		
	}
	
	function it_should_be_able_to_setup_a_user_account_without_going_through_the_constructor(){
	
		$this->set_user_data(array(
			'id'		=> 1,
			'username'	=> 'CMCDragonkai',
		));
	
		$this['id']->shouldReturn(1);
		$this->set_user(2); //calls the parent::__construct()
		$this['id']->shouldReturn(2);
		$this->id()->shouldReturn(2);
	
	}
	
	function it_is_a_subject(){
	
		$this->shouldBeAnInstanceOf('RBAC\Subject\Subject');
		$this->shouldImplement('RBAC\Subject\SubjectInterface');
		
	}
	
	function it_should_manipulate_roles(){
	
		$this->get_role_set()->shouldReturnAnInstanceOf('RBAC\Role\RoleSet');
		$this->get_roles()->shouldBeArray();
		$role_object = $this->get_roles()[0];
		$role_object->shouldBeAnInstanceOf('RBAC\Role\Role');
		$this->has_role($role_object)->shouldReturn(true);
		
	}
	
	function it_should_manipulate_permissions(){
	
		$this->get_permissions()->shouldBeArray();
		$permission_object = $this->get_permissions()[0];
		$permission_object->shouldBeAnInstanceOf('RBAC\Permission');
		$this->has_permission($permission_object)->shouldReturn(true);
	
	}
	
	function it_should_manipulate_userdata(){
	
		$this->set_user_data(array(
			'id'		=> 1,
			'username'	=> 'CMCDragonkai',
		));
		
		//merging data
		$this->set_user_data(array(
			'height'	=> '8m',
		));
		
		$user_object = new \stdClass;
		$user_object->weight = '100 kg';
		$this->set_user_data($user_object);
		
		$this->get_user_data()->shouldReturn(array('id' => 1, 'username' => 'CMCDragonkai', 'height' => '8m', 'weight' => '100 kg'));
		$this['username']->shouldReturn('CMCDragonkai');
	
	}
	
}
