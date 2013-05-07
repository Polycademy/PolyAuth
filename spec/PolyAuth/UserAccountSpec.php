<?php

namespace spec\PolyAuth;

use PhpSpec\ObjectBehavior;
use Prophecy\Argument;

use RBAC\Subject\Subject;
use RBAC\Role\Role;
use RBAC\Role\RoleSet;
use RBAC\Permission;

class UserAccountSpec extends ObjectBehavior{

	function let($subject_id, RoleSet $role_set, Role $role, Permission $permission){
	
		$subject_id = 1;
		//stubbing the getRoles() function
		$role_set->getRoles()->willReturn(array($role));
		$this->beConstructedWith($subject_id, $role_set);
		
	}

	function it_is_initializable(){
	
		$this->shouldHaveType('PolyAuth\UserAccount');
		
	}
	
	function it_is_a_subject(){
	
		$this->shouldBeAnInstanceOf('RBAC\Subject\Subject');
		$this->shouldImplement('RBAC\Subject\SubjectInterface');
		
	}
	
	function it_should_manipulate_roles(){
	
		$this->get_role_set()->shouldReturnAnInstanceOf('RBAC\Role\RoleSet');
		$this->get_roles()->shouldBeArray();
		foreach($this->get_roles() as $role_object){
			$role_object->shouldBeAnInstanceOf('RBAC\Role\Role');
			$this->has_role($role_object)->shouldReturn(true);
		}
		
	}
	
	function it_should_manipulate_permissions(){
	
	}
	
	
	
}
