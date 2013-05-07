<?php

namespace PolyAuth;

//this project will extend upon RBAC package from LeighMacDonald
use RBAC\Subject\Subject;
use RBAC\Role\RoleSet;

//this class extends the Subject which implements the SubjectInterface, it will contain all the methods necessary to interact with the logged in user!
class UserAccount extends Subject{

	protected $user_data = array();

	public function __construct($subject_id, RoleSet $role_set = null){
		parent::__construct($subject_id, $role_set);
		$this->user_data['id'] = $subject_id;
	}
	
	//this is an object!
	public function get_role_set(){
		return $this->getRoleSet();
	}
	
	public function get_roles(){
		return $this->getRoleset()->getRoles();
	}
	
	public function has_role($role){
		$roles = $this->getRoleset()->getRoles();
		return isset($roles[$role]);
	}
	
	public function get_permissions(){
		return $this->getRoleset()->getPermissions();
	}
	
	public function has_permission($permission){
		return $this->hasPermission($permission);
	}
	
	public function require_permission($permission){
		return $this->requirePermission($permission);
	}
	
	public function set_user_data($data){
	
		$type = gettype($data);
		
		if($type != 'object' OR != 'array'){
			return false;
		}
		
		if($type == 'object'){
			$data = get_object_vars($data);
		}
		
		$this->user_data = array_merge($this->user_data, $data);
		
	}
	
	public function get_user_data(){
		return $this->user_data;
	}
	
	public function get($key){
		return (isset($this->user_data[$key])) ? $this->user_data[$key] : false;
	}
	
	//magic getters and setters
	//only called on inaccessible properties
    public function __get($key) {
		return (isset($this->user_data[$key])) ? $this->user_data[$key] : false;
    }

    public function __set($key, $value){
		$this->user_data[$key] = $value;
    }
	
	public function __isset($key){
		return (isset($this->user_data[$key]));
	}
	
	public function __unset($key){
		unset($this->user_data[$key]);
	}
	
}