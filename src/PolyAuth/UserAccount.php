<?php

namespace PolyAuth;

use RBAC\Subject\Subject;
use RBAC\Role\RoleSet;
use RBAC\Role\Role;

class UserAccount extends Subject implements \ArrayAccess{

	protected $user_data = array();

	public function __construct($subject_id = false, RoleSet $role_set = null){
		if($subject_id){
			$this->set_user($subject_id, $role_set);
		}
	}
	
	/**
	 * Sets the user context for this class. It basically allows two methods of using this class, either by constructing it or manually setting it.
	 * 
	 * @param $subject_id  int
	 * @param $role_set object
	 * 
	 * @return null
	 */	
	public function set_user($subject_id, RoleSet $role_set = null){
		parent::__construct($subject_id, $role_set);
		$this->user_data['id'] = $subject_id;
	}
	
	/**
	 * Gets the role set object, simply a underscore proxy for getRoleSet
	 * 
	 * @return object 
	 */
	public function get_role_set(){
		return $this->getRoleSet();
	}
	
	/**
	 * Gets an array of role objects from the role set.
	 * 
	 * @return array of objects
	 */
	public function get_roles(){
		return $this->getRoleset()->getRoles();
	}
	
	/**
	 * Boolean on check on whether this particular user has a particular role.
	 * Checks based on name.
	 *
	 * @param $role object|string
	 * @return boolean
	 */
	public function has_role($role){

		if($role instanceof Role){
			$role_name = $role->name;
		}else{
			$role_name = $role;
		}

		$registered_roles = $this->getRoleset()->getRoles();

		foreach($registered_roles as $role_to_be_checked){

			if($role_to_be_checked->name == $role_name){
				return true;
			}

		}

		return false;

	}
	
	/**
	 * Gets an array of permission objects
	 * 
	 * @return array of objects
	 */
	public function get_permissions(){
		return $this->getRoleset()->getPermissions();
	}
	
	/**
	 * Boolean on check on whether this particular user has a particular permission. Can be used with permission object or name.
	 *
	 * @param $permission object | string
	 * 
	 * @return boolean
	 */
	public function has_permission($permission){
		return $this->hasPermission($permission);
	}
	
	/**
	 * Sets the user data for this user
	 *
	 * @param $data array
	 * @return null
	 */
	public function set_user_data($data){
	
		$type = gettype($data);
		
		if($type != 'object' AND $type != 'array'){
			return false;
		}
		
		if($type == 'object'){
			$data = get_object_vars($data);
		}

		//convert ipaddresses back to human readable form!
		if(isset($data['ipAddress'])){
			$data['ipAddress'] = inet_ntop($data['ipAddress']);
		}
		
		$this->user_data = array_merge($this->user_data, $data);
		
	}
	
	/**
	 * Gets the user data array
	 * 
	 * @return array
	 */
	public function get_user_data(){
		return $this->user_data;
	}
	
	public function offsetSet($offset, $value) {
		if (is_null($offset)) {
			$this->user_data[] = $value;
		} else {
			$this->user_data[$offset] = $value;
		}
	}
	
	public function offsetExists($offset) {
		return isset($this->user_data[$offset]);
	}
	
	public function offsetUnset($offset) {
		unset($this->user_data[$offset]);
	}
	
	public function offsetGet($offset) {
		return isset($this->user_data[$offset]) ? $this->user_data[$offset] : null;
	}
	
}