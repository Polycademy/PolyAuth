<?php

namespace PolyAuth;

use RBAC\Subject\Subject;
use RBAC\Role\RoleSet;
use RBAC\Role\Role;

/**
 * Will Contain
 *
 * ->api->github/facebook/..etc->request
 * ->api->polyauth->resource_owner
 * ->api->polyauth->access_token
 *
 * ->authorized($permissions/$scope (in array), $roles, $user_id/$user_identity, $resource_owner_id){
 * }
 */

class UserAccount extends Subject implements \ArrayAccess{

	protected $user_data = array();
	protected $api; //should contain the object!

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

	//This authorized doesn't actually check whether this user is logged in or not. In fact the UserAccount is always available, but some UserAccounts are anonymous. So we do have to change the parameters of this function
	/**
	 * Checks if the user is logged in and possesses all the passed in parameters.
	 * The parameters operate on all or nothing except $identities and $id. $identities and $id operates like "has to be at least one of them". But if identities and ids are both passed in, then one of them from each has to be true.
	 * This first checks if the session exists, and if not checks if the user exists in this script's memory.
	 * 
	 * @param $permissions array of permission names | string | false
	 * @param $roles array of role names | string | false
	 * @param $identities array of user identities | string | false (this must match your login_identity option)
	 * @param $ids array of user ids | integer | false
	 * @return boolean
	 */
	public function authorized($permissions = false, $roles = false, $identities = false, $ids = false){
	
		$this->session_zone->start_session();
		
		$permissions = ($permissions) ? (array) $permissions : false;
		$roles = ($roles) ? (array) $roles : false;
		$identities = ($identities) ? (array) $identities : false;
		$ids = ($ids) ? (array) $ids : false;

		//if the session and $this->user don't exist, then the user is not logged in
		//if one of them exists, then there's a chance that the session data got lost in a single instance of the script
		//also compensates for if the user id is actually a zero
		if(empty($this->session_zone['user_id']) AND $this->session_zone['user_id'] !== 0){
			if(!$this->user instanceof UserAccount OR empty($this->user['id'])){
				return false;
			}else{
				$user_id = $this->user['id'];
			}
		}else{
			$user_id = $this->session_zone['user_id'];
		}

		//we finished reading from the session, commit it!
		$this->session_zone->commit_session();
		
		//check if the user id actually exists (this may be redundant, but better safe than sorry)
		$row = $this->storage->get_user($user_id);

		//does the id exist?
		if(!$row){
			return false;
		}
		
		//id check
		if($ids AND !in_array($user_id, $ids)){
			return false;
		}

		//identity check
		if($identities AND !in_array($row->{$this->options['login_identity']}, $identities)){
			return false;
		}
		
		//reset the user variable if it does not exist, this is possible if the developer not use $this->start()
		if(!$this->user instanceof UserAccount OR empty($this->user['id'])){
			$this->user = $this->accounts_manager->get_user($user_id);
		}
		
		if($permissions){
		
			//check if the user has all the permissions
			foreach($permissions as $permission_name){
				if(!$this->user->has_permission($permission_name)){
					return false;
				}
			}
		
		}
		
		if($roles){
		
			//we need to acquire role objects first because has_role only accepts objects, not strings
			$role_objects = $this->rbac->get_roles($roles);

			foreach($role_objects as $role_object){

				if(!$this->user->has_role($role_object)){
					return false;
				}
			}
		
		}
		
		return true;
	
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