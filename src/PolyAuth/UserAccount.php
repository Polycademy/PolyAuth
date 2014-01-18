<?php

namespace PolyAuth;

use RBAC\Subject\Subject;
use RBAC\Role\RoleSet;
use RBAC\Role\Role;

//THE KEY POINT IN KEEPING THE USERACCOUNT LEAN AND MEAN
//IS THAT UPON THE CREATION OF USERACCOUNT
//IT SHOULD ALL THE INFORMATION NECESSARY TO SPECIFY WHAT THIS USER IS, HAS, AND WHERE THE USER
//AUTHORISED TO ANY PARTICULAR ACTION
//IT DOES NOT NEED TO CONTACT THE DATABASE FOR ANYTHING, BECAUSE ALL THE INFORMATION IS ALREADY IN THIS ENTITY
//THIS MEANS THAT IF THE USER IS UPDATED, THIS IS THE OBJECT YOU HAVE TO UPDATE, YOU PASS THIS INTO THE ACCOUNTSMANAGER
//FURTHERMORE, WHEN SCOPES IMPLEMENTED, WE NEED TO LOAD THE SCOPES INTO THE USERACCOUNT AS WELL.
//SO THE ACCOUNTS_MANAGER HAS TO GET ALL ASSOCIATED ACCESS TOKENS.
//That could be access tokens that polyauth owns which means external api, it could also mean access tokens that this user owns in relation other users on this system, which also results in associated scopes.
//
//So when you're asking does this user have the permission to do something. This question is only in relation to the role this user possesses. It has nothing to do anyone else.
//If you're asking does this person have the scope to do something. This question is really asking 2 things. Do you have a delegated resource, and do you have the empowered permission to do that action to that delegated resource. And a single user may have many delegated resources and different empowered permissions for each delegated resource. However each request to the system can only handle a single delegated resource and associated scope.

/**
 * Will Contain (this is todo, the authorized function doesn't yet check of scopes.. and needs to be streamlined anyway)
 *
 * ->api->github/facebook/..etc->request (these external APIs would essentially be http request objects, like a thin wrapper over guzzle)
 * ->api->polyauth->resource_owner (this is the id of resource owner, but the client is the user object)
 * ->api->polyauth->access_token (this is the access token with regards to current system)
 * The last 2 refer to the current system as an OAuth API
 *
 * ->authorized($permissions/$scope (in array), $roles, $user_id/$user_identity, $resource_owner_id){
 * }
 */

class UserAccount extends Subject implements \ArrayAccess{

	public $api;

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
	 * Checks if the user is logged in and possesses all the required parameters.
	 * The required parameters can be passed in as a variadic array.
	 * [
	 * 		'permissions'	=> [],
	 * 		'roles'			=> [],
	 * 		'users'			=> [1],
	 * 		'scopes'		=> [],
	 * 		'owners'		=> [1],
	 * ], ...
	 * Within each array set will be queried on an AND basis, except for users and owners which are queried on an AND + ANY basis.
	 * Each subsequent array will be queried on an OR basis.
	 * @param  variadic array
	 * @return boolean
	 */
	public function authorized(){

		//anonymous users are not authorized
		if($this['anonymous']){
			return false;
		}

		if(func_num_args() > 0){

			$options = func_get_args();

			foreach($options as $requirements){

				$passed = true;

				$permissions = (!empty($requirements['permissions'])) ? (array) $requirements['permissions'] : false;
				$roles = (!empty($requirements['roles'])) ? (array) $requirements['roles'] : false;
				$users = (!empty($requirements['users'])) ? $requirements['users'] : false;
				$scopes = (!empty($requirements['scopes'])) ? (array) $requirements['scopes'] : false;
				$owners = (!empty($requirements['owners'])) ? $requirements['owners'] : false;
				
				$permissions_passed = true;
				if($permissions){
					foreach($permissions as $permission_name){
						if(!$this->has_permission($permission_name)){
							$permissions_passed = false;
							break;
						}
					}
				}
				
				$roles_passed = true;
				if($roles){
					foreach($roles as $role_name){
						if(!$this->has_role($role_name)){
							$roles_passed = false;
							break;
						}
					}
				}

				$users_passed = true;
				if($users AND !in_array($this['id'], $users)){
					$users_passed = false;
				}


				//check scopes
				$scopes_passed = true;
				//check owner (resource owner)
				$owners_passed = true;

				//if this requirement set did not pass, then $passed gets set to false, if it's at the end of the loop, the $passed stays false, if there's further iteration the $passed gets reset to true
				//if this requirement set did pass, then we just break the loop and return the $passed as true
				if(!$permissions_passed OR !$roles_passed OR !$users_passed OR !$scopes_passed OR !$owners_passed){
					$passed = false;
				}else{
					break;
				}

			}

		}else{

			$passed = true;

		}

		return $passed;

	}
	
	/**
	 * Gets the user data array
	 * 
	 * @return array
	 */
	public function get_user_data(){

		return $this->user_data;
	
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
		
		$this->user_data = array_merge($this->user_data, $data);
		
	}

	public function set_api($api){

		$this->api = $api;

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