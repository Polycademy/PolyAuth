<?php

namespace PolyAuth\Accounts;

use PolyAuth\Language;
use PolyAuth\Storage\StorageInterface;

use PolyAuth\UserAccount;
use RBAC\Permission;
use RBAC\Role\Role;
use RBAC\Manager\RoleManager;

use PolyAuth\Exceptions\UserExceptions\UserRoleAssignmentException;
use PolyAuth\Exceptions\RoleExceptions\RoleNotFoundException;
use PolyAuth\Exceptions\RoleExceptions\RoleSaveException;
use PolyAuth\Exceptions\PermissionExceptions\PermissionNotFoundException;
use PolyAuth\Exceptions\PermissionExceptions\PermissionSaveException;

class Rbac{

	protected $storage;
	protected $lang;
	protected $role_manager;
	
	public function __construct(
		StorageInterface $storage, 
		Language $language, 
		RoleManager $role_manager = null
	){
	
		$this->storage = $storage;
		$this->lang = $language;
		$this->role_manager  = ($role_manager) ? $role_manager : new RoleManager($storage);
		
	}
	
	/**
	 * Alias for loadSubjectRoles, basically loads all the role objects into the UserAccount object
	 *
	 * @param $user UserAccount
	 * @return $user UserAccount
	 */
	public function load_subject_roles(UserAccount $user){

		return $this->role_manager->loadSubjectRoles($user);

	}
	
	/**
	 * Gets a single role object given the role name.
	 *
	 * @param $requested_role string
	 * @return Role object
	 */
	public function get_role($requested_role){
	
		$roles = $this->get_roles(array($requested_role));
		return (!empty($roles[0])) ? $roles[0] : null;
	
	}
	
	/**
	 * Gets an array of role objects that contains permission objects from an array of role names
	 * If no parameter was passed in, it will get all the roles that currently exist.
	 *
	 * @param $requested_roles array | null
	 * @return $roles array | null
	 */
	public function get_roles(array $requested_roles = null){
	
		$roles = array();
		
		if($requested_roles){
		
			foreach($requested_roles as $role_name){
				if($role = $this->role_manager->roleFetchByName($role_name)){
					$roles[] = $role;
				}
			}
		
		}else{
		
			$roles = $this->role_manager->roleFetch();
		
		}
		
		if(empty($roles)){
			if(!empty($requested_roles)){
				throw new RoleNotFoundException($this->lang['role_not_exists']);
			}
			//if it was empty, we just return null as in, no roles exist
			return null;
		}
		
		//if you want the permissions, just go $roles[#]->getPermissions();
		return $roles;
	
	}
	
	/**
	 * Gets a single permission object given a permission name.
	 *
	 * @param $requested_permission string
	 * @return Permission object
	 */
	public function get_permission($requested_permission){
	
		$permissions = $this->get_permissions(array($requested_permission));
		return (!empty($permissions[0])) ? $permissions[0] : null;
	
	}
	
	/**
	 * Gets an array of permission objects from an array of permission names
	 * If no parameter was passed in, it will get all the permissions that currently exist
	 *
	 * @param $requested_permissions array | null
	 * @return $permissions array | null
	 */
	public function get_permissions(array $requested_permissions = null){
	
		$permissions = array();
		
		if($requested_permissions){
			$permissions = $this->storage->get_permissions($requested_permissions);
		}else{
			$permissions = $this->role_manager->permissionFetch();
		}
		
		if(empty($permissions)){
			if(!empty($requested_permissions)){
				throw new PermissionNotFoundException($this->lang['permission_not_exists']);
			}
			//if it was empty, we just return null as in, no permissions exist
			return null;
		}
		
		return $permissions;
	
	}
	
	/**
	 * Creates or updates a single role given a role name and optionally a role description
	 * Use this function if you just want to register a single role.
	 *
	 * @param $role_name string
	 * @param $role_desc string
	 * @return $roles array of objects
	 */
	public function register_role($role_name, $role_desc = false){
	
		//check if the role already exists
		if($role_object = $this->role_manager->roleFetchByName($role_name)){
			//update the existing role (if the role_desc actually exists)
			$role_object->description = ($role_desc) ? $role_desc : $role_object->description;
		}else{
			//create the new role (if the role_desc is false, pass an empty role desc string)
			$role_desc = ($role_desc) ? $role_desc : '';
			$role_object = Role::create($role_name, $role_desc);
		}
		
		if(!$this->role_manager->roleSave($role_object)){
			throw new RoleSaveException($this->lang('role_save_unsuccessful'));
		}
		
		return $role_object;
	
	}
	
	/**
	 * Creates or updates an array of roles. The array can be associative between role_name => role_desc or just role_name
	 *
	 * @param $roles array
	 * @return $output_roles array of objects
	 */
	public function register_roles(array $roles){
	
		$output_roles = array();
	
		foreach($roles as $key => $value){
		
			if(is_string($key)){
				if(!$role = $this->register_role($key, $value)){
					return false;
				}
			}else{
				if(!$role = $this->register_role($value)){
					return false;
				}
			}
			
			$output_roles[] = $role;
			
		}
		
		return $output_roles;
	
	}
	
	/**
	 * Creates permissions, and assigns them to roles that may be created if they don't already exist
	 * If they already do exist, the permissions will be replaced and updated
	 * Also capable of updating the role descriptions
	 * Use this function when you're constructing an RBAC interface for administrators to create new roles/permissions
	 *
	 * $roles_permissions is accepted in this manner:
	 * 	array(
	 * 		'role_name' => array(
	 * 			'desc' => 'Description of Role',
	 * 			'perms' => array( //<- these are optional (empty array still updates; non-existent key is ignored)
	 * 				'perm_name'	=> 'perm_desc'
	 * 			)
	 * 		),
	 * 		'role_name' => array(
	 * 			'desc' => '', //<- this is also optional (empty string still updates; non-existent key is ignored)
	 * 		),
	 * 		'role_name' => array(
	 * 			'perms' => array(
	 * 				'perm_name' => '', //<- perm_desc is not optional but can be left as an empty string
	 * 			),
	 * 		),
	 *		'role_name'	=> array(
	 *			'perms'	=> array(), //<- this would just clear all the old the permissions
	 *		),
	 * 	);
	 *
	 * @param $roles_permissions array
	 * @return $roles array of objects
	 */
	public function register_roles_permissions(array $roles_permissions){
	
		$role_names = array();
	
		//cycle through the role names
		foreach($roles_permissions as $role_name => $role_data){
		
			//we send role name and description to register role
			if(isset($role_data['desc']) AND is_string($role_data['desc'])){
				$role_object = $this->register_role($role_name, $role_data['desc']);
			}else{
				$role_object = $this->register_role($role_name);
			}
			
			//if any one of the roles failed to be registered (created/updated), fail it
			if(!$role_object){
				throw new RoleSaveException($this->lang('role_register_unsuccessful'));
			}
			
			//at this point role object has already been created or updated
			//if the perms have not been set, there's no need to update it
			if(isset($role_data['perms']) AND is_array($role_data['perms'])){
			
				//first delete all the old permissions (if they exist!)
				$old_permissions = $role_object->getPermissions();
				foreach($old_permissions as $permission_object){
					$this->role_manager->permissionDelete($permission_object);
				}				
				
				//if the perms is not empty, we add/update the new roles
				//if it were empty, we would leave it with no permissions
				if(!empty($role_data['perms'])){
				
					//all permissions will be recreated
					foreach($role_data['perms'] as $permission_name => $permission_desc){
					
						$permission_object = Permission::create($permission_name, $permission_desc);
						if(!$this->role_manager->permissionSave($permission_object)){
							throw new PermissionSaveException($this->lang('permission_save_unsuccessful'));
						}
						if(!$role_object->addPermission($permission_object)){
							throw new PermissionSaveException($this->lang('permission_assignment_unsuccessful'));
						}
						
					}
					
				}
				
				if(!$this->role_manager->roleSave($role_object)){
					throw new RoleSaveException($this->lang('role_save_unsuccessful'));
				}
				
			}
			
			$role_names[] = $role_name;
		
		}
		
		return $this->get_roles($role_names);
	
	}
	
	/**
	 * Delete a single permission
	 *
	 * @param $permission_name string
	 * @return boolean
	 */
	public function delete_permission($permission_name){
	
		if($permission_object = $this->get_permissions(array($permission_name))[0]){
			if(!$this->role_manager->permissionDelete($permission_object)){
				throw new PermissionSaveException($this->lang('permission_delete_unsuccessful'));
			}
		}
		return true;
		
	}
	
	/**
	 * Delete an array of permissions
	 *
	 * @param $permission array
	 * @return boolean
	 */
	public function delete_permissions(array $permissions){
	
		foreach($permissions as $permission_name){
			if(!$this->delete_permission($permission_name)){
				return false;
			}
		}
		return true;
	
	}
	
	/**
	 * Deletes Roles and their associated Permissions. Use this to delete roles by them selves too
	 * Roles that don't exist will be ignored, their associated permissions will also be ignored.
	 *
	 * $roles_permissions is accepted in this manner:
	 * 	array(
	 * 		'role_name' => array(
	 * 			'perm_name',
	 * 			'perm_name2',
	 * 		),
	 * 		'role_name',
	 * 	);
	 *
	 * @param $roles_permissions
	 * @return boolean
	 */
	public function delete_roles_permissions(array $roles_permissions){
	
		foreach($roles_permissions as $key => $value){
		
			if(is_array($value)){
			
				//delete permissions as well
				if($role_object = $this->role_manager->roleFetchByName($key)){
				
					foreach($value as $permission){
						$this->delete_permission($permission);
					}
					
					if(!$this->role_manager->roleDelete($role_object)){
						throw new RoleSaveException($this->lang('role_delete_unsuccessful'));
					}
				
				}
			
			}else{
			
				//just delete the role
				if($role_object = $this->role_manager->roleFetchByName($value)){
				
					if(!$this->role_manager->roleDelete($role_object)){
						throw new RoleSaveException($this->lang('role_delete_unsuccessful'));
					}
				
				}
			
			}
		
		}
		
		return true;
	
	}
	
	/**
	 * Save an array of role objects. This function is not used internally, but it's to provide a pass through API to the RBAC package.
	 * It can allow incremental updates to a single or multitude of $role objects. It can update or insert role objects.
	 *
	 * @param $roles array of objects
	 * @return boolean
	 */
	public function save_roles(array $roles){
	
		foreach($roles as $role){
			if(is_object($role)){
				//if at any times the roleSave failed, we have to return false
				if(!$this->role_manager->roleSave($role)){
					throw new RoleSaveException($this->lang('role_save_unsuccessful'));
				}
			}
		}
		return true;
		
	}
	
	/**
	 * Takes a UserAccount object and array of role names and registers those roles against the user.
	 * The roles must already exist.
	 *
	 * @param $user object
	 * @param $role_names array
	 * @return $user
	 */
	public function register_user_roles(UserAccount $user, array $role_names){
		
		foreach($role_names as $role_name){
		
			$role = $this->role_manager->roleFetchByName($role_name);
			
			if(!$role){
				throw new RoleNotFoundException($this->lang['role_not_exists']);
			}
			
			if(!$this->role_manager->roleAddSubject($role, $user)){
				throw new UserRoleAssignmentException($this->lang['role_assignment_unsuccessful']);
			}
			
		}
		
		return $user;
	
	}

}