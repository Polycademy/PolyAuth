<?php

namespace PolyAuth;

//this is just so we can autoload this language class and so it can be replaced
class Language implements \ArrayAccess{

	public $lang = array(
		// Account Creation
		'account_creation_unsuccessful'			=> 'Unable to create account.',
		'account_creation_duplicate_email'		=> 'Email already used or invalid.',
		'account_creation_duplicate_username'	=> 'Username already used or invalid.',
		'account_creation_invalid'				=> 'Cannot register without valid data fields.',
		'account_creation_email_invalid'		=> 'Cannot use email activation without a emails being registered.',
		// Account Changes
		'account_update_unsuccessful'			=> 'Unable to Update Account Information',
		'account_update_invalid'				=> 'Cannot update without valid data fields.',
		'account_delete_already'				=> 'User is already Deleted or Doesn\'t Exist.',
		// Password
		'password_change_required'				=> 'Your password needs to be changed for security purposes.',
		'password_change_unsuccessful'			=> 'Unable to change password.',
		'password_min'							=> 'Password is not long enough.',
		'password_max'							=> 'Password is too long.',
		'password_lowercase'					=> 'Password requires a lowercase letter.',
		'password_uppercase'					=> 'Password requires an uppercase letter.',
		'password_number'						=> 'Password requires a number.',
		'password_specialchar'					=> 'Password requires a special character.',
		'password_diffpass'						=> 'Password must be a bit more different than the last password.',
		'password_diffidentity'					=> 'Password should not contain your identity.',
		'password_unique'						=> 'Password must contain more unique characters.',
		// Activation
		'activation_email_unsuccessful'			=> 'Unable to Send Activation Email',
		// User
		'user_select_unsuccessful'				=> 'Could not find the user or users.',
		'user_role_select_empty'				=> 'No users were found corresponding to the specified roles.',
		'user_role_select_unsuccessful'			=> 'Could not select users based on roles.',
		'user_permission_select_empty'			=> 'No users were found corresponding to the specified permissions.',
		'user_permission_select_unsuccessful'	=> 'Could not select users based on permissions.',
		'user_banned'							=> 'User has been banned.',
		'user_inactive'							=> 'User is inactive.',
		// Login / Logout
		'login_unsuccessful'					=> 'Incorrect Login Details',
		'login_identity'						=> 'Identity was not found.',
		'login_password'						=> 'Password was incorrect.',
		'login_lockout'							=> 'Temporarily locked out for %d seconds.',
		'logout_successful'						=> 'Logged Out Successfully',
		// Roles
		'role_not_exists'						=> 'Specified role(s) don\'t exist.',
		'role_already_exists'					=> 'Role name already taken',
		'role_delete_unsuccessful'				=> 'Unable to delete role',
		'role_save_unsuccessful'				=> 'Unable to save one of the roles.',
		'role_register_unsuccessful'			=> 'Role failed to be registered.',
		'role_assignment_unsuccessful'			=> 'Could not assign the role to the specified account.',
		// Permissions
		'permission_select_unsuccessful'		=> 'Could not select permissions.',
		'permission_not_exists'					=> 'Specified permission(s) don\'t exist.',
		'permission_delete_unsuccessful'		=> 'Unable to delete permission.',
		'permission_save_unsuccessful'			=> 'Unable to save one of the permissions.',
		'permission_assignment_unsuccessful'	=> 'Could no assign the permission to the specified role.', 
		// Email
		'email_activation_subject'				=> 'Account Activation PolyAuth',
		'email_forgotten_identity_subject'		=> 'Forgotten Identity PolyAuth',
		'email_forgotten_password_subject'		=> 'Forgotten Password PolyAuth',
		// Session
		'session_invalid_key'					=> 'You cannot manipulate properties on the session object that have reserved keys.',
		'session_expire'						=> 'Session id or token has expired.'
	);
	
	public function __construct(array $language = null){
	
		if($language){
			$this->set_language($language);
		}
	
	}
	
	//this accepts a language array, otherwise it defines the default language, this can be changed on the fly, or you can just translate a few of them
	public function set_language(array $new_language_array){
		$this->lang = array_merge($this->lang, $new_language_array);
	}
	
	public function offsetSet($offset, $value) {
		if (is_null($offset)) {
			$this->lang[] = $value;
		} else {
			$this->lang[$offset] = $value;
		}
	}
	
	public function offsetExists($offset) {
		return isset($this->lang[$offset]);
	}
	
	public function offsetUnset($offset) {
		unset($this->lang[$offset]);
	}
	
	public function offsetGet($offset) {
		return isset($this->lang[$offset]) ? $this->lang[$offset] : null;
	}
	
}