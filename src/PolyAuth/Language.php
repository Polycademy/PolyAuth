<?php

namespace PolyAuth;

//this is just so we can autoload this language class and so it can be replaced
class Language implements \ArrayAccess{

	public $lang = array();
	
	public function __construct(){
	
		$this->lang = array(
			// Account Creation
			'account_creation_unsuccessful'			=> 'Unable to Create Account',
			'account_creation_duplicate_email'		=> 'Email already used or invalid',
			'account_creation_duplicate_username'	=> 'Username already used or invalid',
			'account_creation_invalid'				=> 'Cannot register without an identity or password.',
			'account_creation_email_invalid'		=> 'Cannot use email activation without a emails being registered.',
			// Password
			'password_change_unsuccessful'			=> 'Unable to Change Password',
			'password_min'							=> 'Password is not long enough.',
			'password_max'							=> 'Password is too long.',
			'password_lowercase'					=> 'Password requires a lowercase letter.',
			'password_uppercase'					=> 'Password requires an uppercase letter.',
			'password_number'						=> 'Password requires a number.',
			'password_specialchar'					=> 'Password requires a special character.',
			'password_diffpass'						=> 'Password must be a bit more different than the last password.',
			'password_diffidentity'					=> 'Password should not contain your identity.',
			'password_unique'						=> 'Password must contain more unique characters.',
			'password_flag'							=> 'Was unable to flag the password for change on the next login.',
			'forgot_password_unsuccessful'			=> 'Unable to Reset Password',
			'forgot_unsuccessful'					=> 'Unable to update forgotten code and dates.',
			'forgot_check_unsuccessful'				=> 'The forgotten code is invalid or forgotten time limit has been exceeded.',
			// Activation
			'activate_unsuccessful'					=> 'Unable to Activate Account',
			'deactivate_unsuccessful'				=> 'Unable to De-Activate Account',
			'activation_email_unsuccessful'			=> 'Unable to Send Activation Email',
			// User
			'user_select_unsuccessful'				=> 'Could not find the user or users.',
			'user_role_select_empty'				=> 'No users were found corresponding to the specified roles.',
			'user_role_select_unsuccessful'			=> 'Could not select users based on roles.',
			'user_permission_select_empty'			=> 'No users were found corresponding to the specified permissions.',
			'user_permission_select_unsuccessful'	=> 'Could not select users based on permissions.',
			// Login / Logout
			'login_successful'						=> 'Logged In Successfully',
			'login_unsuccessful'					=> 'Incorrect Login',
			'login_unsuccessful_not_active'			=> 'Account is inactive',
			'login_timeout'							=> 'Temporarily Locked Out.  Try again later.',
			'logout_successful'						=> 'Logged Out Successfully',
			// Account Changes
			'update_unsuccessful'					=> 'Unable to Update Account Information',
			'delete_unsuccessful'					=> 'Unable to Delete User',
			'delete_already'						=> 'User is already Deleted.',
			// Roles
			'role_not_exists'						=> 'Specified role(s) don\'t exist.',
			'role_already_exists'					=> 'Role name already taken',
			'role_delete_unsuccessful'				=> 'Unable to delete role',
			'role_save_unsuccessful'				=> 'Unable to save one of the roles.',
			'role_assignment_unsuccessful'			=> 'Could not assign the role to the specified account.',
			// Permissions
			'permission_delete_unsuccessful'		=> 'Unable to delete permission.',
			'permission_save_unsuccessful'			=> 'Unable to save one of the permissions.',
			'permission_assignment_unsuccessful'	=> 'Could no assign the permission to the specified role.', 
			// Email
			'email_activation_subject'				=> 'Account Activation PolyAuth',
			'email_forgotten_identity_subject'		=> 'Forgotten Identity PolyAuth',
			'email_forgotten_password_subject'		=> 'Forgotten Password PolyAuth',
		);
	
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