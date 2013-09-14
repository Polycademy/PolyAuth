<?php

namespace PolyAuth\Storage;

use Psr\Log\LoggerAwareInterface;
use RBAC\DataStore\StorageInterface as RBACStorageInterface;

interface StorageInterface extends LoggerAwareInterface, RBACStorageInterface{

	//AccountsManager
	public function register_user(array $data, array $columns);

	public function deregister_user($user_id);

	public function duplicate_identity_check($identity);

	public function force_activate($user_id);

	public function deactivate($user_id, $activation_code);

	public function forgotten_password($user_id, $forgotten_code, $forgotten_date);

	public function password_change_flag($user_id);

	public function multi_password_change_flag(array $user_ids);

	public function forgotten_clear_password($user_id);

	public function external_register($data);

	public function get_external_providers($external_identifier);

	public function register_external_provider(array $data);

	//needs work
	public function deregister_external_provider();

	//needs work
	public function get_external_providers_by_user();

	public function update_external_provider($provider_id, array $new_data);

	public function get_password($user_id);

	public function update_password($user_id, $new_password);

	public function get_user($user_id);

	public function get_users(array $user_ids);

	public function get_users_by_role(array $roles);

	public function get_users_by_permission(array $permissions);

	public function update_user($user_id, array $data, array $columns);

	//Rbac
	public function get_permissions(array $requested_permissions);

}