<?php

namespace PolyAuth\Storage;

use Psr\Log\LoggerAwareInterface;
use RBAC\DataStore\StorageInterface as RBACStorageInterface;

use PolyAuth\Options;
use Psr\Log\LoggerInterface;

interface StorageInterface extends LoggerAwareInterface, RBACStorageInterface{

	public static function create(Options $options, LoggerInterface $logger = null);

	//AccountsManager
	public function register_user(array $data, array $columns);

	public function deregister_user($user_id);

	public function duplicate_identity_check($identity);

	public function force_activate($user_id);

	public function deactivate($user_id, $activation_code);

	public function forgotten_password($user_id, $forgotten_code, $forgotten_date);

	public function password_change_flag($user_id);

	public function multi_password_change_flag(array $user_ids);

	public function forgotten_password_clear($user_id);

	public function get_password($user_id);

	public function update_password($user_id, $new_password);

	public function update_key($user_id, $new_key);

	public function get_external_providers($external_identifier);

	public function register_external_provider(array $data);

	//needs work
	public function deregister_external_provider();

	//needs work
	public function get_external_providers_by_user();

	public function update_external_provider($provider_id, array $new_data);

	public function get_user($user_id);

	public function get_users(array $user_ids);

	public function get_users_by_role(array $roles);

	public function get_users_by_permission(array $permissions);

	public function count_users(array $parameters);

	public function update_user($user_id, array $data, array $columns);

	public function ban_user($user_id);

	public function validate_columns($table, array $columns);

	//SessionManager
	public function get_login_check($identity);

	public function update_last_login($user_id, $ip_address);

	//LoginAttempts
	public function locked_out($identity, $ip_address);

	public function increment_login_attempt($identity, $ip_address);

	public function clear_login_attempts($identity, $ip_address, $either_or);

	//Strategies
	public function check_autologin($id, $autocode, $valid_date);

	public function set_autologin($id, $autocode);

	public function clear_autologin($id);

	//Rbac
	public function get_permissions(array $requested_permissions);

}