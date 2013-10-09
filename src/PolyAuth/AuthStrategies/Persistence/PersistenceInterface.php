<?php

namespace PolyAuth\AuthStrategies\Persistence;

interface PersistenceInterface extends \ArrayAccess{

	public function is_started();

	public function destroy();

	public function get_all();

	public function clear_all(array $except);

	public function get_flash($key);

	public function set_flash($key, $value);

	public function has_flash($key);

	public function clear_flash();

}