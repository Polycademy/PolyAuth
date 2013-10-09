<?php

namespace PolyAuth\AuthStrategies\Persistence;

/**
 * Persistence objects handles the manipulation of server side sessions. Basically this is how the server remembers
 * the currently authenticated user or users. Memory based implementations are RESTful as long as it fits the stateless
 * request to response model. Non RESTful implementations include file sessions, database sessions, and memory sessions
 * in a daemon.
 */
interface PersistenceInterface extends \ArrayAccess{

	public function start();

	public function commit();

	public function regenerate();

	public function destroy();

	public function get_all();

	public function clear_all(array $except);

	public function get_flash($key);

	public function set_flash($key, $value);

	public function has_flash($key);

	public function clear_flash();

}