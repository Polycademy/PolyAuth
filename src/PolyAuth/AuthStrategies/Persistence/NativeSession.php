<?php

namespace PolyAuth\AuthStrategies\Persistence;

use PolyAuth\Options;

/**
 * NativeSession implements the native PHP session handler to handle the persistence of server side sessions. 
 * Native sessions are easily extendable, by default it uses file storage. You can use Redis, Memcache or your 
 * own custom implementation.
 * Native sessions are not RESTful, as the server is keeping track of client side sessions. If you're building an API
 * or interacting with a rich client, you should try using Memory instead.
 * Note that if you are implementing the CookieStrategy, you must use NativeSession!
 */
class NativeSession implements PersistenceInterface{

	protected $options;
	
	public function __construct(Options $options){

		$this->options = $options;
		
		ob_start();
		register_shutdown_function(array(&$this, 'resolve_multiple_session_cookies'));

	}

	/**
	 * Sets a new name for the session. Use this when you have multiple apps on the same domain requiring different sessions.
	 * It will automatically add in the cookie prefix. This needs to be called before session_start().
	 * A second of doing this is actually using the Options and reinstantiating PolyAuth
	 * @param  string $name Name of the session
	 * @return string       Name of the current session
	 */
	public function set_name($name){

		return session_name($this->options['cookie_prefix'] . $name);

	}

	/**
	 * Gets the current session name.
	 * @return string Name of the current session
	 */
	public function get_name(){

		return session_name();

	}

	/**
	 * Gets the current session id
	 * @return int Integer of the session id
	 */
	public function get_id(){

		return session_id();

	}

	/**
	 * Detects whether the session currently enabled and active.
	 * @return boolean
	 */
	public function is_started(){

		return (session_status() == PHP_SESSION_ACTIVE);

	}

	/**
	 * Starts or restarts session handling.
	 * It will only do this if the session isn't already started.
	 * Before you want to write data to the session, use this first.
	 */
	public function start_session(){

		if(!$this->is_started()){
			session_start();
		}

	}

	/**
	 * Commits the session and closes the file lock.
	 * After you finish writing data to the session use this.
	 */
	public function commit_session(){

		session_write_close();

	}

	/**
	 * Regenerates the session id, and removes the previous session file on the disk.
	 * Remember session data is preserved, so you can carry on through a shopping cart for example.
	 * Use this when:
	 * 1. the role or permissions of the current user was changed programmatically.
	 * 2. the user logs in or logs out (to prevent session fixation) -> (done automatically)
	 * This may cause warning errors in 5.4.X where X is lower than 11. Make sure to update your PHP.
	 */
	public function regenerate(){

		$this->start_session();
		session_regenerate_id(true);
		$this->commit_session();

	}

	/**
	 * Destroys the session and clears the session data.
	 * Use this for logging out.
	 * The cookies will still be left, you'll need to delete them manually.
	 * The file lock is automatically destroyed.
	 */
	public function destroy(){

		$this->start_session();
		session_unset();
		session_destroy();

	}

	/**
	 * Gets all the data in the session zone
	 * @return array Session zone data
	 */
	public function get_all(){

		return $_SESSION;

	}

	/**
	 * Clears all the data in the session zone.
	 * @param  array $except Array of keys to except from deletion
	 */
	public function clear_all(array $except){

		$filtered = array_intersect_key($_SESSION, array_flip($except));
		$_SESSION = $filtered;
	
	}

	/**
	 * Gets a flash "read once" value. It will destroy the value once it has been read.
	 * @return mixed Value of the flash data
	 */
	public function get_flash($key){

		if(isset($_SESSION['__flash'][$key])){
			$value = $_SESSION['__flash'][$key];
			unset($_SESSION['__flash'][$key]);
			return $value;
		}
		return null;

	}

	/**
	 * Sets a flash "read once" value
	 * @param string $key   Key of the flash value
	 * @param mixed  $value Data of the flash value
	 */
	public function set_flash($key, $value){

		$_SESSION['__flash'][$key] = $value;

	}

	/**
	 * Detects whether a flash value is set without deleting the old flash value
	 * @param  string  $key Key of the flash value
	 * @return boolean
	 */
	public function has_flash($key){

		return isset($_SESSION['__flash'][$key]);

	}

	/**
	 * Clears all the flash values
	 */
	public function clear_flash(){

		unset($_SESSION['__flash']);

	}

	/**
	 * Get for ArrayAccess
	 * @param  string $offset Key of the value
	 * @return mixed          Value inside the session zone
	 */
	public function offsetGet($offset) {

		return isset($_SESSION[$offset]) ? $_SESSION[$offset] : null;

	}
	
	/**
	 * Get for ArrayAccess
	 * @param  string $offset Key of the value
	 * @param  mixed  $value  Data value
	 */
	public function offsetSet($offset, $value) {

		if (is_null($offset)) {
			$_SESSION[] = $value;
		} else {
			$_SESSION[$offset] = $value;
		}

	}
	
	/**
	 * Isset for ArrayAccess
	 * @param  string $offset Key of the value
	 * @return boolean
	 */
	public function offsetExists($offset) {

		return isset($_SESSION[$offset]);

	}
	
	/**
	 * Unset for ArrayAccess
	 * @param  string $offset Key of the value
	 */
	public function offsetUnset($offset) {

		unset($_SESSION[$offset]);

	}

	/**
	 * This will intercept the cookies in the headers before they are sent out.
	 * It will make sure that only one SID cookie is sent.
	 * It will also preserve any cookie headers prior to this library being used.
	 */
	public function resolve_multiple_session_cookies(){

		if(defined('SID')){
			$headers =  array_unique(headers_list());   
			$cookie_strings = array();
			foreach($headers as $header){
				if(preg_match('/^Set-Cookie: (.+)/', $header, $matches)){
					$cookie_strings[] = $matches[1];
				}
			}
			header_remove('Set-Cookie');
			foreach($cookie_strings as $cookie){
				header('Set-Cookie: ' . $cookie, false);
			}
		}
		ob_flush();
		
	}

}