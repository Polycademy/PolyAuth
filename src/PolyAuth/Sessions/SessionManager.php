<?php

namespace PolyAuth\Sessions;

use PolyAuth\Options;

class SessionManager implements \ArrayAccess{

	protected $options;
	protected $session_zone;
	
	public function __construct(Options $options){

		$this->options = $options;
		ob_start();
		register_shutdown_function(array(&$this, 'resolve_multiple_session_cookies'));

	}

	/**
	 * Sets a new name for the session. Use this when you have multiple apps on the same domain requiring different sessions.
	 * It will automatically dd in the cookie prefix. This needs to be called before session_start().
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
	 * Creates a new namespaced session zone. 
	 * This utilises the same "session", but allows different zones inside that session.
	 * Call this at startup
	 * @param  string $namespace Namespace of the session zone
	 */
	public function create_zone($namespace){

		$this->start_session();
		$_SESSION[$namespace] = [];
		$this->session_zone = &$_SESSION[$namespace];
		$this->commit_session();

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
	 * Use this when elevating or demoting permissions. Such as logging in or out.
	 * Remember session data is preserved, so you can carry on through a shopping cart for example.
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
	 * Clears all the data in the session zone
	 */
	public function clear_data(){

		$this->start_session();
		$this->session_zone = [];
		$this->commit_session();
	
	}

	/**
	 * Gets a flash "read once" value. It will destroy the value once it has been read.
	 * @return mixed Value of the flash data
	 */
	public function get_flash(){

		if(isset($this->session_zone['__flash'][$key])){
			$value = $this->session_zone['__flash'][$key];
			unset($this->session_zone['__flash'][$key]);
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

		$this->session_zone['__flash'][$key] = $value;

	}

	/**
	 * Detects whether a flash value is set without deleting the old flash value
	 * @param  string  $key Key of the flash value
	 * @return boolean
	 */
	public function has_flash($key){

		return isset($this->session_zone['__flash'][$key]);

	}

	/**
	 * Clears all the flash values
	 */
	public function clear_flash(){

		unset($this->session_zone['__flash']);

	}

	/**
	 * Get for ArrayAccess
	 * @param  string $offset Key of the value
	 * @return mixed          Value inside the session zone
	 */
	public function offsetGet($offset) {

		return isset($this->session_zone[$offset]) ? $this->session_zone[$offset] : null;

	}

	/**
	 * Get for ArrayAccess
	 * @param  string $offset Key of the value
	 * @param  mixed  $value  Data value
	 */
	public function offsetSet($offset, $value) {

		if (is_null($offset)) {
			$this->session_zone[] = $value;
		} else {
			$this->session_zone[$offset] = $value;
		}

	}
	
	/**
	 * Isset for ArrayAccess
	 * @param  string $offset Key of the value
	 * @return boolean
	 */
	public function offsetExists($offset) {

		return isset($this->session_zone[$offset]);

	}
	
	/**
	 * Unset for ArrayAccess
	 * @param  string $offset Key of the value
	 */
	public function offsetUnset($offset) {

		unset($this->session_zone[$offset]);

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