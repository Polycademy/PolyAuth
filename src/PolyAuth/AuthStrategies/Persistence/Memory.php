<?php

namespace PolyAuth\AuthStrategies\Persistence;

/**
 * Memory only keeps the session information for the lifetime of the process. If the script ends the process, then the 
 * session is forgotten. This is not useful unless your client is a rich client. If you're not creating an API, or not
 * interacting with a rich JS client, use NativeSession instead.
 * Since the rich client is the one manipulating the session, many of these methods don't do anything!
 */
class Memory implements PersistenceInterface{

	protected $session = array();

	public function is_started(){

		return !empty($this->session);

	}

	public function destroy(){

		$this->session = array();

	}

	/**
	 * Gets all the data in the memory session
	 * @return array
	 */
	public function get_all(){

		return $this->session;

	}

	/**
	 * Clears all the data in the memory session
	 * @param  array $except Array of keys to except from deletion
	 */
	public function clear_all(array $except){

		$filtered = array_intersect_key($this->session, array_flip($except));
		$this->session = $filtered;
	
	}

	/**
	 * Gets a flash "read once" value. It will destroy the value once it has been read.
	 * @return mixed Value of the flash data
	 */
	public function get_flash($key){

		if(isset($this->session['__flash'][$key])){
			$value = $this->session['__flash'][$key];
			unset($this->session['__flash'][$key]);
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

		$this->session['__flash'][$key] = $value;

	}

	/**
	 * Detects whether a flash value is set without deleting the old flash value
	 * @param  string  $key Key of the flash value
	 * @return boolean
	 */
	public function has_flash($key){

		return isset($this->session['__flash'][$key]);

	}

	/**
	 * Clears all the flash values
	 */
	public function clear_flash(){

		unset($this->session['__flash']);

	}

	/**
	 * Get for ArrayAccess
	 * @param  string $offset Key of the value
	 * @return mixed          Value inside the session zone
	 */
	public function offsetGet($offset) {

		return isset($this->session[$offset]) ? $this->session[$offset] : null;

	}
	
	/**
	 * Get for ArrayAccess
	 * @param  string $offset Key of the value
	 * @param  mixed  $value  Data value
	 */
	public function offsetSet($offset, $value) {

		if (is_null($offset)) {
			$this->session[] = $value;
		} else {
			$this->session[$offset] = $value;
		}

	}
	
	/**
	 * Isset for ArrayAccess
	 * @param  string $offset Key of the value
	 * @return boolean
	 */
	public function offsetExists($offset) {

		return isset($this->session[$offset]);

	}
	
	/**
	 * Unset for ArrayAccess
	 * @param  string $offset Key of the value
	 */
	public function offsetUnset($offset) {

		unset($this->session[$offset]);

	}

}