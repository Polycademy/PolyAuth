<?php

namespace PolyAuth\Persistence;

use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\Security\Random;
use PolyAuth\Sessions\Memory;
use PolyAuth\Sessions\Persistence\PersistenceInterface;

use PolyAuth\Exceptions\LogicExceptions\LogicPersistenceException;

// THIS GETS INJECTED INTO AUTHSTRATEGY!

/**
 * SessionManager by default will persist sessions in memory. It allows an optional long term persistence 
 * object to passed in to be used in order to persist the session data beyond memory. This is not automatically 
 * used unless until you explicitly set $this->use_persistence(true). The authentication strategy will set this.
 * Authentication strategies will have default settings for whether they use persistence, for example the 
 * CookieStrategy will by default persist sessions using the $persistence passed in
 * This session manager does not automatically set the cookie, it gives back the id via $this->get_id().
 * The auth strategy would be one that determines whether to set the cookie or not.
 */
class SessionManager implements \ArrayAccess{

	protected $options;
	protected $lang;
	protected $random;
	protected $memory;
	protected $persistence;

	protected $use_persistence = false;
	protected $session_id = false;

	public function __construct(
		Options $options, 
		Language $language, 
		Random $random, 
		Memory $memory, 
		PersistenceInterface $persistence = null
	){

		$this->options = $options;
		$this->lang = $language;
		$this->random = $random;
		$this->memory = $memory;
		$this->persistence = $persistence;

	}

	//this would be toggled in the start() function of the auth strategies, not in the constructor
	//it would be dependent on the autologin and login of the auth strategies
	/**
	 * When toggled true, this will make subsequent session operations store first on the memory, and then on persistence.
	 * @param  [type] $toggle [description]
	 * @return [type]         [description]
	 */
	public function use_persistence($toggle){

		if($toggle AND !$this->persistence){
			throw new LogicPersistenceException('Cannot switch on persistence for sessions without a persistence object implementing PersistenceInterface.');
		}
		$this->use_persistence = $toggle;
	
	}

	//everytime the session id doesn't exist (either never existed or stale), we call this $this->start()
	public function start($session_id = false){

		//this should open the file lock, if it has been closed before?

		//if session has already started, no need to start the session again!
		if($this->session_id){
			return true;
		}

		$this->run_gc();

		//if current session id doesn't exist, we are going to generate a new one
		if(!$session_id){

			//generate a random unique session id with a range between 20 to 40
			$this->session_id  = $this->generate_session_id();
			//setup an empty session into the memory
			if($this->use_persistence){
				$this->persistence->set($this->session_id, array(), $this->options['session_expiration']);
			}else{
				$this->memory->set($this->session_id, array());
			}

		}else{

			if($this->use_persistence){

				if($this->persistence->exists($session_id)){
					$this->session_id = $session_id;
				}else{
					return $this->start();
				}

			}else{

				if($this->memory->exists($session_id)){
					$this->session_id = $session_id;
				}else{
					return $this->start();
				}

			}

		}
		
		return true;

	}

	//get's the id of the session
	public function get_session_id(){

		return ($this->session_id) ? $this->session_id : false;

	}

	//regenerates the session id, but keeps the session data
	public function regenerate_session_id(){

		//session hasn't been started, cannot regenerate_session_id!
		if(!$this->session_id){
			return false;
		}

		//open up a lock (because we're modifying sessions)
		if($this->use_persistence){

			//get the old data
			$old_session_data = $this->persistence->get($this->session_id);

			//if the session has expired, old data will equal empty array
			if(!$this->persistence->exists($this->session_id)){
				$old_session_data = array();
			}

			//concurrent requests will get the old session data
			$this->persistence->lock($this->session_id);
			//clear the previous data (if it existed)
			$this->persistence->clear($this->session_id);
			//generate the new session id and assign it
			$this->session_id = $this->generate_session_id();
			//add it to the new persistence
			$this->persistence->set($this->session_id, $old_session_data, $this->options['session_expiration']);
			
		}else{

			//get the old data
			$old_session_data = $this->memory->get($this->session_id);

			//if the session has expired, old data will equal empty array
			if(!$this->memory->exists($this->session_id)){
				$old_session_data = array();
			}

			//clear the previous data (if it existed)
			$this->memory->clear($this->session_id);
			//generate the new session id and assign it
			$this->session_id = $this->generate_session_id();
			//add it to the new memory
			$this->memory->set($this->session_id, $old_session_data);

		}

	}

	protected function generate_session_id(){

		return $this->random->generate(mt_rand(20, 40));

	}

	//called on every call to start(), given propabilities similar to how PHP does it
	//this runs it on the persistence layer
	protected function run_gc(){

		if($this->use_persistence){
			//runs some probabilities
			if((mt_rand(0, 1000)/10) <= $this->options['session_gc_probability']){
				$this->persistence->purge();
			}
		}

	}


	//CONTINUE...



	/**
	 * Commits the session and closes the file lock.
	 * After you finish writing data to the session use this.
	 */
	public function commit(){

		if($this->using_sessions){
			session_write_close();
		}

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

		$this->start();
		if($this->using_sessions){
			session_regenerate_id(true);
		}
		$this->commit();

	}

	/**
	 * Destroys the session and clears the session data.
	 * Use this for logging out.
	 * The cookies will still be left, you'll need to delete them manually.
	 * The file lock is automatically destroyed.
	 */
	public function destroy(){

		$this->start();
		if($this->using_sessions){
			session_unset();
			session_destroy();
		}
		unset($_SESSION);

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

}