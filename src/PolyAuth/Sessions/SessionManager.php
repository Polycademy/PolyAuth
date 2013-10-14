<?php

namespace PolyAuth\Persistence;

use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\Security\Random;
use PolyAuth\Sessions\Persistence\Memory;
use PolyAuth\Sessions\Persistence\PersistenceAbstract;

use Stash\Item;

use PolyAuth\Exceptions\LogicExceptions\LogicPersistenceException;

/**
 * PLAN B:
 * new Authenticator(new CookieStrategy(new SessionManager(new Persistence)))
 * OR
 * new Authenticator(new CompositeStrategy(new CookieStrategy(new SessionManager(new Persistence)), new HTTPBasicStrategy, new OAuthProviderStrategy))
 */

/**
 * This class can be used as a singleton, or shared, or individualised. IT DOES NOT MATTER.
 * Memory sessions will never be shared! Not between processes, and not between auth strategies (this is because a single auth strategy gets used in the process)
 * In the case of daemon, memory can be shared, but only when the class is shared. And it's for the duration of that session! But it's unlikely, since a client will elect
 * to use only one auth strategy for authentication for the duration of the session.
 */



// THIS GETS INJECTED INTO AUTHSTRATEGY! This will be a singleton. The same SessionManager will be set for all of the strategies so they can share sessions. Then some of them will use persistence and some will use memory.
//This means that the persistence can get shared. But never the memory.

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

	protected $session_id = false;

	public function __construct(
		Options $options, 
		Language $language, 
		Random $random, 
		PersistenceAbstract $persistence = null
	){

		$this->options = $options;
		$this->lang = $language;
		$this->random = $random;
		$this->memory = $memory;
		$this->persistence = ($persistence) ? $persistence : new Memory;

	}

	/**
	 * Starts the session tracking or starts a new session. Called at startup. 
	 * The authentication strategy checks if they have the relevant container of the session id, 
	 * and if they do they pass in a session id to start().
	 * This does not set the new or old session onto the client. The auth strategy will do that.
	 * @param  Boolean $session_id       Tracked session id
	 * @return String  $this->session_id New session id         
	 */
	public function start($session_id = false){

		//if session has already started, no need to start the session again!
		if($this->session_id){
			return true;
		}

		$this->run_gc();

		//if current session id doesn't exist, we are going to generate a new one
		if(!$session_id){

			//generate a random unique session id with a range between 20 to 40
			$this->session_id  = $this->generate_session_id();
			$this->persistence->set($this->session_id, array(), $this->options['session_expiration']);

		}else{

			if($this->persistence->exists($session_id)){
				$this->session_id = $session_id;
			}else{
				return $this->start();
			}

		}
		
		return $this->session_id;

	}

	/**
	 * Finishes the session handling. This basically logs out the person. But also destroys
	 * all mentions of the session. The start() will have to be called again to begin tracking.
	 * Any client handling needs to be done by the authentication strategy.
	 * @return String Old session id
	 */
	public function finish(){

		$session_id = $this->session_id; 

		$this->persistence->clear($session_id);

		$this->session_id = false;

		return $session_id;

	}

	/**
	 * Regenerates the session id while keeping the old session data.
	 * This works even if the session has expired, it will create a new session with empty array as data.
	 * This should be used whenever: 
	 * 1. the role or permissions of the current user was changed programmatically.
	 * 2. the user logs in or logs out to prevent session fixation.
	 * This returns the new session id, a follow up function should be used to pass this back to the client.
	 * @return String New Session ID
	 */
	public function regenerate(){

		//session hasn't been started, cannot regenerate_session_id!
		if(!$this->session_id){
			return false;
		}

		if($this->use_persistence){

			//if the session has expired, this will get the old value
			$old_session_data = $this->persistence->get($this->session_id, Item::SP_OLD);

			//now to really check if it has expired, we are going to refresh the session with an empty array
			//concurrent requests will get the old session data with 240 second ttl
			if(!$this->persistence->exists($this->session_id)){
				$this->persistence->lock($this->session_id, 240);
				$old_session_data = array();
			}
			
			//this will clear the old session, and clear the lock?
			$this->persistence->clear($this->session_id);
			//set a new session with the old session data or empty array
			$this->session_id = $this->generate_session_id();
			$this->persistence->set($this->session_id, $old_session_data, $this->options['session_expiration']);
			
		}else{

			//if the session has expired, this will get the old value
			$old_session_data = $this->memory->get($this->session_id, Item::SP_OLD);

			if(!$this->memory->exists($this->session_id)){
				$this->memory->lock($this->session_id, 240);
				$old_session_data = array();
			}

			//reset the session with a new session id and the old session data or empty array
			$this->memory->clear($this->session_id);
			$this->session_id = $this->generate_session_id();
			$this->memory->set($this->session_id, $old_session_data);

		}

		//return the new session_id, a follow up function needs to be called to put this new session id
		//into the cookies/headers.. etc
		return $this->session_id;

	}

	/**
	 * Gets the current session id
	 * @return String
	 */
	public function get_session_id(){

		return ($this->session_id) ? $this->session_id : false;

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

	/**
	 * Gets all the data in the session zone
	 * @return array Session zone data
	 */
	public function get_all(){

		if($this->use_persistence){
			return $this->persistence->get($this->session_id);
		}else{
			return $this->memory->get($this->session_id);
		}

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