<?php

namespace PolyAuth\Persistence;

use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\Security\Random;
use PolyAuth\Sessions\Persistence\MemoryPersistence;
use PolyAuth\Sessions\Persistence\PersistenceAbstract;

use Stash\Item;

use PolyAuth\Exceptions\SessionExceptions\SessionExpireException;

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


//Problem:
//When the session id expires. For cookie based sessions, you can recreate a new one, and just keep going.
//For Oauth, this an access token. These are long lived sessions ids. The strategy needs the ability to set these
//options directly for the session manager. Which would be a different new session manager.
//Also you don't just recreate the session id and keep going, the access token is invalid, it needs to return
//a 401 or something and ask the client to recreate an access token by using their credentials or refresh token!
//I think we need to separate the "recreation of the session" from the starting of the session
//Also regenerate only makes sense for CookieStrategy, not for any of the others!
//We can do this by making start() return false.
//But the problem is for the get or get_all... they all use locks.
//How would you lock things if the session expired.
//I think the point is, in Cookies, if the session expired restart it and return the data. Or just return empty array or null
//In others, if the session expired... well too bad.
//But others such as HTTPBasic's token is not an access token, it's the credentials everytime! Well in that case
//the token never expires, because HTTP Basic will just request a new session every time! they'll call start()!


class SessionManager implements \ArrayAccess{

	protected $options;
	protected $lang;
	protected $random;
	protected $memory;
	protected $persistence;

	protected $session_id = false;
	protected $session_cache_expiration;
	protected $lock_ttl;

	public function __construct(
		Options $options, 
		Language $language, 
		Random $random, 
		PersistenceAbstract $persistence = null, 
		$lock_ttl = false;
	){

		$this->options = $options;
		$this->lang = $language;
		$this->random = $random;
		$this->memory = $memory;
		$this->persistence = ($persistence) ? $persistence : new MemoryPersistence;

		if($this->options['session_cache_expiration'] === 0){
			$this->session_cache_expiration = null;
		}else{
			$this->session_cache_expiration = $this->options['session_cache_expiration'];
		}

		$this->lock_ttl = ($lock_ttl) ? $lock_ttl : 240;

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
			$this->persistence->set($this->session_id, array(), $this->session_cache_expiration);

		}else{

			if($this->persistence->exists($session_id)){
				$this->session_id = $session_id;
			}else{
				throw new SessionExpireException($this->lang['session_expire']);
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
	 * This function only really make sense for CookieStrategy, you shouldn't call this with the other strategies
	 * @return String New Session ID
	 */
	public function regenerate(){

		//session hasn't been started, cannot regenerate_session_id!
		if(!$this->session_id){
			return false;
		}

		//if the session has expired, this will get the old value
		$old_session_data = $this->persistence->get($this->session_id, Item::SP_OLD);

		//now to really check if it has expired, we are going to refresh the session with an empty array
		//concurrent requests will get the old session data with 240 second ttl
		if(!$this->persistence->exists($this->session_id)){
			$this->persistence->lock($this->session_id, $this->lock_ttl);
			$old_session_data = array();
		}
		
		//this will clear the old session, and clear the lock?
		$this->persistence->clear($this->session_id);

		//set a new session with the old session data or empty array
		$this->session_id = $this->generate_session_id();
		$this->persistence->set($this->session_id, $old_session_data, $this->session_cache_expiration);

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

		//runs some probabilities
		if((mt_rand(0, 1000)/10) <= $this->options['session_gc_probability']){
			$this->persistence->purge();
		}

	}

	/**
	 * Gets all the data in the session zone.
	 * If the session expired in between calling start and calling get_all, 
	 * it will regenerate cache by locking the session, calling start() which 
	 * will set a new session and call itself to get the new session data.
	 * Concurrent functions will just get the old session data if has been locked
	 * @return array Session zone data
	 */
	public function get_all(){

		$session_data = $this->persistence->get($this->session_id);

		if(!$this->persistence->exists($this->session_id)){
			throw new SessionExpireException($this->lang['session_expire']);
		}

		return $session_data;

	}

	/**
	 * Clears all the session data except the keys passed into the array.
	 * It also resets the expiration.
	 * @param  array $except Array of keys to except from deletion
	 */
	public function clear_all(array $except = array()){

		$session_data = $this->get_all();
		$filtered = array_intersect_key($session_data, array_flip($except));
		$this->persistence->set($this->session_id, $filtered, $this->session_cache_expiration);
	
	}

	/**
	 * Get for ArrayAccess
	 * @param  string $offset Key of the value
	 * @return mixed          Value inside the session zone
	 */
	public function offsetGet($offset) {

		$session_data = $this->get_all();
		return isset($session_data[$offset]) ? $session_data[$offset] : null;

	}
	
	/**
	 * Get for ArrayAccess
	 * @param  string $offset Key of the value
	 * @param  mixed  $value  Data value
	 */
	public function offsetSet($offset, $value) {

		$session_data = $this->get_all();
		if (is_null($offset)) {
			$session_data[] = $value;
		} else {
			$session_data[$offset] = $value;
		}
		$this->persistence->set($this->session_id, $session_data, $this->session_cache_expiration);

	}
	
	/**
	 * Isset for ArrayAccess
	 * @param  string $offset Key of the value
	 * @return boolean
	 */
	public function offsetExists($offset) {

		$session_data = $this->get_all();
		return isset($session_data[$offset]);

	}
	
	/**
	 * Unset for ArrayAccess
	 * @param  string $offset Key of the value
	 */
	public function offsetUnset($offset) {

		$session_data = $this->get_all();
		unset($session_data[$offset]);
		$this->persistence->set($this->session_id, $session_data, $this->session_cache_expiration);

	}

}