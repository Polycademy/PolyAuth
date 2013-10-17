<?php

namespace PolyAuth\Sessions;

use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\Sessions\Persistence\AbstractPersistence;
use PolyAuth\Sessions\Persistence\MemoryPersistence;
use PolyAuth\Security\Random;

use Stash\Item;

/**
 * SessionManager manages the server side part of sessions. Sessions in PolyAuth refer to the state 
 * in which a client is using the current system. Therefore every time a client is using the system, 
 * they possess a session. Sessions doesn't necessarily mean that the client is authenticated or 
 * authorised, even an anonymous guest will have a session. Sessions are required for the server to 
 * remember a client connection's access level and any associated meta data. In a practical sense this is 
 * basically a session ID and an array of session data. The session ID will be created upon the creation 
 * of a new session, this session ID will be passed to the client to remember as a token. As long as the 
 * client remembers this session ID, then this will be the key that unlocks a persisted and non-expired 
 * session data. This SessionManager by default persists the session in memory. The session data and id 
 * would be unique to each process and each instance. This is useful for authentication strategies that 
 * are stateless and so abide by the RESTful request response model. For example HTTP Basic or OAuth. This 
 * means that the session data will only be valid for the life of the process, or operations between request 
 * to response. In certain strategies, the session id will not only unlock persisted non-expired session 
 * data, but will also authenticate the connection's request. For example clients that use HTTP Basic will 
 * usually not try to remember the session id, however OAuth clients will need to remember the session id as
 * the "access token". This "access token" would authenticate the OAuth request, and also provide access 
 * to prior persisted non-expired session data. SessionManager can optionally become a stateful server side 
 * session manager. Persistence dependencies can be passed into the constructor, and so session data will 
 * now be persisted by a third party that lives longer than the RESTful request response cycle. This tends 
 * to be used by authentication strategies that do not have a rich client. The archetypical pattern is the 
 * cookie based authentication. A browser that does not have any javascript will not be able to manage a 
 * client session a web application system. Servers compensate by hooking into the cookie header transport 
 * standard. This means the session id can be passed between the client and the server via the cookie headers. 
 * The session data will be persisted through multiple request response cycles on the server. Now SessionManager 
 * provides flexibility, in that if you want to have server side persisted sessions, you can have it, just make 
 * sure the client remembers the session id regardless of what kind of authentication strategy. However if you're 
 * going with the RESTful stateless architecture, then the default implementation of memory persisted sessions 
 * is suitable, and the client will the be the system that persists the session data between request response 
 * cycles. To use this class, you can instantiate one and share among all the authentication strategies, or you 
 * can instantiate one SessionManager for each authentication strategy. Just remember that memory persisted 
 * session data is unique on each instance and each request response cycle. This means that memory data cannot 
 * be shared across requests, and cannot be shared across multiple instances. The second limitation is not really 
 * a limitation, unless you're running a daemon. Non-memory persisted session data do not have this problem. As 
 * long as the right session id is used, and it hasn't been expired, then session data can be persisted!
 * The SessionManager does not specify how the session id is to be passed back to the client. The authentication 
 * strategy will determine this.
 */
class SessionManager implements \ArrayAccess{

	protected $options;
	protected $lang;
	protected $persistence;
	protected $random;

	protected $session_id = false;
	protected $session_expiration;
	protected $lock_ttl;

	public function __construct(
		Options $options, 
		Language $language, 
		AbstractPersistence $persistence = null,
		$session_expiration = false, 
		Random $random = null, 
		$lock_ttl = false
	){

		$this->options = $options;
		$this->lang = $language;
		$this->persistence = ($persistence) ? $persistence : new MemoryPersistence();
		$this->random = ($random) ? $random : new Random();

		if($session_expiration !== false){
			$this->session_expiration = $session_expiration;
		}else{
			$this->session_expiration = $this->options['session_expiration'];
		}

		$this->lock_ttl = ($lock_ttl) ? $lock_ttl : 240;

	}

	/**
	 * Starts the session tracking or starts a new session. Called at startup.
	 * Every time this is called, it calles the garbage collector to potentially purge 
	 * expired sessions. If a session id is passed in, and it has expired, then it will 
	 * restart a new session
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
			$this->persistence->set($this->session_id, array(), $this->session_expiration);

		}else{

			if($this->persistence->exists($session_id)){
				//resets the expiration upon starting the same session again, sequential requests will keep the session alive
				$this->session_id = $session_id;
				$this->persistence->set($this->session_id, $this->persistence->get($this->session_id), $this->session_expiration);
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
	 * This returns the new session id, a follow up function should be used to pass this back to the client.
	 * This function only really make sense for CookieStrategy, you shouldn't call this with the other strategies
	 * @return String New Session ID
	 */
	public function regenerate(){

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
		$this->persistence->set($this->session_id, $old_session_data, $this->session_expiration);

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

	public function get_session_expiration(){

		return $this->session_expiration;

	}

	/**
	 * Gets all the data in the session zone.
	 * The session cannot expire at this point, this is because on each new request,
	 * $this->start() is called which refreshes the session expiration.
	 * @return array Session zone data
	 */
	public function get_all(){

		$session_data = $this->persistence->get($this->session_id);

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
		$this->persistence->set($this->session_id, $filtered, $this->session_expiration);
	
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
		$this->persistence->set($this->session_id, $session_data, $this->session_expiration);

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
		$this->persistence->set($this->session_id, $session_data, $this->session_expiration);

	}

	protected function generate_session_id(){

		return $this->random->generate(mt_rand(16, 50));

	}

	//called on every call to start(), given propabilities similar to how PHP does it
	//this runs it on the persistence layer
	protected function run_gc(){

		//runs some probabilities
		if((mt_rand(0, 1000)/10) <= $this->options['session_gc_probability']){
			$this->persistence->purge();
		}

	}

}