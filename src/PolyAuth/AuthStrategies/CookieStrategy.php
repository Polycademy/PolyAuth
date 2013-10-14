<?php

namespace PolyAuth\AuthStrategies;

use PolyAuth\Storage\StorageInterface;
use PolyAuth\Options;
use PolyAuth\Sessions\SessionManager;
use PolyAuth\Cookies;
use PolyAuth\Security\Random;
use Psr\Log\LoggerInterface;

//this strategy will inject SessionManager (and provide methods to manipulate the session data)
//provide a function to get the session() directly, and pass that into the Authenticator!
//also there needs to be a function that tests whether this si the correct srtatetgy to use

//Cookie strategy is vulnerable to CSRF. But not XSS when you have HTTPONLY.
//Authorisation Header is not vulnerable to CSRF. But it is vulnerable to XSS!

class CookieStrategy implements StrategyInterface{

	protected $storage;
	protected $options;
	protected $session_manager;
	protected $cookies;
	protected $random;
	protected $logger;
	
	public function __construct(
		StorageInterface $storage, 
		Options $options, 
		SessionManager $session_manager, 
		Cookies $cookies = null, 
		Random $random = null, 
		LoggerInterface $logger = null
	){
		
		$this->storage = $storage;
		$this->options = $options;
		$this->session_manager = $session_manager;
		$this->cookies = ($cookies) ? $cookies : new Cookies($options);
		$this->random = ($random) ? $random : new Random;
		$this->logger = $logger;
		
	}
	
	/**
	 * Sets a logger instance on the object
	 *
	 * @param LoggerInterface $logger
	 * @return null
	 */
	public function setLogger(LoggerInterface $logger){
		$this->logger = $logger;
	}

	/**
	 * Autologin Cookie Strategy, this checks whether the autologin cookie exists, and checks if the cookie's credentials are valid.
	 * If it is valid, it will return the user id. It may also extend the autologin expiration time.
	 * If it is invalid, it will clear the autologin details in the database, and also delete the autologin cookie.
	 * If the user id didn't exist, it doesn't really matter, since the update will still pass.
	 *
	 * @return $user_id int | boolean
	 */
	public function autologin(){
	
		//should return an array
		$autologin = $this->cookies->get_cookie('autologin');
		
		if($autologin){
		
			$autologin = unserialize($autologin);
			$id = $autologin['id'];
			$autocode = $autologin['autoCode'];
			//current time minus duration less/equal autoDate
			$valid_date = date('Y-m-d H:i:s', time() - $this->options['login_expiration']);

			//also check for expiration
			$row = $this->storage->check_autologin($id, $autocode, $valid_date);

			if($row){
				
				//extend the user's autologin if it is switched on
				if($this->options['login_expiration_extend']){
					$this->set_autologin($id);
				}
				return $row->id;
				
			}else{
			
				//clear the autoCode in the DB, since it failed
				$this->clear_autologin($id);
				return false;
				
			}
		
		}

		return false;
	
	}
	
	/**
	 * Set the autologin cookie, autologin code and autologin date for the specified user id.
	 * Can also be used to reset the autologin cookie.
	 *
	 * @param $id integer
	 * @return boolean
	 */
	public function set_autologin($id){
	
		$autocode = $this->random->generate(20);

		if($this->storage->set_autologin($id, $autocode)){

			$autologin = serialize(array(
				'id'		=> $id,
				'autoCode'	=> $autocode,
			));
			$expiration = ($this->options['login_expiration'] !== 0) ? $this->options['login_expiration'] : (60*60*24*365*2);
			$this->cookies->set_cookie('autologin', $autologin, $expiration);
			return true;

		}else{

			return false;

		}
	
	}
	
	/**
	 * Clears the autologin cookie, autologin code and autologin date for the specified user id.
	 *
	 * @param $id integer
	 * @return boolean
	 */
	public function clear_autologin($id){
	
		//clear the cookie to prevent multiple attempts
		$this->cookies->delete_cookie('autologin');
		return $this->storage->clear_autologin($id);
	
	}
	
	/**
	 * Login hook, this will manipulate the $data array passed in and return it.
	 * The cookie strategy won't do anything in this case. It's a simple stub.
	 *
	 * @param $data array
	 * @return $data array
	 */
	public function login_hook($data){
		
		return $data;
		
	}
	
	/**
	 * Logout hook, will perform any necessary custom actions when logging out.
	 * The cookie strategy won't do anything in this case.
	 *
	 * @return null
	 */
	public function logout_hook(){
	
		return;
	
	}

}