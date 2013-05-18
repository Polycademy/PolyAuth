<?php

namespace PolyAuth\AuthStrategies;

use PDO;
use PDOException;
use Psr\Log\LoggerInterface;
use PolyAuth\Options;
use PolyAuth\Language;
use PolyAuth\Cookies;
use PolyAuth\Security\Random;

class CookieStrategy implements AuthStrategyInterface{

	protected $db;
	protected $options;
	protected $lang;
	protected $logger;
	protected $cookies;
	protected $random;
	
	public function __construct(
		PDO $db, 
		Options $options, 
		Language $language, 
		LoggerInterface $logger = null,
		Cookies $cookies = null, 
		Random $random = null
	){
		
		$this->db = $db;
		$this->options = $options;
		$this->language = $language;
		$this->logger = $logger;
		$this->cookies = ($cookies) ? $cookies : new Cookies($options);
		$this->random = ($random) ? $random : new Random;
		
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
			
			// check for expiration
			if($this->options['login_expiration'] !== 0){
				//current time minus duration less/equal autoDate
				$valid_date = date('Y-m-d H:i:s', time() - $this->options['login_expiration']);
				$query = "SELECT id FROM {$this->options['table_users']} WHERE id = :id AND autoCode = :autoCode AND autoDate >= :valid_date";
			}else{
				$query = "SELECT id FROM {$this->options['table_users']} WHERE id = :id AND autoCode = :autoCode";
			}
			
			$sth = $this->db->prepare($query);
			$sth->bindValue('id', $id, PDO::PARAM_INT);
			$sth->bindValue('autoCode', $autocode, PDO::PARAM_STR);
			if($this->options['login_expiration'] !== 0){
				$sth->bindValue('valid_date', $valid_date, PDO::PARAM_STR);
			}
			
			try{
			
				$sth->execute();
				$row = $sth->fetch(PDO::FETCH_OBJ);
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
			
			}catch(PDOException $db_err){
			
				if($this->logger){
					$this->logger->error("Failed to execute query to autologin.", ['exception' => $db_err]);
				}
				throw $db_err;
			
			}
		
		}
	
	}
	
	/**
	 * Set the autologin cookie, autologin code and autologin date for the specified user id.
	 * Can also be used to reset the autologin cookie.
	 *
	 * @param $id integer
	 * @return boolean
	 */
	protected function set_autologin($id){
	
		$autocode = $this->random->generate(20);
		$autodate = date('Y-m-d H:i:s');
		
		$query = "UPDATE {$this->options['table_users']} SET autoCode = :autoCode, autoDate = :autoDate WHERE id = :id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('autoCode', $autocode, PDO::PARAM_STR);
		$sth->bindValue('autoDate', $autoDate, PDO::PARAM_STR);
		
		try{
		
			$sth->execute();
			if($sth->rowCount() >= 1){
				$autologin = serialize(array(
					'id'		=> $id,
					'autoCode'	=> $autoCode,
				));
				$expiration = ($this->options['login_expiration'] !== 0) ? $this->options['login_expiration'] : (60*60*24*365*2);
				$this->cookies->set_cookie('autologin', $autologin, $expiration);
				return true;
			}else{
				return false;
			}
		
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to setup autologin.", ['exception' => $db_err]);
			}
			throw $db_err;
		
		}
	
	}
	
	/**
	 * Clears the autologin cookie, autologin code and autologin date for the specified user id.
	 *
	 * @param $id integer
	 * @return boolean
	 */
	protected function clear_autologin($id){
	
		//clear the cookie to prevent multiple attempts
		$this->cookies->delete_cookie('autologin');
	
		$query = "UPDATE {$this->options['table_users']} SET autoCode = NULL, autoDate = NULL WHERE id = :id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('id', $id, PDO::PARAM_INT);
		
		try{
		
			$sth->execute();
			if($sth->rowCount() >= 1){
				return true;
			}else{
				return false;
			}
			
		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error("Failed to execute query to clear autologin.", ['exception' => $db_err]);
			}
			throw $db_err;
			
		}
	
	}
	
	//this just returns the $data because the cookie based authentication doesn't do anything at this point
	//but also assigns the cookies
	//$data needs id!
	//this $data requires the UserAccount??
	//no it will first login, grab the details, then do anything it needs to do
	public function login_hook($data){
		//assign $data to cookies (using encryption)
		
		//the thing to assign should just be the session id, and also any extra data to store
		//does the session id need to be encrypted?
		
		//should create a session
		
		//call $this->set_autologin();
		
		return $data;
	}
	
	public function logout_hook(){
	
	}

}