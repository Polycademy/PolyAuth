<?php

//this needs to composit objects

namespace PolyAuth\Storage;

use PDO;
use PDOException;
use Psr\Log\LoggerInterface;
use PolyAuth\Options;

use PolyAuth\Storage\StorageInterface;

use OAuth\Common\Token\TokenInterface;
use OAuth\Common\Storage\Exception\TokenNotFoundException;
use OAuth\Common\Storage\Exception\StorageException;

class MySQLAdapter implements StorageInterface{

	protected $db;
	protected $options;
	protected $logger;

	//this is going to be the child rbac storage object to be composited
	protected $rbac_storage;

	//Token Storage Parameters
	protected $external_id;
	protected $external_user_id; //the id of the user that is relevant
	protected $external_provider;

	public function __construct(PDO $db, Options $options, LoggerInterface = null){

		$this->db = $db;
		$this->options = $options;
		$this->logger = $logger;
		//setup RBAC
		//setup OAUTH

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

	//OAUTH FUNCTIONS

	public function set_external_parameters($id = false, $user_id = false, $provider = false){

		$this->external_id = $id;
		$this->external_user_id = $user_id;
		$this->external_provider = $provider;

	}

	public function retrieveAccessToken(){

   		if(empty($this->external_id)){
			throw new PolyAuthException('The external provider ID must be set to extract existing tokens from the database. You can get it by corresponding the user id and the provider name.');
		}

		$query = "SELECT tokenObject FROM {$this->options['table_external_providers']} WHERE id = :id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('id', $this->external_id, PDO::PARAM_INT);

		try{

			$sth->execute();
			$row = $sth->fetch(PDO::FETCH_OBJ);
			if(!$row){
            	throw new TokenNotFoundException('Token not found in MySQL');
			}

		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error('Failed to execute query to select token objects based on token ids.', ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

		return unserialize($row->tokenObject);

	}

	public function storeAccessToken(TokenInterface $token){

   		if(empty($this->external_user_id) OR empty($this->external_provider)){
			throw new PolyAuthException('The external user id and external provider name must be set prior to storing the access token.');
		}

		$query = "INSERT INTO {$this->options['table_external_providers']} (userId, provider, tokenObject) VALUES (:user_id, :provider_name, :token_object)";
		$sth = $this->db->prepare($query);
		$sth->bindValue('user_id', $this->external_user_id, PDO::PARAM_INT);
		$sth->bindValue('provider_name', $this->external_provider, PDO::PARAM_STR);
		$sth->bindValue('token_object', serialize($token), PDO::PARAM_STR);

		try{

			$sth->execute();

		}catch(PDOException $db_err){

			if($this->logger){
				$this->logger->error('Failed to execute query to insert new token objects', ['exception' => $db_err]);
			}
			throw $db_err;

		}

		return true;

	}

    public function hasAccessToken(){

   		if(empty($this->external_id)){
			throw new PolyAuthException('The external provider ID must be set to check if access token exists.');
		}

		$query = "SELECT tokenObject FROM {$this->options['table_external_providers']} WHERE id = :id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('id', $this->external_id, PDO::PARAM_INT);

		try{

			$sth->execute();
			$row = $sth->fetch();

		}catch(PDOException $db_err){
		
			if($this->logger){
				$this->logger->error('Failed to execute query to select token objects based on token ids.', ['exception' => $db_err]);
			}
			throw $db_err;
		
		}

		if(!$row){
        	return false;
		}
		return true;

    }

    public function clearToken(){

   		if(empty($this->external_id)){
			throw new PolyAuthException('The external provider ID must be set to delete an access token.');
		}

		$query = "DELETE FROM {$this->options['table_external_providers']} WHERE id = :id";
		$sth = $this->db->prepare($query);
		$sth->bindValue('id', $this->external_id, PDO::PARAM_INT);

		try{

			$sth->execute();

		}catch(PDOException $db_err){
				
			if($this->logger){
				$this->logger->error('Failed to execute query to clear old login attempts.', ['exception' => $db_err]);
			}
			throw $db_err;
			
		}

		if($sth->rowCount() < 1){
			return false;
		}
		return true;

    }

}