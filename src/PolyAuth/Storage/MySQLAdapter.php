<?php

//this needs to composit objects

namespace PolyAuth\Storage;

use PDO;
use PDOException;
use Psr\Log\LoggerInterface;
use PolyAuth\Options;
use PolyAuth\Storage\StorageInterface;

class MySQLAdapter implements StorageInterface{

	protected $db;
	protected $options;
	protected $logger;

	//this is going to be the child rbac storage object to be composited
	protected $rbac_storage;

	public function __construct(PDO $db, Options $options, LoggerInterface = null){

		$this->db = $db;
		$this->options = $options;
		$this->logger = $logger;
		//setup RBAC
		//setup OAUTH

	}

	//NO NEED TO DO THE BELOW. Just use the in memory storage. First understand where they need to go, then send in the results inside the AccountManager.

	/**
	 * Sets a logger instance on the object
	 *
	 * @param LoggerInterface $logger
	 * @return null
	 */
	public function setLogger(LoggerInterface $logger){
		$this->logger = $logger;
	}

}